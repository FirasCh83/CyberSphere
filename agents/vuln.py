import json
import os
import re
import time
import logging
from dotenv import load_dotenv
from openai import OpenAI
from openai import APIConnectionError, APITimeoutError, RateLimitError, InternalServerError

logger = logging.getLogger("vuln_agent")


def _llm_create_with_retry(client, max_attempts: int = 4, **kwargs):
    """
    Call the LLM with exponential backoff + retry.
    'openrouter/free' is heavily rate-limited; a single transient failure
    previously killed the whole pipeline. Now we retry the last 4 times
    before giving up.
    """
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            return client.chat.completions.create(**kwargs)
        except (RateLimitError, APIConnectionError, APITimeoutError,
                InternalServerError) as e:
            last_exc = e
            if attempt == max_attempts:
                break
            wait = min(2 ** attempt, 30)  # 2,4,8 ... up to 30s
            logger.warning(
                "LLM call attempt %d/%d failed (%s: %s) — retrying in %ds",
                attempt, max_attempts, type(e).__name__, e, wait,
            )
            print(f"[VulnAgent] LLM attempt {attempt}/{max_attempts} "
                  f"({type(e).__name__}) — retrying in {wait}s")
            time.sleep(wait)
    # All attempts failed — log a clear message and re-raise so the
    # orchestrator's pipeline-failure surfacing picks it up.
    logger.error("LLM call failed after %d attempts: %s",
                 max_attempts, last_exc)
    print(f"[VulnAgent] LLM call failed after {max_attempts} attempts: {last_exc}")
    raise last_exc
from utilities.models import ConfirmedVulnerability, VulnState, Severity, ExploitationComplexity, ValidationStatus
from utilities.state import ReconState
from utilities import events
from knowledge.query import VulnKnowledgeBase
from tools.validation.connectivity import run_connectivity_check
from tools.validation.banner_grab import run_banner_grab, version_matches
from tools.validation.msf_check import run_msf_check

load_dotenv()

# Central LLM config — override in .env. Defaults to the OpenRouter endpoint.
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://vyceai.com/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "claude-sonnet-4-6")
client = OpenAI(
    base_url=LLM_BASE_URL,
    api_key=os.getenv("OPENROUTER_API_KEY"),
)

# tool schemas 
tools = [
    {
        "type": "function",
        "function": {
            "name": "run_connectivity_check",
            "description": (
                "Confirms a port is reachable from the attack path and grabs "
                "whatever the service sends immediately on connection. "
                "Fast (~3s)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "port":   {"type": "integer"},
                },
                "required": ["target", "port"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_banner_grab",
            "description": (
                "Connects to a port and grabs the full service banner to confirm "
                "the exact version. Cross-reference against the expected version "
                "from the RAG candidate to confirm or deny the match. Fast (~5s)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"},
                    "port":   {"type": "integer"},
                },
                "required": ["target", "port"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_msf_check",
            "description": (
                "Runs Metasploit check() command against target — NOT exploitation. "
                "Safe confirmation only. Returns vulnerable/safe/unsupported/error. "
                "You do NOT choose the module: pass the cve_id of the candidate you "
                "are validating and the system runs the vetted Metasploit module from "
                "the knowledge base for that CVE. Slow (~30-60s per check)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target":  {"type": "string"},
                    "port":    {"type": "integer"},
                    "cve_id":  {"type": "string", "description": "CVE id of the candidate being validated, e.g. CVE-2011-2523"},
                },
                "required": ["target", "port", "cve_id"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    },
]

# helpers

# CVE id token, e.g. CVE-2011-2523 — the year is 4 digits, the sequence 4-7.
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def _tool_cited_cves(recon_state) -> set:
    """Collect every CVE id that actually appears in real recon tool output.

    These are the only CVE ids the recon brief is allowed to name. We scan the
    structured nuclei findings plus the string finding lists — anything a tool
    genuinely emitted — and normalise to upper-case for comparison.
    """
    cited = set()

    for f in getattr(recon_state, "nuclei_findings", []) or []:
        source = f.values() if isinstance(f, dict) else [f]
        for v in source:
            for m in _CVE_RE.findall(str(v)):
                cited.add(m.upper())

    for coll in (getattr(recon_state, "nuclei_summary", []),
                 getattr(recon_state, "findings", [])):
        for line in coll or []:
            for m in _CVE_RE.findall(str(line)):
                cited.add(m.upper())

    return cited


def _strip_unverified_cves(text: str, allowed: set):
    """Replace CVE ids not in `allowed` with a redaction marker.

    Returns (cleaned_text, list_of_stripped_ids). Tool-cited CVEs are left
    intact; anything the model invented becomes '[unverified CVE]' so the
    surrounding sentence still reads but the fabricated id can't propagate.
    """
    stripped = []

    def _repl(m):
        cid = m.group(0).upper()
        if cid in allowed:
            return m.group(0)
        stripped.append(cid)
        return "[unverified CVE]"

    return _CVE_RE.sub(_repl, text), stripped


def _vuln_cmd(name: str, args: dict):
    """Map a validation tool call to (family, command line) for the UI."""
    target = args.get("target", "")
    port = args.get("port", "")
    if name == "run_connectivity_check":
        return "validate", f"connectivity check → {target}:{port}"
    if name == "run_banner_grab":
        return "validate", f"banner grab → {target}:{port}"
    if name == "run_msf_check":
        return "metasploit", f"msf check → {args.get('msf_module', '')}"
    return name, f"{name} {target}:{port}"


def call_tool(name: str, args: dict) -> dict:
    if name == "run_connectivity_check":
        return run_connectivity_check(
            target=args["target"],
            port=args["port"],
        )
    elif name == "run_banner_grab":
        return run_banner_grab(
            target=args["target"],
            port=args["port"],
        )
    elif name == "run_msf_check":
        return run_msf_check(
            target=args["target"],
            port=args["port"],
            msf_module=args["msf_module"],
        )
    else:
        raise ValueError(f"Unknown tool: {name}")


def _resolve_msf_module(candidates: list, cve_id: str, port) -> str:
    """Look up the vetted Metasploit module for a candidate from RAG metadata.

    The agent supplies only a cve_id; the module string comes from the knowledge
    base — never from the LLM — so hallucinated / non-existent module names can't
    reach msfconsole. Match on (cve_id, port); fall back to cve_id alone.
    Returns "" if the candidate has no module or isn't found.
    """
    cand = next(
        (c for c in candidates
         if c["metadata"].get("cve_id") == cve_id and c["matched_port"] == port),
        None,
    )
    if cand is None:
        cand = next(
            (c for c in candidates if c["metadata"].get("cve_id") == cve_id),
            None,
        )
    if cand is None:
        return ""
    return cand["metadata"].get("metasploit_module", "") or ""


def generate_recon_summary(recon_state: ReconState) -> str:
    """
    Ask the LLM to summarize ReconState into a compact
    vulnerability-focused brief for the vuln agent.

    The brief is OBSERVATION-focused: the recon layer reports ports, versions,
    banners and misconfigurations — it must not mint CVE ids from memory. Any
    CVE that slips through and wasn't in real tool output is stripped by the
    guard below, so a fabricated identifier can never reach the report.
    """
    print("[VulnAgent] generating recon summary...")

    prompt = f"""You are a senior penetration tester writing a reconnaissance brief.
Summarize the following recon findings into a concise, factual brief for the
vulnerability-analysis stage.

Focus ONLY on observed facts: open ports, detected service versions, banners,
technologies, and misconfigurations. Group by service where useful.

STRICT RULES:
- Do NOT state any CVE identifier or CVSS score from memory. Only mention a CVE
  if it appears verbatim in the recon findings below.
- Describe evidence, not verdicts: "vsftpd 2.3.4 banner on port 21", not
  "confirmed backdoor". Use "appears", "banner suggests" for anything inferred.
- CVE matching and confirmation happen downstream — your job is accurate observations.
Keep it under 200 words.

RECON FINDINGS:
{recon_state.summary()}
"""
    response = _llm_create_with_retry(
        client,
        model=LLM_MODEL,
        messages=[{"role": "user", "content": prompt}],
        tools=tools,
    )
    summary = response.choices[0].message.content or ""

    # guard: drop any CVE id the recon tools never actually reported
    allowed = _tool_cited_cves(recon_state)
    summary, stripped = _strip_unverified_cves(summary, allowed)
    if stripped:
        uniq = sorted(set(stripped))
        print(f"[VulnAgent] recon-summary guard removed {len(uniq)} "
              f"unverified CVE id(s): {uniq}")
        summary += (
            "\n\n[note] One or more CVE identifiers produced in this brief were "
            "not present in any tool output and were removed as unverified. CVE "
            "attribution is performed by the validation layer below."
        )
    return summary


def build_confirmed_vuln(
    candidate: dict,
    validation_status: ValidationStatus,
    validation_output: str,
    recon_state: ReconState,
) -> ConfirmedVulnerability:
    """Build a ConfirmedVulnerability from a RAG candidate + validation result."""
    meta = candidate["metadata"]

    return ConfirmedVulnerability(
        cve_id=meta.get("cve_id", ""),
        name=meta.get("cve_id", ""),
        description=candidate.get("document", ""),
        target=recon_state.target,
        port=candidate["matched_port"],
        service=candidate["matched_service"],
        version=candidate["matched_version"],
        severity=Severity(meta.get("severity", "medium")),
        cvss_score=float(meta.get("cvss_score", 0.0)),
        exploitation_complexity=ExploitationComplexity(
            meta.get("exploitation_complexity", "medium")
        ),
        requires_auth=bool(meta.get("requires_auth", False)),
        metasploit_module=meta.get("metasploit_module", ""),
        status=validation_status,
        rag_score=candidate.get("combined_score", 0.0),
        evidence_score=candidate.get("evidence_score", 0.0),
        semantic_score=candidate.get("semantic_score", 0.0),
        validation_output=validation_output,
        validation_method=meta.get("validation_method", ""),
        tags=meta.get("tags", "").split() if meta.get("tags") else [],
        references=[],
        notes="",
    )


# main agent

def run_vuln_agent(recon_state: ReconState) -> VulnState:
    """
    Full vulnerability agent pipeline.
    Layer 1: RAG matching against recon findings
    Layer 2: Active validation via ReAct loop
    Returns: VulnState with all confirmed/probable/unconfirmed findings
    """
    vuln_state = VulnState(target=recon_state.target)

    events.phase("Vuln Agent", "rag matching + active validation")

    # LAYER 1: RAG
    print(f"[VulnAgent] target: {recon_state.target}")
    print(f"[VulnAgent] starting RAG layer...")

    kb = VulnKnowledgeBase()
    print(f"[VulnAgent] knowledge base: {kb.count()} vulnerabilities loaded")

    # generate LLM summary of recon findings
    vuln_state.recon_summary = generate_recon_summary(recon_state)
    print(f"\n[VulnAgent] recon summary:\n{vuln_state.recon_summary}\n")
    events.thought(vuln_state.recon_summary, who="recon summary")

    # query KB against recon state
    all_candidates = kb.match_against_recon(recon_state)
    vuln_state.rag_candidates = all_candidates

    # Selection — two lanes, per the KB design (curated validation + advisory NVD):
    #
    #   VALIDATE lane  → candidates that carry a vetted Metasploit module. Only
    #     these can be actively confirmed, so only these enter the ReAct/msf loop.
    #     This is what stops the no_module flood: module-less NVD entries never
    #     reach msf_check anymore.
    #   ADVISORY lane  → decent RAG matches with NO module. Can't be validated,
    #     so they're recorded as "potential exposure, manual review" and shown in
    #     the report — never sent to Metasploit.
    #
    # msf_check remains the real arbiter for the validate lane; RAG only decides
    # which lane a candidate falls into.
    CONFIDENCE_THRESHOLD = 0.55
    ADVISORY_THRESHOLD = 0.50

    best_per_port = {}
    for c in all_candidates:  # already sorted desc by combined_score
        p = c["matched_port"]
        if p in best_per_port:
            continue
        if not c["metadata"].get("metasploit_module"):
            continue  # can't run msf_check without a module
        if c["combined_score"] < 0.40:
            continue  # floor — don't validate near-random matches
        best_per_port[p] = c

    high_confidence = []
    advisory = []
    seen = set()
    for c in all_candidates:
        cve_id = c["metadata"].get("cve_id", "")
        key = (cve_id, c["matched_port"])
        if key in seen:
            continue
        has_module = bool(c["metadata"].get("metasploit_module"))

        if has_module and (
            c["combined_score"] >= CONFIDENCE_THRESHOLD
            or best_per_port.get(c["matched_port"]) is c
        ):
            c["routing"] = "validate"
            seen.add(key)
            high_confidence.append(c)
        elif not has_module and c["combined_score"] >= ADVISORY_THRESHOLD:
            c["routing"] = "advisory"
            seen.add(key)
            advisory.append(c)
        # else: below both bars — dropped from both lanes (no routing tag)

    high_confidence.sort(key=lambda x: x["combined_score"], reverse=True)
    advisory.sort(key=lambda x: x["combined_score"], reverse=True)

    vuln_state.rag_high_confidence = high_confidence

    # record advisory matches now — they skip validation entirely
    for c in advisory:
        adv = build_confirmed_vuln(
            c,
            ValidationStatus.ADVISORY,
            "no exploit module in KB — potential exposure, manual review required",
            recon_state,
        )
        adv.notes = "advisory: matched by RAG, no active validation available"
        vuln_state.advisory.append(adv)
        events.finding(
            c["metadata"].get("cve_id", ""),
            c["metadata"].get("severity", "medium"),
            "advisory",
            f"{c['matched_port']}/{c['matched_service']}",
            "Potential exposure — no exploit module, manual review.",
        )

    print(f"[VulnAgent] RAG found {len(all_candidates)} candidates")
    print(f"[VulnAgent] {len(high_confidence)} to validate, {len(advisory)} advisory (no module)")

    # RAG inspection surface — emit the candidate table (both lanes) so the UI can
    # show WHY each match was kept and where it was routed.
    events.rag_inspection(high_confidence + advisory)
    events.thought(
        f"Cross-referenced recon against the knowledge base "
        f"({kb.count()} CVEs). {len(all_candidates)} candidates matched. "
        f"{len(high_confidence)} carry a Metasploit module and go to active "
        f"validation (bar {CONFIDENCE_THRESHOLD:.2f}, plus the best msf-backed "
        f"candidate per port); {len(advisory)} have no module and are logged as "
        f"advisory findings for manual review.",
        who="rag matching",
    )

    if not high_confidence:
        print("[VulnAgent] no module-backed candidates — skipping active validation")
        return vuln_state

    # print RAG layer results
    print(f"\n RAG CANDIDATES (validate lane)")
    for c in high_confidence:
        print(
            f"  {c['metadata']['cve_id']} "
            f"port={c['matched_port']} "
            f"score={c['combined_score']:.2f} "
            f"msf={c['metadata']['metasploit_module']}"
        )

    # LAYER 2: ACTIVE VALIDATION ReAct loop
    print(f"\n[VulnAgent] starting active validation layer...")
    print(f"[VulnAgent] {len(high_confidence)} candidates to validate\n")

    # build candidates summary for agent context
    candidates_text = "\n".join([
        f"- {c['metadata']['cve_id']} "
        f"port={c['matched_port']} "
        f"service={c['matched_service']} "
        f"version={c['matched_version']} "
        f"score={c['combined_score']:.2f} "
        f"msf={c['metadata']['metasploit_module']}"
        for c in high_confidence
    ])

    system_prompt = f"""You are an expert penetration tester performing active vulnerability validation.

You have already completed reconnaissance and RAG-based vulnerability matching.
Your job now is to CONFIRM or DENY each candidate vulnerability through active validation.

TARGET: {recon_state.target}

RECON SUMMARY:
{vuln_state.recon_summary}

RAG CANDIDATES TO VALIDATE (ordered by confidence):
{candidates_text}

VALIDATION WORKFLOW — for each candidate:
1. run_connectivity_check — confirm port is reachable
2. run_banner_grab — confirm exact version matches expected
3. run_msf_check — pass the candidate's cve_id; the system runs the vetted
   Metasploit module from the knowledge base. Do NOT invent or pass module
   names — you only supply target, port, and cve_id.

RULES:
- Validate ONE candidate at a time, ONE tool at a time
- If connectivity check fails → mark as UNCONFIRMED, move to next candidate
- If banner version doesn't match → lower confidence, still run msf_check
- If msf_check returns 'vulnerable' → CONFIRMED
- If msf_check returns 'safe' → mark as UNCONFIRMED
- If msf_check returns 'unsupported' (module has no check method) → PROBABLE if banner matched, else UNCONFIRMED
- If msf_check returns 'no_module' (KB has no module for this CVE) → UNCONFIRMED
- If msf_check returns 'invalid_module' or 'error' → UNCONFIRMED
- Stop when all candidates have been validated
- After all candidates validated, stop calling tools and give final summary

After each tool result reason:
- What did this tell me about the candidate?
- Is this candidate confirmed, probable, or unconfirmed?
- What is the next validation step?
"CRITICAL: You must validate ALL {len(high_confidence)} candidates before stopping."
"Currently validated: {len(vuln_state.all_findings())} of {len(high_confidence)}."
"Do NOT stop until all candidates have been through msf_check."""

    messages = [
        {"role": "system", "content": system_prompt},
        {
            "role": "user",
            "content": (
                f"Please validate all {len(high_confidence)} RAG candidates "
                f"against target {recon_state.target}."
            ),
        },
    ]

    # ReAct loop
    max_iterations = len(high_confidence) * 10 # max 10 tool calls per candidate
    iteration = 0

    while iteration < max_iterations:
        iteration += 1

        # inject current state into context
        state_message = {
            "role": "user",
            "content": f"[CURRENT VALIDATION STATE]\n{vuln_state.summary()}"
        }

        context = (
            [messages[0]]       # system prompt
            + [messages[1]]     # original task
            + [state_message]   # current state
            + messages[-6:]     # last 6 messages for continuity
        )

        completion = _llm_create_with_retry(
            client,
            model=LLM_MODEL,
            messages=context,
            tools=tools,
        )

        response_message = completion.choices[0].message
        messages.append(response_message)

        # show reasoning
        reasoning = (
            getattr(response_message, "reasoning", None)
            or response_message.content
            or "(no reasoning)"
        )
        print(f"\n[VulnAgent reasoning]:\n{reasoning}")
        events.thought(reasoning)

        # no tool calls == agent finished
        if not response_message.tool_calls:
            print("\n[VulnAgent] validation complete — no more tool calls")
            print(response_message.content)
            break

        # execute tool
        tool_call = response_message.tool_calls[0]
        tool_name = tool_call.function.name
        tool_args = json.loads(tool_call.function.arguments)

        print(f"\n[VulnAgent tool]: {tool_name} {tool_args}")
        vuln_state.validations_run.append(tool_name)

        # msf_check: the agent gives us a cve_id, not a module. Resolve the
        # vetted module from RAG metadata so a hallucinated module name can
        # never reach msfconsole. Inject it as msf_module for call_tool,
        # the UI line, and state classification.
        if tool_name == "run_msf_check":
            tool_args["msf_module"] = _resolve_msf_module(
                high_confidence, tool_args.get("cve_id", ""), tool_args.get("port")
            )

        _fam, _line = _vuln_cmd(tool_name, tool_args)
        _cid = events.tool_start(_fam, _line)
        _t0 = time.time()
        try:
            result = call_tool(tool_name, tool_args)
            events.tool_end(_cid, time.time() - _t0, result, ok=True)
        except Exception as _e:
            events.tool_end(_cid, time.time() - _t0, f"{type(_e).__name__}: {_e}", ok=False)
            raise
        print(f"[VulnAgent result]: {result}")

        # check if this tool call completed a candidate validation
        _update_vuln_state(
            tool_name, tool_args, result,
            high_confidence, vuln_state, recon_state
        )

        messages.append({
            "role": "tool",
            "tool_call_id": tool_call.id,
            "content": json.dumps(result),
        })

    # any candidates not validated → unconfirmed
    _finalize_unconfirmed(high_confidence, vuln_state, recon_state)

    # final summary
    print(f"[VulnAgent] VALIDATION COMPLETE")
    print(f"  Confirmed:   {len(vuln_state.confirmed)}")
    print(f"  Probable:    {len(vuln_state.probable)}")
    print(f"  Unconfirmed: {len(vuln_state.unconfirmed)}")
    print(f"  Exploitable: {len(vuln_state.exploitable())}")
    print(f"\n CONFIRMED VULNERABILITIES")
    for v in vuln_state.confirmed:
        print(f"  {v.to_agent_summary()}")

    return vuln_state


# state update helpers
def _update_vuln_state(
    tool_name: str,
    tool_args: dict,
    result: dict,
    candidates: list,
    vuln_state: VulnState,
    recon_state: ReconState,
) -> None:
    """
    After each tool call, check if we have enough info
    to classify a candidate and update vuln_state.
    """
    if tool_name != "run_msf_check":
        return  # only classify after msf_check

    msf_status = result.get("status", "unknown")
    port = tool_args.get("port")
    cve_id = tool_args.get("cve_id", "")

    # find matching candidate by (cve_id, port) — the agent tells us which
    # candidate it validated. Fall back to cve_id alone.
    candidate = next(
        (c for c in candidates
         if c["metadata"].get("cve_id") == cve_id and c["matched_port"] == port),
        None,
    )
    if candidate is None:
        candidate = next(
            (c for c in candidates if c["metadata"].get("cve_id") == cve_id),
            None,
        )

    if not candidate:
        return

    cve_id = candidate["metadata"]["cve_id"]

    # skip if already classified
    if any(v.cve_id == cve_id for v in vuln_state.all_findings()):
        return

    _sev = candidate["metadata"].get("severity", "medium")
    _loc = f"{candidate['matched_port']}/{candidate['matched_service']}"

    if msf_status == "vulnerable":
        vuln = build_confirmed_vuln(
            candidate,
            ValidationStatus.CONFIRMED,
            result.get("output", ""),
            recon_state,
        )
        vuln_state.confirmed.append(vuln)
        print(f"[VulnAgent] CONFIRMED: {cve_id}")
        events.finding(cve_id, _sev, "confirmed", _loc,
                       "Active validation passed (msf check: vulnerable).")

    elif msf_status == "unsupported":
        vuln = build_confirmed_vuln(
            candidate,
            ValidationStatus.PROBABLE,
            result.get("output", ""),
            recon_state,
        )
        vuln_state.probable.append(vuln)
        print(f"[VulnAgent] PROBABLE: {cve_id}")
        events.finding(cve_id, _sev, "probable", _loc,
                       "Module has no check method — probable, needs manual confirmation.")

    else:
        vuln = build_confirmed_vuln(
            candidate,
            ValidationStatus.UNCONFIRMED,
            result.get("output", ""),
            recon_state,
        )
        vuln_state.unconfirmed.append(vuln)
        print(f"[VulnAgent] UNCONFIRMED: {cve_id}")


def _finalize_unconfirmed(
    candidates: list,
    vuln_state: VulnState,
    recon_state: ReconState,
) -> None:
    """Mark any candidates the agent never validated as UNCONFIRMED."""
    validated_cves = {v.cve_id for v in vuln_state.all_findings()}

    for candidate in candidates:
        cve_id = candidate["metadata"]["cve_id"]
        if cve_id not in validated_cves:
            vuln = build_confirmed_vuln(
                candidate,
                ValidationStatus.UNCONFIRMED,
                "not validated — agent did not reach this candidate",
                recon_state,
            )
            vuln_state.unconfirmed.append(vuln)
            print(f"[VulnAgent] UNCONFIRMED (not reached): {cve_id}")