import json
import os
from dotenv import load_dotenv
from openai import OpenAI
from utilities.models import ConfirmedVulnerability, VulnState, Severity, ExploitationComplexity, ValidationStatus
from utilities.state import ReconState
from knowledge.query import VulnKnowledgeBase
from tools.validation.connectivity import run_connectivity_check
from tools.validation.banner_grab import run_banner_grab, version_matches
from tools.validation.msf_check import run_msf_check

load_dotenv()

client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY")
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
                "candidate is worth checking. Slow (~30-60s per check)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target":     {"type": "string"},
                    "port":       {"type": "integer"},
                    "msf_module": {"type": "string"},
                },
                "required": ["target", "port", "msf_module"],
                "additionalProperties": False,
            },
            "strict": True,
        },
    },
]

# helpers 

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


def generate_recon_summary(recon_state: ReconState) -> str:
    """
    Ask the LLM to summarize ReconState into a compact
    vulnerability-focused brief for the vuln agent.
    """
    print("[VulnAgent] generating recon summary...")

    prompt = f"""You are a senior penetration tester.
Summarize the following recon findings into a concise vulnerability-focused brief.
Focus on: open ports, service versions, known-vulnerable software, and attack surface.
Keep it under 200 words.

RECON STATE:
{recon_state.summary()}
"""
    response = client.chat.completions.create(
        model="openrouter/free",
        messages=[{"role": "user", "content": prompt}],
        tools=tools
    )
    return response.choices[0].message.content or ""


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

    # LAYER 1: RAG 
    print(f"[VulnAgent] target: {recon_state.target}")
    print(f"[VulnAgent] starting RAG layer...")

    kb = VulnKnowledgeBase()
    print(f"[VulnAgent] knowledge base: {kb.count()} vulnerabilities loaded")

    # generate LLM summary of recon findings
    vuln_state.recon_summary = generate_recon_summary(recon_state)
    print(f"\n[VulnAgent] recon summary:\n{vuln_state.recon_summary}\n")

    # query KB against recon state
    all_candidates = kb.match_against_recon(recon_state)
    vuln_state.rag_candidates = all_candidates

    high_confidence = [c for c in all_candidates if c["combined_score"] >= 0.6]
    vuln_state.rag_high_confidence = high_confidence

    print(f"[VulnAgent] RAG found {len(all_candidates)} candidates")
    print(f"[VulnAgent] {len(high_confidence)} above confidence threshold")

    if not high_confidence:
        print("[VulnAgent] no high confidence candidates — skipping active validation")
        return vuln_state

    # print RAG layer results
    print(f"\n RAG CANDIDATES")
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
3. run_msf_check — run Metasploit check() to confirm exploitability

RULES:
- Validate ONE candidate at a time, ONE tool at a time
- If connectivity check fails → mark as UNCONFIRMED, move to next candidate
- If banner version doesn't match → lower confidence, still run msf_check
- If msf_check returns 'vulnerable' → CONFIRMED
- If msf_check returns 'safe' → mark as UNCONFIRMED
- If msf_check returns 'unsupported' → mark as PROBABLE if banner matched
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

        completion = client.chat.completions.create(
            model="openrouter/free",
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

        result = call_tool(tool_name, tool_args)
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
    msf_module = tool_args.get("msf_module", "")

    # find matching candidate
    candidate = next(
        (c for c in candidates
         if c["matched_port"] == port
         and c["metadata"].get("metasploit_module") == msf_module),
        None
    )

    if not candidate:
        return

    cve_id = candidate["metadata"]["cve_id"]

    # skip if already classified
    if any(v.cve_id == cve_id for v in vuln_state.all_findings()):
        return

    if msf_status == "vulnerable":
        vuln = build_confirmed_vuln(
            candidate,
            ValidationStatus.CONFIRMED,
            result.get("output", ""),
            recon_state,
        )
        vuln_state.confirmed.append(vuln)
        print(f"[VulnAgent] CONFIRMED: {cve_id}")

    elif msf_status == "unsupported":
        vuln = build_confirmed_vuln(
            candidate,
            ValidationStatus.PROBABLE,
            result.get("output", ""),
            recon_state,
        )
        vuln_state.probable.append(vuln)
        print(f"[VulnAgent] PROBABLE: {cve_id}")

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