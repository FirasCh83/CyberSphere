"""
Structured streaming events for the CyberSphere UI.

Agents already print free-form text to stdout (which the server captures line
by line and streams over SSE, and which the /findings endpoint regex-parses).
On top of that raw stream we emit a second, machine-readable channel: single
lines prefixed with [[CSEVENT]] followed by a compact JSON object. The frontend
picks these out to render the chat conversation — phases, agent reasoning, and
command cards with live timers — while the raw prints stay untouched so nothing
else breaks.
"""

import json
import sys
import itertools

MARKER = "[[CSEVENT]]"
_counter = itertools.count(1)


def emit(event: dict) -> None:
    """Write one [[CSEVENT]] line and flush so it streams immediately."""
    try:
        sys.stdout.write(MARKER + json.dumps(event, ensure_ascii=False) + "\n")
        sys.stdout.flush()
    except Exception:
        # streaming is best-effort — never let a UI event kill the pipeline
        pass


def phase(name: str, sub: str = "") -> None:
    """Start a new agent turn in the conversation (e.g. 'Recon Agent')."""
    emit({"type": "phase", "name": name, "sub": sub})


def thought(text, who: str = "reasoning") -> None:
    """Stream a block of agent reasoning / narration."""
    if text is None:
        return
    text = str(text).strip()
    if not text:
        return
    emit({"type": "thought", "who": who, "text": text})


def tool_start(tool: str, line: str) -> str:
    """Announce a command is running; returns an id to close it with tool_end."""
    cid = f"cmd{next(_counter)}"
    emit({"type": "tool_start", "id": cid, "tool": tool, "line": line})
    return cid


def tool_end(cid: str, elapsed: float, result="", ok: bool = True) -> None:
    """Close a running command with its backend-measured elapsed + output."""
    emit({
        "type": "tool_end",
        "id": cid,
        "elapsed": round(float(elapsed), 1),
        "result": _clip(result),
        "ok": bool(ok),
    })


def done(text: str = "") -> None:
    """Mark the pipeline's final summary."""
    emit({"type": "done", "text": str(text)})


def report(data: dict) -> None:
    """Emit the final structured assessment report for the Reports view."""
    emit({"type": "report", "data": data})


def handoff(frm: str, to: str, ports: list, findings: int = 0) -> None:
    """Announce a structured agent-to-agent handoff (e.g. Recon → Vuln).

    `ports` is the list of open-port rows being passed downstream so the UI can
    show exactly what one agent handed the next, instead of a silent gap.
    """
    rows = []
    for p in ports or []:
        if isinstance(p, dict):
            rows.append({
                "port": p.get("port"),
                "service": p.get("service", ""),
                "version": p.get("version", ""),
            })
        else:
            rows.append({"port": p, "service": "", "version": ""})
    emit({"type": "handoff", "from": frm, "to": to, "ports": rows, "findings": int(findings)})


def rag_inspection(candidates: list) -> None:
    """Emit the RAG candidate table so the UI can show WHY each match was kept.

    Each row: cve / port / service / scores / whether it has an msf module /
    the routing decision (validate vs advisory). This is the 'rag inspection'
    surface — the reasoning that used to only exist in stdout.
    """
    rows = []
    for c in candidates or []:
        meta = c.get("metadata", {})
        rows.append({
            "cve": meta.get("cve_id", ""),
            "port": c.get("matched_port"),
            "service": c.get("matched_service", ""),
            "version": c.get("matched_version", ""),
            "combined": round(float(c.get("combined_score", 0.0)), 2),
            "semantic": round(float(c.get("semantic_score", 0.0)), 2),
            "evidence": round(float(c.get("evidence_score", 0.0)), 2),
            "has_module": bool(meta.get("metasploit_module")),
            "module": meta.get("metasploit_module", ""),
            "decision": c.get("routing", ""),
        })
    emit({"type": "rag_inspection", "rows": rows})


def finding(cve: str, severity: str, status: str, location: str = "", detail: str = "") -> None:
    """Emit a single structured finding as it is classified.

    The findings side-rail is fed from these events (real data) instead of
    regex-scraping prose out of stdout.
    """
    emit({
        "type": "finding",
        "cve": cve,
        "severity": severity,
        "status": status,
        "location": location,
        "detail": detail,
    })


def _clip(result, limit: int = 1600) -> str:
    """Render any tool result into a readable, length-capped string."""
    if isinstance(result, (dict, list)):
        try:
            result = json.dumps(result, ensure_ascii=False, indent=2)
        except Exception:
            result = str(result)
    else:
        result = str(result)
    if len(result) > limit:
        result = result[:limit] + "\n… (output truncated)"
    return result
