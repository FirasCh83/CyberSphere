import asyncio
import json
import sys
import os
import uuid
import threading
import subprocess
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

sessions = {}

class StartRequest(BaseModel):
    target: str


@app.post("/api/session/start")
async def start_session(req: StartRequest):
    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        "target": req.target,
        "status": "running",
        "logs": [],
    }
    # use a thread instead of asyncio subprocess — works on Windows
    thread = threading.Thread(
        target=run_pipeline_thread,
        args=(session_id, req.target),
        daemon=True
    )
    thread.start()
    return {"session_id": session_id, "target": req.target}


@app.get("/api/session/{session_id}/stream")
async def stream_logs(session_id: str):
    async def event_generator():
        last_index = 0
        while True:
            session = sessions.get(session_id)
            if not session:
                yield f"data: {json.dumps({'error': 'session not found'})}\n\n"
                break
            logs = session["logs"]
            if last_index < len(logs):
                for line in logs[last_index:]:
                    yield f"data: {json.dumps({'log': line})}\n\n"
                last_index = len(logs)
            if session["status"] in ("done", "error"):
                yield f"data: {json.dumps({'status': session['status']})}\n\n"
                break
            await asyncio.sleep(0.3)

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.get("/api/session/{session_id}/state")
async def get_state(session_id: str):
    session = sessions.get(session_id)
    if not session:
        return {"error": "session not found"}
    return {"status": session["status"]}


@app.get("/api/health")
async def health():
    import docker
    try:
        client = docker.from_env()
        client.ping()
        return {"status": "ok", "docker": "connected"}
    except Exception as e:
        return {"status": "error", "docker": str(e)}


# ---------------------------------------------------------------------------
# Live findings extraction — keeps the UI's findings panel in sync as the
# pipeline streams. Reads the STRUCTURED [[CSEVENT]] channel (handoff / finding
# / report) rather than regex-scraping prose, which used to invent fake CVE
# cards out of ordinary log sentences.
# ---------------------------------------------------------------------------

CSEVENT_MARKER = "[[CSEVENT]]"


def _iter_events(logs: list):
    """Yield each parsed [[CSEVENT]] JSON object from the raw log lines."""
    for line in logs:
        idx = line.find(CSEVENT_MARKER)
        if idx == -1:
            continue
        payload = line[idx + len(CSEVENT_MARKER):].strip()
        try:
            yield json.loads(payload)
        except (ValueError, TypeError):
            continue


def extract_findings(logs: list) -> dict:
    """Build the findings panel from structured events only.

    Severity tiles count only *validated* findings (confirmed / probable) so the
    live panel matches the report's framing. Advisory matches (RAG hits with no
    exploit module — potential exposure, never validated) are returned in their
    own list instead of inflating the crit/high tiles.
    """
    open_ports = []
    seen_ports = set()
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    findings = []          # validated: confirmed / probable
    advisory = []          # no-module RAG matches, potential exposure only
    seen_findings = set()

    def _add_port(port, service=""):
        key = str(port)
        if not key or key in seen_ports:
            return
        seen_ports.add(key)
        open_ports.append({"port": port, "service": service})

    for ev in _iter_events(logs):
        etype = ev.get("type")

        # ports come from the recon→vuln handoff (early) and the final report
        if etype in ("handoff", "report"):
            src = ev if etype == "handoff" else ev.get("data", {})
            for p in src.get("ports", src.get("open_ports", [])):
                if isinstance(p, dict):
                    _add_port(p.get("port"), p.get("service", ""))
                else:
                    _add_port(p)

        # each classified finding is a real, structured event
        elif etype == "finding":
            cve = ev.get("cve", "")
            loc = ev.get("location", "")
            key = (cve, loc)
            if key in seen_findings:
                continue
            seen_findings.add(key)
            sev = (ev.get("severity") or "info").lower()
            status = (ev.get("status") or "").lower()
            item = {
                "cve": cve,
                "severity": sev,
                "status": status,
                "detail": ev.get("detail", "")[:200],
                "location": loc,
            }
            if status == "advisory":
                advisory.append(item)
            else:
                findings.append(item)
                if sev in sev_counts:
                    sev_counts[sev] += 1

    return {
        "open_ports": open_ports,
        "severity_counts": sev_counts,
        "findings": findings,
        "advisory": advisory,
    }


@app.get("/api/session/{session_id}/findings")
async def get_findings(session_id: str):
    session = sessions.get(session_id)
    if not session:
        return {"error": "session not found"}
    return {
        "status": session["status"],
        "target": session.get("target", ""),
        **extract_findings(session["logs"]),
    }


def run_pipeline_thread(session_id: str, target: str):
    """Runs orchestrator.py in a thread using blocking subprocess — Windows safe."""
    project_root = os.path.dirname(os.path.abspath(__file__))
    orchestrator_path = os.path.join(project_root, "orchestrator.py")
    python_exe = sys.executable

    sessions[session_id]["logs"].append(f"[CyberSphere] starting pipeline for: {target}")
    sessions[session_id]["logs"].append(f"[CyberSphere] backend={python_exe} cwd={project_root}")

    try:
        process = subprocess.Popen(
            [python_exe, "-u", orchestrator_path, target],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=project_root,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            env={**os.environ, "PYTHONUNBUFFERED": "1"},  # line buffered
        )

        for line in process.stdout:
            stripped = line.strip()
            if stripped:
                sessions[session_id]["logs"].append(stripped)

        rc = process.wait()
        if rc == 0:
            sessions[session_id]["status"] = "done"
            sessions[session_id]["logs"].append("[CyberSphere] pipeline complete.")
        else:
            # pipeline crashed — surface the last log lines so the UI shows WHY
            sessions[session_id]["status"] = "error"
            sessions[session_id]["logs"].append(f"[CyberSphere] pipeline FAILED (exit code {rc}) — last lines above show the traceback")

    except Exception as e:
        import traceback
        sessions[session_id]["logs"].append(f"[ERROR] {type(e).__name__}: {str(e)}")
        sessions[session_id]["logs"].append(traceback.format_exc())
        sessions[session_id]["status"] = "done"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")
