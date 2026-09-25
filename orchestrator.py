import sys
from datetime import datetime
from agents.recon import run_recon_agent
from agents.vuln import run_vuln_agent
from utilities.state import ReconState
from utilities.models import VulnState
from utilities import events

# Force UTF-8 stdout/stderr so non-cp1252 characters (emoji like 📡, CJK, etc.)
# in agent responses don't crash printing on the Windows console.
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.stderr.reconfigure(encoding="utf-8", errors="replace")

def run_pipeline(target: str) :
    print(f"[Cybersphere] starting pipeline for: {target}")
    print("[Orchestrator] launching Recon Agent...")
    recon_state = run_recon_agent(target)

    print(f"\n[Orchestrator] Recon complete:")
    print(f"  Open ports:  {[p['port'] for p in recon_state.open_ports]}")
    print(f"  Findings:    {len(recon_state.findings)}")
    print(f"  Scans run:   {recon_state.scans_run}")

    print(f"\n[Orchestrator] handing ReconState to Vuln Agent...")
    events.handoff(
        "Recon Agent", "Vuln Agent",
        recon_state.open_ports,
        findings=len(recon_state.findings),
    )

    print("[Orchestrator] launching Vulnerability Agent...")
    vuln_state = run_vuln_agent(recon_state)
    print(f"\n[Orchestrator] Vuln Agent complete:")
    print(f"  Confirmed:   {len(vuln_state.confirmed)}")
    print(f"  Probable:    {len(vuln_state.probable)}")
    print(f"  Unconfirmed: {len(vuln_state.unconfirmed)}")
    print(f"  Advisory:    {len(vuln_state.advisory)}")
    print(f"  Exploitable: {len(vuln_state.exploitable())}")
    print(f"[Cybersphere] PIPELINE COMPLETE")

    # final report turn for the UI conversation
    events.phase("Report", "summary")
    summary = (
        f"Assessment complete for {target}. "
        f"{len(vuln_state.confirmed)} confirmed, "
        f"{len(vuln_state.probable)} probable, "
        f"{len(vuln_state.unconfirmed)} unconfirmed — "
        f"{len(vuln_state.exploitable())} exploitable with a working Metasploit path. "
        f"Open ports: {[p['port'] for p in recon_state.open_ports]}."
    )
    events.thought(summary, who="summary")

    # structured report for the Reports tab — built from the real state objects
    def _port_row(p):
        if isinstance(p, dict):
            return {"port": p.get("port"), "service": p.get("service", ""), "version": p.get("version", "")}
        return {"port": p, "service": "", "version": ""}

    report = {
        "target": target,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "os_guess": getattr(recon_state, "os_guess", "") or "",
        "counts": {
            "confirmed": len(vuln_state.confirmed),
            "probable": len(vuln_state.probable),
            "unconfirmed": len(vuln_state.unconfirmed),
            "advisory": len(vuln_state.advisory),
            "exploitable": len(vuln_state.exploitable()),
        },
        "open_ports": [_port_row(p) for p in recon_state.open_ports],
        "confirmed": [v.to_dict() for v in vuln_state.confirmed],
        "probable": [v.to_dict() for v in vuln_state.probable],
        "unconfirmed": [v.to_dict() for v in vuln_state.unconfirmed],
        "advisory": [v.to_dict() for v in vuln_state.advisory],
        "recon_summary": vuln_state.recon_summary,
        "summary": summary,
    }
    events.report(report)
    events.done(summary)

    print(recon_state.summary())
    print(vuln_state.summary())

    return recon_state, vuln_state

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else input("Enter target: ")
    run_pipeline(target)