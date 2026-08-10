import sys
from agents.recon import run_recon_agent
from agents.vuln import run_vuln_agent
from utilities.state import ReconState
from utilities.models import VulnState

def run_pipeline(target: str) :
    print(f"[Cybersphere] starting pipeline for: {target}")
    print("[Orchestrator] launching Recon Agent...")
    recon_state = run_recon_agent(target)

    print(f"\n[Orchestrator] Recon complete:")
    print(f"  Open ports:  {[p['port'] for p in recon_state.open_ports]}")
    print(f"  Findings:    {len(recon_state.findings)}")
    print(f"  Scans run:   {recon_state.scans_run}")

    print(f"\n[Orchestrator] handing ReconState to Vuln Agent...")

    print("[Orchestrator] launching Vulnerability Agent...")
    vuln_state = run_vuln_agent(recon_state)
    print(f"\n[Orchestrator] Vuln Agent complete:")
    print(f"  Confirmed:   {len(vuln_state.confirmed)}")
    print(f"  Probable:    {len(vuln_state.probable)}")
    print(f"  Unconfirmed: {len(vuln_state.unconfirmed)}")
    print(f"  Exploitable: {len(vuln_state.exploitable())}")
    print(f"[Cybersphere] PIPELINE COMPLETE")

    print(recon_state.summary())
    print(vuln_state.summary())

    return recon_state, vuln_state

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else input("Enter target: ")
    run_pipeline(target)