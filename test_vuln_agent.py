# test_vuln_agent.py
from utilities.state import ReconState
from agents.vuln import run_vuln_agent

# simulate recon state from Metasploitable
recon_state = ReconState(target="192.168.56.107")
recon_state.open_ports = [
    {"port": 21,   "service": "ftp",         "version": "vsftpd 2.3.4"},
    {"port": 22,   "service": "ssh",         "version": "OpenSSH 4.7p1"},
    {"port": 445,  "service": "netbios-ssn", "version": "Samba 3.0.20"},
    {"port": 6667, "service": "irc",         "version": "UnrealIRCd"},
    {"port": 8009, "service": "ajp13",       "version": "Apache Jserv"},
    {"port": 2121, "service": "ftp",         "version": "ProFTPD 1.3.1"},
]
recon_state.findings = [
    "vsftpd 2.3.4 backdoor on port 21",
    "UnrealIRCd backdoor on port 6667",
    "Samba 3.0.20 on port 445",
]

# run the vulnerability agent
vuln_state = run_vuln_agent(recon_state)

print(f"\n--- FINAL VULN STATE ---")
print(vuln_state.summary())