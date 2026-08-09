from knowledge.query import VulnKnowledgeBase
from knowledge.populate.seed import populate_knowledge_base
from utilities.state import ReconState

#Initialise the knowledge base
kb = VulnKnowledgeBase()

#Populate it if empty
if kb.count() == 0:
    populate_knowledge_base(kb)

#Simulating a recon state from Metasploitable
test_state = ReconState(target= "192.168.56.07")
test_state.open_ports = [
    {"port": 21,   "service": "ftp",         "version": "vsftpd 2.3.4"},
    {"port": 22,   "service": "ssh",         "version": "OpenSSH 4.7p1"},
    {"port": 445,  "service": "netbios-ssn", "version": "Samba 3.0.20"},
    {"port": 6667, "service": "irc",         "version": "UnrealIRCd"},
    {"port": 8009, "service": "ajp13",       "version": "Apache Jserv"},
    {"port": 2121, "service": "ftp",         "version": "ProFTPD 1.3.1"},

]
#test matching
print("\n HIGH CONFIDENCE CANDIDATES")
candidates = kb.get_high_confidence_candidates(test_state)
for c in candidates:
    print(f"\nCVE: {c['metadata']['cve_id']}")
    print(f"  Port: {c['matched_port']} / {c['matched_service']}")
    print(f"  Semantic: {c['semantic_score']:.2f}")
    print(f"  Evidence: {c['evidence_score']:.2f}")
    print(f"  Combined: {c['combined_score']:.2f}")
    print(f"  MSF: {c['metadata']['metasploit_module']}")
