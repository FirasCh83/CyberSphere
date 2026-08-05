import re
from typing import List, Dict

def parse_nmap_output(raw: str) -> Dict:
    """Strip nmap output down to just what matters for reasonning."""
    result = {
        "open_ports": [],
        "os_guess": None,
        "key_findings": [],
    }

    for line in raw.splitlines():
        port_match = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
        if port_match:
            port, service, version = port_match.groups()
            result["open_ports"].append({
                "port": int(port),
                "service": service,
                "version": version.strip()
            })
        
        os_match = re.match(r"OS details: (.+)", line)
        if os_match:
            result["os_guess"] = os_match.group(1)
        
        if any(x in line.lower() for x in ["anonymous", "vuln", "backdoor", "default credentials",
            "auth bypass", "remote code", "sql injection", "sslv2"]):
            result["key_findings"].append(line.strip())
    
    return result