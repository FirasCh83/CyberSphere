import re
from typing import List, Dict
import json

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

def parse_httpx_output(raw: str) -> Dict:
    """Parse httpx JSON output into structured findings."""
    result = {
        "web_services": [],
        "technologies": [],
        "tls_issues": [],
        "missing_headers": [],
        "key_findings": [],
    }

    security_headers = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]
    for line in raw.strip().splitlines():
        if not line.strip():
            continue
        try:
            data= json.loads(line)
        except json.JSONDecodeError:
            continue

        #Basic web service info
        service = {
            "url": data.get("url", ""),
            "status_code": data.get("status_code"),
            "title": data.get("title"),
            "server": data.get("server", ""),
            "content_length": data.get("content_length"),
        }
        result["web_services"].append(service)

        #technologies
        techs = data.get("tech", []) or data.get("technologies", [])
        result["technologies"].extend(techs)

        #TLS issues
        tls = data.get("tls", {})
        if tls:
            version = tls.get("version", "")
            if version in ["TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"]:
                result["tls_issues"].append(f"Weak TLS version: {version} on {service['url']}")
            expiry = tls.get("not_after", "")
            if expiry:
                result["key_findings"].append(f"TLS cert expires: {expiry}")

        #Key findings worth flagging
        if data.get("status_code") == 200:
            title = data.get("title", "")
            if any(x in title.lower() for x in ["admin", "login", "dashboard", "cpanel", "wp-admin"]):
                result["key_findings"].append(f"Sensitive page found: {title} at {service['url']}")
    result["technologies"] = list(set(result["technologies"]))
    return result