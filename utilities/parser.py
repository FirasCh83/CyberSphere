import re
from typing import List, Dict
import json
from datetime import datetime


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
        #Missing security headers
        headers = data.get("headers", {})
        if headers:
            headers_lower = {k.lower(): v for k, v in headers.items()}
            for h in security_headers:
                if h not in headers_lower:
                    result["missing_headers"].append(f"Missing security header: {h} on {service['url']}")

                    
    result["technologies"] = list(set(result["technologies"]))
    return result



def parse_whois_output(raw: str) -> Dict:
    """Parse raw whois text output into structured findings."""
    result = {
        "registrar": None,
        "org": None,
        "country": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "emails": [],
        "domain_age_days": None,
        "days_until_expiry": None,
        "key_findings": [],
    }

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("%") or line.startswith("#"):
            continue

        lower = line.lower()

        # Registrar
        if lower.startswith("registrar:") and not result["registrar"]:
            result["registrar"] = line.split(":", 1)[1].strip()

        # Org
        if any(lower.startswith(k) for k in ["org:", "organisation:", "organization:"]):
            if not result["org"]:
                result["org"] = line.split(":", 1)[1].strip()

        # Country
        if lower.startswith("country:") and not result["country"]:
            result["country"] = line.split(":", 1)[1].strip()

        # Dates
        if any(lower.startswith(k) for k in ["creation date:", "created:", "registered:"]):
            if not result["creation_date"]:
                result["creation_date"] = line.split(":", 1)[1].strip()

        if any(lower.startswith(k) for k in ["expir", "registry expiry date:", "expiration date:"]):
            if not result["expiration_date"]:
                result["expiration_date"] = line.split(":", 1)[1].strip()

        if lower.startswith("updated date:") or lower.startswith("last updated:"):
            if not result["updated_date"]:
                result["updated_date"] = line.split(":", 1)[1].strip()

        # Name servers
        if lower.startswith("name server:") or lower.startswith("nserver:"):
            ns = line.split(":", 1)[1].strip().lower()
            if ns and ns not in result["name_servers"]:
                result["name_servers"].append(ns)

        # Status
        if lower.startswith("domain status:") or lower.startswith("status:"):
            status = line.split(":", 1)[1].strip()
            if status and status not in result["status"]:
                result["status"].append(status)

        # Emails
        email_match = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", line)
        for email in email_match:
            if email not in result["emails"]:
                result["emails"].append(email)

    # Calculate domain age and expiry countdown
    for date_str in [result["creation_date"], result["expiration_date"]]:
        if not date_str:
            continue
        for fmt in ["%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y", "%Y-%m-%dT%H:%M:%S"]:
            try:
                parsed_date = datetime.strptime(date_str[:19], fmt[:len(date_str[:19])])
                if date_str == result["creation_date"]:
                    result["domain_age_days"] = (datetime.now() - parsed_date).days
                elif date_str == result["expiration_date"]:
                    result["days_until_expiry"] = (parsed_date - datetime.now()).days
                break
            except ValueError:
                continue

    # Generate key findings
    if result["domain_age_days"] is not None:
        if result["domain_age_days"] < 90:
            result["key_findings"].append(
                f"⚠️ Domain is only {result['domain_age_days']} days old — newly registered, suspicious"
            )
        else:
            result["key_findings"].append(
                f"Domain age: {result['domain_age_days']} days"
            )

    if result["days_until_expiry"] is not None:
        if result["days_until_expiry"] < 0:
            result["key_findings"].append(
                "🚨 Domain is EXPIRED — high risk of domain takeover"
            )
        elif result["days_until_expiry"] < 30:
            result["key_findings"].append(
                f"⚠️ Domain expires in {result['days_until_expiry']} days — takeover risk"
            )

    if result["registrar"]:
        result["key_findings"].append(f"Registrar: {result['registrar']}")

    if result["org"]:
        result["key_findings"].append(f"Organization: {result['org']}")

    if result["name_servers"]:
        result["key_findings"].append(f"Name servers: {', '.join(result['name_servers'])}")

    return result