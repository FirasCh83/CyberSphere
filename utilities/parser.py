import re
from typing import List, Dict
import json
from datetime import datetime
from libnmap.parser import NmapParser, NmapParserException


def parse_nmap_output(raw: str) -> Dict:
    result = {
        "open_ports": [],
        "os_guess": None,
        "vulnerabilities": [],   # replaces key_findings for vuln data
        "key_findings": [],
    }

    try:
        report = NmapParser.parse(raw)
    except NmapParserException:
        # fallback if not valid XML — old regex parser
        return _parse_nmap_regex(raw)

    for host in report.hosts:
        if not host.is_up():
            continue

        # OS detection
        if host.os_fingerprinted and host.os.osmatch():
            best = host.os.osmatch()[0]
            result["os_guess"] = f"{best['name']} ({best['accuracy']}% confidence)"

        for svc in host.services:
            if svc.state != "open":
                continue

            port_info = {
                "port": svc.port,
                "protocol": svc.protocol,
                "service": svc.service,
                "version": f"{svc.servicefp or ''} {svc.banner or ''}".strip(),
            }
            result["open_ports"].append(port_info)

            # Extract NSE script output per port
            for script_id, script_out in svc.scripts_results:
                _extract_script_findings(
                    script_id, script_out, svc.port, svc.service, result
                )

        # Host-level scripts (smb, nbstat etc)
        for script_id, script_out in host.scripts_results:
            _extract_script_findings(
                script_id, script_out, None, None, result
            )

    return result


def _extract_script_findings(script_id, output, port, service, result):
    """Extract only the signal from NSE script output."""

    # Confirmed vulnerabilities
    if "VULNERABLE" in output:
        # Extract just the vuln name and state, not the 50-line description
        lines = output.splitlines()
        vuln_name = lines[0].strip() if lines else script_id
        result["vulnerabilities"].append({
            "port": port,
            "service": service,
            "script": script_id,
            "summary": vuln_name,
            "severity": _guess_severity(script_id, output),
        })
        result["key_findings"].append(
            f"VULNERABLE [{_guess_severity(script_id, output)}] port {port} — {vuln_name}"
        )
        return

    # Anonymous FTP
    if script_id == "ftp-anon" and "allowed" in output.lower():
        result["key_findings"].append(f"Anonymous FTP login allowed on port {port}")

    # SMB signing disabled
    if script_id == "smb-security-mode" and "disabled" in output.lower():
        result["key_findings"].append("SMB signing disabled — MITM attack possible")

    # IRC backdoor
    if script_id == "irc-unrealircd-backdoor" and "trojaned" in output.lower():
        result["key_findings"].append(f"UnrealIRCd BACKDOOR detected on port {port} — RCE")

    # RMI RCE
    if script_id == "rmi-vuln-classloader" and "VULNERABLE" in output:
        result["key_findings"].append(f"RMI registry RCE vulnerability on port {port}")

    # Bindshell
    if script_id == "bindshell-backdoor" or (service and "bindshell" in service):
        result["key_findings"].append(f"BACKDOOR root shell detected on port {port}")

    # SSLv2
    if script_id == "sslv2" and output.strip():
        result["key_findings"].append(f"SSLv2 supported on port {port} — critical weakness")

    # Vulners — only keep CVSS >= 9.0, max 5
    if script_id == "vulners":
        critical = []
        for line in output.splitlines():
            match = re.search(r"(CVE-\d{4}-\d+)\s+([\d.]+)", line)
            if match:
                cve, score = match.group(1), float(match.group(2))
                if score >= 9.0:
                    critical.append(f"{cve} (CVSS {score})")
            if len(critical) >= 5:
                break
        if critical:
            result["key_findings"].append(
                f"Critical CVEs on port {port} ({service}): {', '.join(critical)}"
            )


def _guess_severity(script_id, output):
    high_scripts = {"ssl-poodle", "ssl-ccs-injection", "smb-vuln-ms17-010",
                    "ftp-vsftpd-backdoor", "rmi-vuln-classloader"}
    if script_id in high_scripts:
        return "CRITICAL"
    if "10.0" in output or "9." in output:
        return "CRITICAL"
    if "7." in output or "8." in output:
        return "HIGH"
    return "MEDIUM"


def _parse_nmap_regex(raw: str) -> Dict:
    """Fallback regex parser for non-XML output."""
    result = {"open_ports": [], "os_guess": None, "vulnerabilities": [], "key_findings": []}
    for line in raw.splitlines():
        port_match = re.match(r"(\d+)/tcp\s+open\s+(\S+)\s*(.*)", line)
        if port_match:
            port, service, version = port_match.groups()
            result["open_ports"].append({
                "port": int(port), "service": service, "version": version.strip()
            })
        if any(x in line.lower() for x in ["anonymous", "backdoor", "vulnerable", "sslv2"]):
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