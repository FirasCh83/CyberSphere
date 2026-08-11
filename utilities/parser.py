import re
from typing import List, Dict
import json
from datetime import datetime
from libnmap.parser import NmapParser, NmapParserException
from urllib.parse import urlparse, parse_qs

def _build_version_string(svc) -> str:
    """
    Build clean version string from libnmap NmapService attributes.
    libnmap stores everything in svc.service_dict
    """
    # libnmap stores parsed fields in service_dict
    d = getattr(svc, "service_dict", {}) or {}
    
    parts = []
    
    product = d.get("product", "")
    version = d.get("version", "")
    extrainfo = d.get("extrainfo", "")
    
    if product:
        parts.append(product)
    if version:
        parts.append(version)
    if extrainfo:
        parts.append(f"({extrainfo})")
    
    return " ".join(parts).strip()


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
                "version": _build_version_string(svc),
            }
            result["open_ports"].append(port_info)

            # Extract NSE script output per port
            _process_nmap_scripts(
                svc.scripts_results,
                svc.port,
                svc.service,
                result
            )
        # Host-level scripts (smb, nbstat etc)
    _process_nmap_scripts(
        host.scripts_results,
        None,
        None,
        result
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
        return result

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


def _process_nmap_scripts(scripts, port, service, result):
    for script in scripts:

        if isinstance(script, tuple):
            script_id = script[0]
            script_out = script[1]

        elif isinstance(script, dict):
            script_id = script.get("id")
            script_out = script.get("output", "")

        else:
            continue

        if not script_id:
            continue

        _extract_script_findings(
            script_id,
            script_out,
            port,
            service,
            result
        )


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

def parse_whatweb_output(raw: str) -> Dict:
    result = {
        "targets": [],
        "technologies": [],
        "key_findings": [],
    }

    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        target_url = data.get("target", "")
        http_status = data.get("http_status", "")
        plugins = data.get("plugins", {})

        target_info = {
            "url": target_url,
            "status": http_status,
            "technologies": []
        }

        for plugin_name, plugin_data in plugins.items():
            #Extract version if present
            version = None
            if "version" in plugin_data:
                versions = plugin_data["version"]
                version = versions[0] if versions else None
            
            string = None
            if "string" in plugin_data:
                strings = plugin_data["string"]
                string = strings[0] if strings else None
            tech_entry = {
                "name": plugin_name,
                "version": version,
                "string": string
            }
            target_info["technologies"].append(tech_entry)
            result["technologies"].append(plugin_name)

                        # flag interesting findings
            name_lower = plugin_name.lower()

            if name_lower == "wordpress" :
                result["key_findings"].append(
                    f"WordPress detected on {target_url}"
                    + (f" version {version}" if version else "")
                )
            if name_lower in ["joomla", "drupal", "magento"]:
                result["key_findings"].append(
                    f"{plugin_name} CMS detected on {target_url}"
                    + (f" version {version}" if version else "")
                )
            if name_lower == "php":
                result["key_findings"].append(
                    f"PHP {version or 'unknown version'} detected on {target_url}"
                )
            if name_lower == "apache":
                result["key_findings"].append(
                    f"Apache {version or ''} detected on {target_url}"
                )
            if name_lower == "x-powered-by":
                result["key_findings"].append(
                    f"X-Powered-By header exposed: {string} on {target_url}"
                )
            if name_lower == "email":
                result["key_findings"].append(
                    f"Email address exposed on {target_url}: {string}"
                )

        result["targets"].append(target_info)

    # deduplicate technologies
    result["technologies"] = list(set(result["technologies"]))

    return result


def parse_nuclei_output(raw: str) -> Dict:
    """
    Parse Nuclei JSONL output into structured findings.

    Two layers:
    - findings: canonical structured evidence (preserved for reporting)
    - key_findings: agent-facing summary (minimal tokens, maximum signal)
    """
    result = {
        "findings": [],
        "key_findings": [],
        "critical_count": 0,
        "high_count": 0,
        "medium_count": 0,
        "low_count": 0,
        "info_count": 0,
    }

    severity_order = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = data.get("info", {})
        severity = info.get("severity", "info").lower()
        classification = info.get("classification", {})

        finding = {
            "template_id": data.get("template-id", ""),
            "name": info.get("name", ""),
            "severity": severity,
            "description": info.get("description", ""),
            "host": data.get("host", ""),
            "ip": data.get("ip", ""),
            "port": data.get("port", ""),
            "scheme": data.get("scheme", ""),
            "url": data.get("url", ""),
            "matched_at": data.get("matched-at", ""),
            "tags": info.get("tags", []) or [],
            "cve": classification.get("cve-id"),
            "cvss_score": classification.get("cvss-score"),
            "cwe": classification.get("cwe-id"),
            "references": info.get("reference", []) or [],
            "extracted": data.get("extracted-results", []) or [],
            "matcher_name": data.get("matcher-name", ""),
        }
        result["findings"].append(finding)

        count_key = f"{severity}_count"
        if count_key in result:
            result[count_key] += 1

    result["findings"].sort(
        key=lambda x: severity_order.get(x["severity"], 99)
    )

    for finding in result["findings"]:
        parts = [
            f"[{finding['severity'].upper()}]",
            finding["name"],
            f"at {finding['matched_at']}",
        ]

        if finding["cve"]:
            parts.append(f"({finding['cve']})")

        if finding["cvss_score"] is not None:
            parts.append(f"CVSS {finding['cvss_score']}")

        if finding["extracted"]:
            extracted = str(finding["extracted"][0])[:80]
            parts.append(f"-> {extracted}")

        result["key_findings"].append(" ".join(parts))

    total = len(result["findings"])
    if total > 0:
        result["key_findings"].insert(0,
            f"Nuclei: {total} findings — "
            f"{result['critical_count']} critical, "
            f"{result['high_count']} high, "
            f"{result['medium_count']} medium, "
            f"{result['low_count']} low, "
            f"{result['info_count']} info"
        )
    else:
        result["key_findings"].append(
            "Nuclei: no findings for this scan profile"
        )

    return result




def parse_katana_output(raw: str) -> Dict:
    """
    Parse Katana JSONL crawl output into structured findings.
    Two layers:
    - endpoints: canonical structured evidence with full URL decomposition
    - key_findings: agent-facing summary
    """
    result = {
        # canonical evidence
        "endpoints": [],
        "forms": [],
        "emails": [],
        "interesting_endpoints": [],

        # agent summary
        "key_findings": [],

        # operational stats — tells agent if crawl was complete
        "crawl_stats": {
            "total_lines": 0,
            "unique_urls": 0,
            "forms_found": 0,
            "max_depth_events": 0,
            "other_errors": 0,
        },
    }

    # path segment based classification — avoids substring false positives
    categories = {
        "administrative": [
            "admin", "manager", "management", "console",
            "dashboard", "panel", "controlpanel", "cp",
        ],
        "authentication": [
            "login", "logout", "signin", "signup", "register",
            "auth", "oauth", "sso", "password", "reset",
            "wp-login", "wp-admin",
        ],
        "configuration": [
            "config", "configuration", "settings", "setup",
            "install", "phpinfo",
        ],
        "development": [
            "test", "dev", "debug", "staging", "demo",
            "beta", "swagger", "api-docs", "redoc",
        ],
        "backup": [
            "backup", "bak", "old", "archive", "dump",
            "export", "restore",
        ],
        "api": [
            "api", "v1", "v2", "v3", "graphql",
            "rest", "endpoint", "rpc",
        ],
        "file_management": [
            "upload", "download", "file", "files",
            "media", "static", "assets",
        ],
        "potential_secrets": [
            ".env", ".git", ".htaccess", "passwd",
            "shadow", "secret", "credentials", "key",
            "token", "private",
        ],
        "debugging": [
            "actuator", "health", "metrics", "trace",
            "heapdump", "env", "beans", "mappings",
        ],
    }

    seen_urls = set()
    placeholder_emails = {
        "yourdomain", "domain.com", "example",
        "somewhere.test", "your.company", "a@z.com",
        "name@domain", "webmaster@your",
    }

    for line in raw.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        result["crawl_stats"]["total_lines"] += 1

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        request = data.get("request", {})
        endpoint = request.get("endpoint", "")
        method = request.get("method", "GET")
        tag = request.get("tag", "")
        attribute = request.get("attribute", "")
        source = request.get("source", "")
        error = data.get("error", "")
        custom_fields = data.get("custom_fields", {})

        # handle errors
        if error:
            if error == "max depth reached":
                result["crawl_stats"]["max_depth_events"] += 1
            else:
                result["crawl_stats"]["other_errors"] += 1

            # still extract emails even from errored lines
            emails = custom_fields.get("email", []) or []
            for email in emails:
                if not email:
                    continue
                if any(p in email for p in placeholder_emails):
                    continue
                if email not in result["emails"]:
                    result["emails"].append(email)
                    result["key_findings"].append(
                        f"Email exposed during crawl: {email}"
                    )
            continue

        if not endpoint or endpoint in seen_urls:
            continue
        seen_urls.add(endpoint)

        # full URL decomposition
        try:
            parsed_url = urlparse(endpoint)
            query_params = parse_qs(parsed_url.query)
            port = parsed_url.port
            if port is None:
                port = 443 if parsed_url.scheme == "https" else 80
            path_segments = [
                s for s in parsed_url.path.split("/") if s
            ]
        except Exception:
            continue

        # classify by path segments — avoids substring false positives
        matched_categories = []
        for segment in path_segments:
            segment_lower = segment.lower()
            for category, patterns in categories.items():
                if segment_lower in patterns:
                    if category not in matched_categories:
                        matched_categories.append(category)

        url_info = {
            # full URL
            "url": endpoint,
            # decomposed
            "scheme": parsed_url.scheme,
            "host": parsed_url.hostname,
            "port": port,
            "path": parsed_url.path,
            "path_segments": path_segments,
            "query": parsed_url.query,
            "parameters": list(query_params.keys()),
            # context
            "method": method,
            "tag": tag,
            "attribute": attribute,
            "source": source,
            # classification
            "categories": matched_categories,
            "has_parameters": len(query_params) > 0,
        }

        result["endpoints"].append(url_info)

        # forms — tag==form or attribute==action only
        if tag == "form" or attribute == "action":
            result["forms"].append(url_info)
            result["crawl_stats"]["forms_found"] += 1
            params_str = f" params={url_info['parameters']}" if url_info["parameters"] else ""
            result["key_findings"].append(
                f"Form endpoint: {method} {endpoint}{params_str}"
            )

        # interesting endpoints with categories
        if matched_categories:
            result["interesting_endpoints"].append(url_info)
            category_str = ", ".join(matched_categories)
            params_note = f" [params: {', '.join(url_info['parameters'])}]" if url_info["parameters"] else ""
            result["key_findings"].append(
                f"Interesting [{category_str}]: {endpoint}{params_note}"
            )

    # update unique URL count
    result["crawl_stats"]["unique_urls"] = len(seen_urls)

    # deduplicate key_findings preserving order
    result["key_findings"] = list(dict.fromkeys(result["key_findings"]))

    # crawl completeness warning
    max_depth = result["crawl_stats"]["max_depth_events"]
    if max_depth > 0:
        result["key_findings"].insert(0,
            f"NOTE: crawl hit max depth {max_depth} times — surface may be incomplete, consider run_deep_crawl"
        )

    # summary header
    stats = result["crawl_stats"]
    summary = (
        f"Katana: {stats['unique_urls']} unique URLs | "
        f"{stats['forms_found']} forms | "
        f"{len(result['interesting_endpoints'])} interesting endpoints | "
        f"{len(result['emails'])} emails exposed"
    )
    result["key_findings"].insert(0, summary)

    return result