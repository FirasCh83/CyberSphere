from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ReconState:
    target: str
    scans_run: List[str] = field(default_factory=list)
    open_ports: List[dict] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)

    #Httpx addition
    web_services: List[str] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    tls_issues: List[str] = field(default_factory=list)
    missing_headers: List[str] = field(default_factory=list)

    #nuclei
    nuclei_findings: List[Dict] = field(default_factory=list)
    nuclei_summary: List[str] = field(default_factory=list)
    nuclei_critical_count: int = 0
    nuclei_high_count: int = 0
    nuclei_medium_count: int = 0

    findings: List[str] = field(default_factory=list) #general findings across all tools

    def summary(self) -> str:
        """Compact summary injected into each LLM reasoning cycle"""
                # nuclei severity summary for agent context
        nuclei_line = "none yet"
        if self.nuclei_findings:
            nuclei_line = (
                f"{self.nuclei_critical_count} critical, "
                f"{self.nuclei_high_count} high, "
                f"{self.nuclei_medium_count} medium"
            )
        return f"""
TARGET: {self.target}
SCANS RUN: {", ".join(self.scans_run) or 'none yet'}
OPEN PORTS: {[p['port'] for p in self.open_ports] or 'unknown'}
SERVICES: {self.services or 'unknown'}
WEB SERVICES: {self.web_services or 'none found yet'}
TECHNOLOGIES: {self.technologies or 'none found yet'}
TLS ISSUES: {self.tls_issues or 'none found yet'}
MISSING HEADERS: {self.missing_headers or 'none found yet'}
NUCLEI FINDINGS: {nuclei_line}
NUCLEI DETAILS:
{chr(10).join(self.nuclei_summary) or '  none yet'}
KEY FINDINGS:
{chr(10).join(self.findings) or '  none yet'}
"""


from urllib.parse import urlparse, parse_qs
import json
from typing import Dict

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
    