from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ReconState:
    target: str
    scans_run: List[str] = field(default_factory=list)
    open_ports: List[dict] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)
    os_guess: str = ""

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

    #katana fields
    katana_endpoints: List[Dict] = field(default_factory=list)
    katana_forms: List[Dict] = field(default_factory=list)
    katana_interesting: List[Dict] = field(default_factory=list)
    katana_emails: List[str] = field(default_factory=list)
    katana_stats: Dict = field(default_factory=dict)

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
        crawl_complete = "not run yet"
        if self.katana_stats:
            max_depth = self.katana_stats.get("max_depth_events", 0)
            crawl_complete = (
                "YES" if not max_depth
                else f"NO - hit depth limit {max_depth} times"
            )
        return f"""
TARGET: {self.target}
SCANS RUN: {', '.join(self.scans_run) or 'none yet'}

NETWORK:
  Open ports: {[p['port'] for p in self.open_ports] or 'unknown'}
  Services: {self.services or 'unknown'}

WEB:
  Services: {self.web_services or 'none found yet'}
  Technologies: {self.technologies or 'unknown'}
  TLS issues: {self.tls_issues or 'none'}
  Missing headers: {self.missing_headers or 'none'}

CRAWL:
  Unique URLs: {len(self.katana_endpoints)}
  Forms: {len(self.katana_forms)}
  Interesting paths: {[e['url'] for e in self.katana_interesting[:5]] or 'none'}
  Emails exposed: {self.katana_emails or 'none'}
  Crawl complete: {crawl_complete}

NUCLEI:
  Findings: {nuclei_line}
  Details:
{chr(10).join('  ' + f for f in self.nuclei_summary) or '  none yet'}

KEY FINDINGS:
{chr(10).join('  ' + f for f in self.findings) or '  none yet'}
"""

    