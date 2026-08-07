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
    