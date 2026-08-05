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

    def summary(self) -> str:
        """Compact summary injected into each LLM reasoning cycle"""
        return f"""
TARGET: {self.target}
SCANS RUN: {", ".join(self.scans_run) or 'none yet'}
OPEN PORTS: {[p['port'] for p in self.open_ports] or 'unknown'}
SERVICES: {self.services or 'unknown'}
WEB SERVICES: {self.web_services or 'none found yet'}
TECHNOLOGIES: {self.technologies or 'none found yet'}
TLS ISSUES: {self.tls_issues or 'none found yet'}
MISSING HEADERS: {self.missing_headers or 'none found yet'}
KEY FINDINGS: {self.findings or 'none yet'}
"""
    