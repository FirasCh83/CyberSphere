from dataclasses import dataclass, field
from typing import List, Dict

@dataclass
class ReconState:
    target: str
    scans_run: List[str] = field(default_factory=list)
    open_ports: List[dict] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)

    def summary(self) -> str:
        """Compact summary injected into each LLM reasoning cycle"""
        return f"""
TARGET: {self.target}
SCANS RUN: {", ".join(self.scans_run) or 'none yet'}
OPEN PORTS: {[p['port'] for p in self.open_ports] or 'unknown'}
SERVICES: {self.services or 'unknown'}
KEY FINDINGS: {self.findings or 'none yet'}
"""
    