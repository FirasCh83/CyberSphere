from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ExploitationComplexity(str, Enum):
    LOW = "low"             #no special conditions, reliable
    MEDIUM = "medium"       #some conditions required
    HIGH = "high"           #Difficult to exploit, requires special conditions

class ValidationStatus(str, Enum):
    CONFIRMED = "confirmed"         # active validation passed
    PROBABLE = "probable"           # high RAG confidence, validation inconclusive
    UNCONFIRMED = "unconfirmed"     # RAG match only, no active validation run


@dataclass
class ConfirmedVulnerability:
    # identity
    cve_id: str
    name: str
    description: str

    # location
    target: str
    port: int
    service: str
    version: str

    # severity
    severity: Severity
    cvss_score: float
    exploitation_complexity: ExploitationComplexity

    # exploitation
    requires_auth: bool
    metasploit_module: str

    # Confidence
    status: ValidationStatus
    rag_score: float
    evidence_score: float
    semantic_score: float

    # validation evidence
    validation_output: str
    validation_method: str

    # context
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    notes: str = ""

    def is_exploitable (self) -> bool:
        """Quick check for exploitation agent routing"""
        return (
            self.status == ValidationStatus.CONFIRMED and
            self.exploitation_complexity in [ExploitationComplexity.LOW, ExploitationComplexity.MEDIUM]
            and bool(self.metasploit_module)
        )
    
    def priority_score(self) -> float:
        """Numeric priority for exploitation agent ordering"""
        severity_weight = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.8,
            Severity.MEDIUM: 0.5,
            Severity.LOW: 0.2,
            Severity.INFO: 0.0,
        }
        complexity_weight = {
            ExploitationComplexity.LOW: 1.0,
            ExploitationComplexity.MEDIUM: 0.6,
            ExploitationComplexity.HIGH: 0.2,
        }
        status_weight = {
            ValidationStatus.CONFIRMED: 1.0,
            ValidationStatus.PROBABLE: 0.7,
            ValidationStatus.UNCONFIRMED: 0.3,
        }

        return (
            severity_weight.get(self.severity, 0) * 0.4 +
            complexity_weight.get(self.exploitation_complexity, 0) * 0.3 +
            status_weight.get(self.status, 0) * 0.3
        )
    
    def to_agent_summary(self) -> str:
        """Compact summary for LLM context Used when passing findings to the next agent"""
        return (
            f"[{self.status.value.upper()}] {self.cve_id} "
            f"({self.severity.value}) "
            f"port {self.port}/{self.service} "
            f"v{self.version} "
            f"complexity={self.exploitation_complexity.value} "
            f"msf={self.metasploit_module or 'none'} "
            f"score={self.rag_score:.2f}"

        )
    def to_dict(self) -> dict:
        """Serializable dict for state storage and report generation."""
        return {
            "cve_id": self.cve_id,
            "name": self.name,
            "description": self.description,
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "version": self.version,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "exploitation_complexity": self.exploitation_complexity.value,
            "requires_auth": self.requires_auth,
            "metasploit_module": self.metasploit_module,
            "status": self.status.value,
            "rag_score": self.rag_score,
            "evidence_score": self.evidence_score,
            "semantic_score": self.semantic_score,
            "validation_output": self.validation_output,
            "validation_method": self.validation_method,
            "tags": self.tags,
            "references": self.references,
            "notes": self.notes,
            "priority_score": self.priority_score(),
            "is_exploitable": self.is_exploitable(),
        }


