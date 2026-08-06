from pydantic import BaseModel, Field
from typing import List, Optional
from tools.whois.whois_executor import execute_whois_scan

def run_whois_lookup(target: str) -> List[str]:
    """
    Perform a WHOIS lookup against a domain or a public IP.
    
    Returns ownership and registration intelligence:
    - Registrar
    - Organization
    - Registration dates
    - Expiration dates
    - Name servers
    - Registry status
    - Abuse contracts
    """
    return execute_whois_scan([
        target
    ])
