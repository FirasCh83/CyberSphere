from pydantic import BaseModel, Field
from typing import List, Optional
from tools.nmap.nmap_executor import execute_nmap_scan

def run_service_detection(target: str) -> List[str]:
    return execute_nmap_scan(["-sV", "-Pn", "-T4", target])

def run_os_detection(target: str) -> List[str]:
    return execute_nmap_scan(["-O", "-Pn", "-T4", target])

def run_default_scripts(target: str) -> List[str]:
    return execute_nmap_scan(["-sC", "-sV", "-Pn", "-T4", target])

def run_udp_scan(target: str) -> List[str]:
    return execute_nmap_scan(["-sU", "-Pn", "-T3", target])

def run_vulnerability_scan(target: str) -> List[str]:
    return execute_nmap_scan(["-sV", "--script", "vuln", "-Pn", "-T4", target])

def run_full_port_scan(target: str) -> List[str]:
    return execute_nmap_scan(["-p-", "-Pn", "-T4", target])


