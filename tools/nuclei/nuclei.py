from pydantic import BaseModel, Field
from typing import List, Optional
from tools.nuclei.nuclei_executor import execute_nuclei_scan

def run_cve_scan(target: str) -> List[str]:
    return execute_nuclei_scan([
        "-u",
        target,
        "-tags",
        "cve",
        "-severity",
        "critical,high,medium"
    ])

def run_rce_scan(target: str) -> List[str]:
    return execute_nuclei_scan([
        "-u",
        target,
        "-tags",
        "rce",
        "-severity",
        "critical,high,medium"
    ])

def run_exposure_scan(target: str) -> List[str]:
    return execute_nuclei_scan([
        "-u",
        target,
        "-tags",
        "exposure",
    ])

def run_misconfiguration_scan(target: str) -> List[str]:
    return execute_nuclei_scan([
        "-u",
        target,
        "-tags",
        "misconfig",
    ])

def run_default_login_scan(target: str) -> List[str]:
    return execute_nuclei_scan([
        "-u",
        target,
        "-tags",
        "default-login"
    ])

def run_apache_scan(target: str) -> List[str]:
    return execute_nuclei_scan([
        "-u",
        target,
        "-tags",
        "apache"
    ])

def run_tomcat_scan(target: str) -> List[str]:
    return execute_nuclei_scan([
        "-u",
        target,
        "-tags",
        "tomcat"
    ])

def run_wordpress_scan(target: str) -> List[str]:
    return execute_nuclei_scan([
        "-u",
        target,
        "-tags",
        "wordpress"
    ])

def run_tomcat_scan(target: str) -> List[str]:
    return execute_nuclei_scan([
        "-u",
        target,
        "-tags",
        "tomcat",
    ])