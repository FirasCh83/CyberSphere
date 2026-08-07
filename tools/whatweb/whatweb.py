from pydantic import BaseModel, Field
from typing import List, Optional
from tools.whatweb.whatweb_executor import execute_whatweb_scan

def run_basic_fingerprint(target: str) -> List[str]:
    """
    Basic Whatweb technology fingerprinting.
    Fast identification of web technologies
    """
    return execute_whatweb_scan(
        [
            "--log-json=-",
            "--quiet",
            target
        ]
    )

def run_aggressive_fingerprint(target: str) -> List[str]:
    """
    Aggressive Whatweb scan.
    Performs deeper technology detection.
    """
    return execute_whatweb_scan(
        [
            "--log-json=-",
            "-a",
            "3",
            "--quiet",
            target
        ]
    )

def run_full_fingerprint(target: str) -> List[str]:
    """
    Maximum aggression fingerprinting.
    Use carefully because it generates more requests.
    """
    return execute_whatweb_scan(
        [
            "--log-json=-",
            "-a",
            "4",
            "--quiet",
            target
        ]
    )