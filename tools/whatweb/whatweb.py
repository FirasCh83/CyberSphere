from pydantic import BaseModel, Field
from typing import List, Optional
from tools.whatweb.whatweb_executor import execute_whatweb_scan

def run_basic_fingerprint(target: str) -> List[str]:
    """
    Basic Whatweb technology fingerprinting.
    Fast identification of web technologies
    """
    urls = [u.strip() for u in target.split(",") if u.strip()]
    return execute_whatweb_scan(
        [
            "--log-json=-",
            "--quiet",
            ] + urls)
        

def run_aggressive_fingerprint(target: str) -> List[str]:
    """
    Aggressive Whatweb scan.
    Performs deeper technology detection.
    """
    urls = [u.strip() for u in target.split(",") if u.strip()]
    return execute_whatweb_scan(
        [
            "--log-json=-",
            "-a",
            "3",
            "--quiet",
            ] + urls)
        

def run_full_fingerprint(target: str) -> List[str]:
    """
    Maximum aggression fingerprinting.
    Use carefully because it generates more requests.
    """
    urls = [u.strip() for u in target.split(",") if u.strip()]
    return execute_whatweb_scan(
        [
            "--log-json=-",
            "-a",
            "4",
            "--quiet",
            ] + urls)

            #todo: add more functions for different levels of fingerprinting if needed
        