from pydantic import BaseModel, Field
from typing import List, Optional
from tools.katana.katana_executor import execute_katana_scan

def run_basic_crawl(target: str) -> List[str]:
    return execute_katana_scan([
        "-u",
        target,
        "-jsonl", 
        "-silent"
    ])

def run_deep_crawl(target: str) -> List[str]:
    return execute_katana_scan([
        "-u",
        target,
        "-jsonl", 
        "-d",
        "5",
        "-silent"
    ])

def run_js_crawl(target: str) -> List[str]:
    return execute_katana_scan([
        "-u",
        target,
        "-jsonl", 
        "-jc",
        "-silent"
    ])

def run_form_discovery(target: str) -> List[str]:
    return execute_katana_scan([
        "-u",
        target,
        "-jsonl", 
        "-form",
        "-silent"
    ])

def run_passive_crawl(target: str) -> List[str]:
    return execute_katana_scan([
        "-u",
        target,
        "-jsonl", 
        "-passive",
        "-silent"
    ])
