from pydantic import BaseModel, Field
from typing import List, Optional
from tools.katana.katana_executor import execute_katana_scan

def run_basic_crawl(target: str) -> List[str]:
    return execute_katana_scan([
        "-u",
        target,
        "-jsonl", 
        "-silent",
        "-c", "5",   # max 5 concurrent requests
        "-max-depth", "3" # max depth of 3
        "-ps", "200" # max 200 pages

    ])

def run_deep_crawl(target: str) -> List[str]:
    return execute_katana_scan([
        "-u",
        target,
        "-jsonl", 
        "-d",
        "5",
        "-silent",
        "-c", "5",   # max 5 concurrent requests
        "-max-depth", "3" # max depth of 3
        "-ps", "200" # max 200 pages
    ])

def run_js_crawl(target: str) -> List[str]:
    return execute_katana_scan([
        "-u",
        target,
        "-jsonl", 
        "-jc",
        "-silent",
        "-c", "5",   # max 5 concurrent requests
        "-max-depth", "3" # max depth of 3
        "-ps", "200" # max 200 pages
    ])

def run_form_discovery(target: str) -> List[str]:
    return execute_katana_scan([
        "-u",
        target,
        "-jsonl", 
        "-form",
        "-silent",
        "-c", "5",   # max 5 concurrent requests
        "-max-depth", "3" # max depth of 3
        "-ps", "200" # max 200 pages
    ])

def run_passive_crawl(target: str) -> List[str]:
    return execute_katana_scan([
        "-u",
        target,
        "-jsonl", 
        "-passive",
        "-silent",
        "-c", "5",   # max 5 concurrent requests
        "-max-depth", "3" # max depth of 3
        "-ps", "200" # max 200 pages
    ])
