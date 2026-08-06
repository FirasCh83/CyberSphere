from pydantic import BaseModel, Field
from typing import List, Optional
from tools.httpx.httpx_executor import execute_httpx_scan

def run_http_probe(target: str) -> List[str]:
    """
    Basic HTTP discovery:
    - Check alive web services
    - Get status code
    - Get title
    - Detect technologies"""
"""     return execute_httpx_scan([
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
        "-follow-redirects",
        target
    
    ]) """

def run_http_tls_analysis(target: str) -> List[str]:
    """
    HTTP/TLS information gathering:
    - Certificates
    - TLS details
    - Security headers
    """
"""     return execute_httpx_scan([
        "-tls-grab",
        "-status-code",
        "-title",
        target
    ]) """

def run_http_header_analysis(target: str) -> List[str]:
    """
    Collect HTTP headers:
    - Server banners
    - Cookies*
    - Security headers
    """
"""     return execute_httpx_scan([
        "-status-code",
        "-server",
        "-header",
        target
    ])
 """
