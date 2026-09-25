import json
import os
import time
import logging
from dotenv import load_dotenv
from openai import OpenAI
from openai import APIConnectionError, APITimeoutError, RateLimitError, InternalServerError

logger = logging.getLogger("recon_agent")


def _llm_create_with_retry(client, max_attempts: int = 4, **kwargs):
    """LLM call with exponential backoff — 'openrouter/free' is rate-limited."""
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            return client.chat.completions.create(**kwargs)
        except (RateLimitError, APIConnectionError, APITimeoutError,
                InternalServerError) as e:
            last_exc = e
            if attempt == max_attempts:
                break
            wait = min(2 ** attempt, 30)
            print(f"[ReconAgent] LLM attempt {attempt}/{max_attempts} "
                  f"({type(e).__name__}) — retrying in {wait}s")
            time.sleep(wait)
    print(f"[ReconAgent] LLM call failed after {max_attempts} attempts: {last_exc}")
    raise last_exc
from pydantic import BaseModel, Field
from tools.nmap.nmap import run_service_detection, run_os_detection, run_default_scripts, run_udp_scan, run_vulnerability_scan, run_full_port_scan
""" from tools.httpx.httpx import run_http_probe, run_http_tls_analysis, run_http_header_analysis """
from tools.whois.whois import run_whois_lookup
from tools.whatweb.whatweb import run_basic_fingerprint, run_aggressive_fingerprint, run_full_fingerprint
from tools.nuclei.nuclei import run_cve_scan, run_rce_scan, run_exposure_scan, run_misconfiguration_scan, run_default_login_scan, run_apache_scan, run_tomcat_scan, run_wordpress_scan, run_tomcat_scan 
from tools.katana.katana import run_basic_crawl, run_deep_crawl, run_js_crawl, run_form_discovery,run_passive_crawl 
from utilities.state import ReconState
from utilities.parser import parse_nmap_output, parse_whois_output, parse_httpx_output, parse_whatweb_output, parse_nuclei_output, parse_katana_output
from utilities import events
import json

load_dotenv()

# Central LLM config — override in .env. Defaults to the OpenRouter endpoint.
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://vyceai.com/v1")
LLM_MODEL = os.getenv("LLM_MODEL", "claude-sonnet-4-6")
client = OpenAI(
    base_url=LLM_BASE_URL,
    api_key=os.getenv("OPENROUTER_API_KEY"),
)

#(TODO) make sure that the agent follows each web finding and pass it to the whatweb tool for fingerprinting, and then pass the results to the next tool in the chain.

tools_nmap = [
    {
        "type": "function",
        "function": {
            "name": "run_service_detection",
            "description": (
                "Runs 'nmap -sV -Pn -T4' against the target. "
                "Scans the most common 1000 TCP ports, identifies open ports, running "
                "services and their exact versions (e.g. Apache 2.2.8, OpenSSH 4.7p1). "
                "Fast scan (~20-30s). "
                
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname e.g. '192.168.56.107' or 'example.com'."
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_default_scripts",
            "description": (
                "Runs 'nmap -sC -sV -Pn -T4' against the target. Executes Nmap's "
                "default NSE scripts on top of service detection — extracts extra "
                "info like anonymous FTP access, SMB details, SSL certificates, SSH "
                "host keys, HTTP page titles, and more. Use this"
                "when you want deeper info on what was found. Medium speed (~60-90s)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_vulnerability_scan",
            "description": (
                "Runs 'nmap -sV --script vuln -Pn -T4' against the target. Runs "
                "Nmap's vuln NSE scripts to check for known CVEs and misconfigurations "
                "— detects things like vsftpd backdoor, MS17-010 (EternalBlue), "
                "SSL POODLE, Heartbleed, SQL injection vectors, CSRF, XSS. "
                "Run this only if you want to check for known vulnerabilities after open ports and"
                "services are found. Slow scan (~5-8 min)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_os_detection",
            "description": (
                "Runs 'nmap -O -Pn -T4' against the target. Attempts to fingerprint "
                "the operating system based on TCP/IP stack behavior."
                "May return no result if insufficient closed ports exist. Fast (~10s)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_full_port_scan",
            "description": (
                "Runs 'nmap -p- -Pn -T4' against the target. Scans ALL 65535 TCP "
                "ports instead of just the default 1000. Use this only when "
                "run_service_detection found very few open ports and you suspect "
                "services are running on non-standard ports. Very slow (~10-20 min)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_udp_scan",
            "description": (
                "Runs 'nmap -sU -Pn -T3' against the target. Scans common UDP ports "
                "to find services like DNS (53), SNMP (161), TFTP (69), NTP (123). "
                "Only run this if UDP services are suspected or SNMP/DNS exposure is "
                "a concern. Very slow (~15-20 min)"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string"}
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
]

""" tools_httpx = [
    {
        "type": "function",
        "function": {
            "name": "run_http_probe",
            "description": (
                "Runs httpx with '-status-code -title -tech-detect -server "
                "-follow-redirects -json' against a URL. finds open HTTP ports (80, 8080, 8443, 8180 "
                "etc). Returns HTTP status code, page title, detected technologies "
                "(WordPress, Laravel, jQuery versions etc), server banner, and "
                "redirect chain. Fast (~5s). Target must include protocol: "
                "for example'http://192.168.56.107:80'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Full URL with protocol and port e.g. 'http://192.168.56.107:80' or 'https://example.com:443'."
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_http_tls_analysis",
            "description": (
                "Runs httpx with '-tls-grab -status-code -title -json' against an "
                "HTTPS URL. Extracts TLS certificate details (expiry date, issuer, "
                "SANs), TLS version (flags weak TLS 1.0/1.1/SSLv3), and cipher "
                "suites.Fast (~5s). Target must use https://."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "HTTPS URL with port e.g. 'https://192.168.56.107:443'."
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_http_header_analysis",
            "description": (
                "Runs httpx with '-status-code -server -header -json' against a URL. "
                "Collects all HTTP response headers to check for missing security "
                "headers (Strict-Transport-Security, Content-Security-Policy, "
                "X-Frame-Options, X-Content-Type-Options) and exposed server banners. "
                "Missing security headers are a common finding in small business "
                "audits. "
                "Fast (~5s)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Full URL with protocol and port e.g. 'http://192.168.56.107:80'."
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
] """

tools_whois = [
    {
        "type": "function",
        "function": {
            "name": "run_whois_lookup",
            "description": (
                "Performs a WHOIS lookup against a domain or public IP address. "
                "Collects passive registration intelligence including registrar, "
                "organization, registration date, expiration date, name servers, "
                "domain status, country, and abuse/contact information when available. "
                "Use this early during reconnaissance for internet-facing domains "
                "to understand ownership and infrastructure context. "
                "Does not scan the target and generates no network noise. "
                "Very fast (~2-5s). "
                "Do not use against private IP addresses (e.g. 192.168.x.x, "
                "10.x.x.x, 172.16-31.x.x) because WHOIS data will not be useful."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target domain or public IP address. "
                            "Examples: 'example.com' or '8.8.8.8'. "
                            "Avoid private IP addresses."
                        )
                    }
                },
                "required": [
                    "target"
                ],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
]

tools_whatweb = [
    {
        "type": "function",
        "function": {
            "name": "run_basic_fingerprint",
            "description": (
                "Performs a basic WhatWeb technology fingerprint against a web target. "
                "Fast, low-noise identification of web technologies, frameworks, "
                "servers, CMS platforms, and other application components. "
                "Use this as the default first step when a web service has been "
                "identified during reconnaissance. "
                "Generates relatively few HTTP requests and is suitable for "
                "initial web technology discovery. "
                "Returns structured JSON output from WhatWeb. "
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target web URL to fingerprint. "
                        )
                    }
                },
                "required": [
                    "target"
                ],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_aggressive_fingerprint",
            "description": (
                "Performs an aggressive WhatWeb technology fingerprint against "
                "a web target using aggression level 3. "
                "Provides deeper technology detection than the basic fingerprint "
                "and may identify additional plugins, frameworks, versions, "
                "and application components that basic detection misses. "
                "Use when basic fingerprinting produced useful web evidence but "
                "additional technology identification is justified. "
                "Generates more HTTP requests and network traffic than the basic "
                "fingerprint. "
                "Returns structured JSON output from WhatWeb. "
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target web URL to fingerprint. "
                        )
                    }
                },
                "required": [
                    "target"
                ],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_full_fingerprint",
            "description": (
                "Performs maximum-aggression WhatWeb technology fingerprinting "
                "against a web target using aggression level 4. "
                "Attempts the most comprehensive technology identification and "
                "can reveal deeper application, framework, CMS, server, and "
                "version information. "
                "Use only when deeper fingerprinting is warranted by previous "
                "reconnaissance evidence or when lower aggression levels were "
                "insufficient. "
                "Generates significantly more HTTP requests and network traffic "
                "and should not be the default reconnaissance action. "
                "Returns structured JSON output from WhatWeb. "
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target web URL to fingerprint. "
                        )
                    }
                },
                "required": [
                    "target"
                ],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
]


tools_nuclei = [
    {
        "type": "function",
        "function": {
            "name": "run_cve_scan",
            "description": (
                "Runs a Nuclei vulnerability scan focused on known CVE-based "
                "vulnerabilities against a web target. "
                "Uses CVE-tagged templates and limits results to critical, "
                "high, and medium severity findings. "
                "Use when reconnaissance has identified a reachable web "
                "service and you want to check for known vulnerabilities. "
                "This is a targeted vulnerability scan rather than a general "
                "technology discovery scan. "
                "Requires a complete HTTP or HTTPS URL including the correct "
                "port when the service is running on a non-standard port. "
                "Returns structured Nuclei JSONL findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Complete web service URL to scan. "
                            "Include the HTTP or HTTPS scheme and explicit port "
                            "when applicable. "
                            "Examples: "
                            "'http://192.168.56.107', "
                            "'http://192.168.56.107:8180', "
                            "'https://example.com:8443'."
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_rce_scan",
            "description": (
                "Runs a targeted Nuclei scan for Remote Code Execution (RCE) "
                "vulnerabilities using RCE-tagged templates. "
                "Results are limited to critical, high, and medium severity. "
                "Use when reconnaissance provides evidence that a web service "
                "or application may expose an RCE-related attack surface. "
                "This scan can generate more intrusive requests than basic "
                "technology fingerprinting. "
                "Requires a complete HTTP or HTTPS URL, including the correct "
                "port for non-standard web services. "
                "Returns structured Nuclei JSONL findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Complete web service URL. "
                            "Examples: "
                            "'http://192.168.56.107', "
                            "'http://192.168.56.107:8180', "
                            "'https://example.com:8443'."
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_exposure_scan",
            "description": (
                "Runs a Nuclei scan for exposed files, services, credentials, "
                "sensitive information, and other security exposures using "
                "exposure-tagged templates. "
                "Use when reconnaissance indicates a web service that may "
                "expose sensitive resources or configuration. "
                "Requires a complete HTTP or HTTPS URL, including the correct "
                "port for non-standard services. "
                "Returns structured Nuclei JSONL findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Complete web service URL including scheme and, "
                            "when necessary, port. "
                            "Examples: 'http://192.168.56.107' or "
                            "'http://192.168.56.107:8080'."
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_misconfiguration_scan",
            "description": (
                "Runs a Nuclei scan for web server and application "
                "misconfigurations using misconfiguration-tagged templates. "
                "Use to identify insecure configurations, exposed settings, "
                "and common deployment mistakes after a web service has been "
                "identified. "
                "Requires a complete HTTP or HTTPS URL and the correct port "
                "for non-standard web services. "
                "Returns structured Nuclei JSONL findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Complete HTTP or HTTPS service URL. "
                            "Examples: 'http://192.168.56.107' or "
                            "'https://192.168.56.107:8443'."
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_default_login_scan",
            "description": (
                "Runs Nuclei templates targeting known default credentials "
                "and default login configurations. "
                "Use when reconnaissance identifies a web application, "
                "administrative interface, appliance, framework, or service "
                "that may use vendor-default credentials. "
                "Requires a complete HTTP or HTTPS URL and the correct port. "
                "Returns structured Nuclei JSONL findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Complete web service URL including scheme and "
                            "explicit non-standard port when applicable."
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_apache_scan",
            "description": (
                "Runs Nuclei templates specifically associated with Apache "
                "web servers. "
                "Use when reconnaissance or WhatWeb identifies Apache as "
                "the underlying web server. "
                "This provides technology-specific vulnerability and "
                "misconfiguration checks rather than generic web scanning. "
                "Requires a complete HTTP or HTTPS URL and the correct port. "
                "Returns structured Nuclei JSONL findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Complete Apache web service URL. "
                            "Examples: 'http://192.168.56.107' or "
                            "'http://192.168.56.107:8080'."
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_tomcat_scan",
            "description": (
                "Runs Nuclei templates specifically associated with Apache "
                "Tomcat web applications and servers. "
                "Use when service detection or WhatWeb identifies Tomcat "
                "or the Coyote HTTP connector. "
                "Requires a complete HTTP or HTTPS URL for the discovered "
                "Tomcat service, including its non-standard port when present. "
                "Returns structured Nuclei JSONL findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Complete Tomcat service URL. "
                            "Examples: 'http://192.168.56.107:8180' or "
                            "'https://example.com:8443'."
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_wordpress_scan",
            "description": (
                "Runs Nuclei templates specifically associated with "
                "WordPress installations. "
                "Use when WhatWeb, HTTP responses, page content, or previous "
                "reconnaissance indicates that the target is running WordPress. "
                "This is a technology-specific scan and should not be used "
                "against services without WordPress evidence unless broader "
                "testing is explicitly required. "
                "Requires a complete HTTP or HTTPS URL and the correct port. "
                "Returns structured Nuclei JSONL findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Complete WordPress service URL. "
                            "Examples: 'http://192.168.56.107' or "
                            "'http://192.168.56.107:8080'."
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
]

tools_katana = [
    {
        "type": "function",
        "function": {
            "name": "run_basic_crawl",
            "description": (
                "Runs a standard Katana web crawl against the target using "
                "'katana -u TARGET -jsonl -silent'. Discovers URLs, links, "
                "paths, and other endpoints exposed through the application's "
                "crawlable content. Use this as the default web discovery "
                "capability after an HTTP/HTTPS service has been identified. "
                "Fast-to-medium scan depending on application size."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target HTTP/HTTPS URL to crawl"
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_deep_crawl",
            "description": (
                "Runs a deeper Katana crawl using "
                "'katana -u TARGET -jsonl -d 5 -silent'. "
                "Traverses the application up to depth 5 to discover "
                "nested pages and endpoints that a shallow crawl may miss. "
                "Use this when a basic crawl reveals a large or deeply "
                "structured web application, documentation portal, CMS, "
                "or many nested paths. More expensive than the basic crawl."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target HTTP/HTTPS URL to crawl deeply"
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_js_crawl",
            "description": (
                "Runs Katana with JavaScript crawling enabled using "
                "'katana -u TARGET -jsonl -jc -silent'. "
                "Analyzes JavaScript resources discovered during crawling "
                "to identify additional URLs and endpoints that may not "
                "appear in normal HTML links. Use this when the target "
                "uses JavaScript heavily, exposes many .js files, or when "
                "client-side endpoints need to be discovered."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target HTTP/HTTPS URL whose JavaScript "
                            "resources should be analyzed."
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_form_discovery",
            "description": (
                "Runs Katana's form discovery capability using "
                "'katana -u TARGET -jsonl -form -silent'. "
                "Identifies forms and input-related endpoints exposed "
                "by the application. Use this when the target contains "
                "login pages, search functionality, upload functionality, "
                "or other user-input surfaces that may require further "
                "security testing."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target HTTP/HTTPS URL to inspect for forms "
                            "and input surfaces."
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },

    {
        "type": "function",
        "function": {
            "name": "run_passive_crawl",
            "description": (
                "Runs Katana in passive mode using "
                "'katana -u TARGET -jsonl -passive -silent'. "
                "Performs passive URL discovery using available "
                "non-active sources rather than actively crawling the "
                "application. Use this when additional endpoint discovery "
                "is desired with reduced interaction, or when passive "
                "discovery can complement an active crawl."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target HTTP/HTTPS URL for passive "
                            "endpoint discovery."
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    },
]


tools = tools_nmap + tools_whois + tools_whatweb + tools_nuclei + tools_katana  # + tools_httpx




System_prompt = """You are an expert penetration tester performing reconnaissance on an authorized target.

You operate in a strict SEQUENTIAL reasoning loop:
1. Call ONE tool at a time
2. Wait for the result
3. Analyze the output carefully
4. Decide what to do next based on what you learned

RULES:
- NEVER call more than one tool at a time
- Each tool call must be justified by what you already know
- Start with the fastest, broadest scan first, then drill down
- Only run deeper/slower scans if earlier results justify it
- Stop when you have enough information for a useful pentest report

EVIDENCE DISCIPLINE (critical — you are a reconnaissance agent, not a vulnerability database):
- Report ONLY what the tools actually returned: open ports, detected service versions,
  banners, technologies, and misconfigurations.
- NEVER state a CVE identifier or a CVSS score from memory. Cite a CVE ONLY if it appears
  verbatim in a tool's output (e.g. a nuclei finding). If no tool reported a CVE, do not name one.
- Describe evidence, not conclusions. Say "vsftpd 2.3.4 banner observed on port 21", not
  "confirmed vsftpd backdoor CVE-XXXX-XXXX".
- Mark inference clearly: use "appears to run", "banner suggests", "possibly vulnerable" —
  never "confirmed", "critical exploitability", or a definitive verdict. You do not validate.
- CVE matching, severity, and confirmation are performed downstream by the vulnerability agent
  (RAG + live Metasploit validation). Your job is to hand off accurate observations, not verdicts.

After each result, reason out loud:
- What did I find?
- Does this change my plan?
- What is the single most valuable next scan, or should I stop?

When you have gathered sufficient information, stop calling tools and summarize your
OBSERVATIONS (versions, banners, misconfigurations) — without inventing CVE ids or verdicts."""


httpx_tools = {"run_http_probe", "run_http_tls_analysis", "run_http_header_analysis"}
whois_tools = {"run_whois_lookup"}
whatweb_tools = {"run_basic_fingerprint", "run_aggressive_fingerprint", "run_full_fingerprint"}
nuclei_tools = {
    "run_cve_scan", "run_rce_scan", "run_exposure_scan",
    "run_misconfiguration_scan", "run_default_login_scan",
    "run_apache_scan", "run_tomcat_scan", "run_wordpress_scan",
}
katana_tools = {
    "run_basic_crawl", "run_deep_crawl", "run_js_crawl",
    "run_form_discovery", "run_passive_crawl",
}

# UI streaming: map each tool to the shell-style command line + tool family
# shown in the conversation's command cards.
_RECON_CMD = {
    "run_service_detection":     "nmap -sV -Pn -T4 {t}",
    "run_default_scripts":       "nmap -sC -sV -Pn -T4 {t}",
    "run_vulnerability_scan":    "nmap -sV --script vuln -Pn -T4 {t}",
    "run_os_detection":          "nmap -O -Pn -T4 {t}",
    "run_full_port_scan":        "nmap -p- -Pn -T4 {t}",
    "run_udp_scan":              "nmap -sU -Pn -T3 {t}",
    "run_whois_lookup":          "whois {t}",
    "run_basic_fingerprint":     "whatweb {t}",
    "run_aggressive_fingerprint":"whatweb -a 3 {t}",
    "run_full_fingerprint":      "whatweb -a 4 {t}",
    "run_cve_scan":              "nuclei -u {t} -tags cve",
    "run_rce_scan":              "nuclei -u {t} -tags rce",
    "run_exposure_scan":         "nuclei -u {t} -tags exposure",
    "run_misconfiguration_scan": "nuclei -u {t} -tags misconfig",
    "run_default_login_scan":    "nuclei -u {t} -tags default-login",
    "run_apache_scan":           "nuclei -u {t} -tags apache",
    "run_tomcat_scan":           "nuclei -u {t} -tags tomcat",
    "run_wordpress_scan":        "nuclei -u {t} -tags wordpress",
    "run_basic_crawl":           "katana -u {t} -jsonl -silent",
    "run_deep_crawl":            "katana -u {t} -jsonl -d 5 -silent",
    "run_js_crawl":              "katana -u {t} -jsonl -jc -silent",
    "run_form_discovery":        "katana -u {t} -jsonl -form -silent",
    "run_passive_crawl":         "katana -u {t} -jsonl -passive -silent",
}


def _tool_family(name: str) -> str:
    if name in nuclei_tools:
        return "nuclei"
    if name in whatweb_tools:
        return "whatweb"
    if name in katana_tools:
        return "katana"
    if name in whois_tools:
        return "whois"
    return "nmap"


def _recon_cmd(name: str, target: str) -> str:
    return _RECON_CMD.get(name, name + " {t}").format(t=target)


def build_web_targets(state: ReconState) -> str:
    """
    Build comma-separated URL list from ports already discovered by nmap.
    Falls back to common ports if nmap hasn't run yet.
    """
    http_services = {
        "http", "https", "http-alt", "http-proxy",
        "tomcat", "ajp13", "webcache", "8180"
    }
    
    urls = []
    for port_info in state.open_ports:
        if isinstance(port_info, dict):
            port = port_info["port"]
            service = port_info.get("service", "")
        else:
            # tolerate plain int/str entries
            port = port_info
            service = ""
        try:
            port = int(port)
        except (ValueError, TypeError):
            continue

        if service in http_services or port in [80, 443, 8080, 8180, 8443, 8000, 8888]:
            scheme = "https" if port in [443, 8443] else "http"
            urls.append(f"{scheme}://{state.target}:{port}")
    
    return ",".join(urls) if urls else state.target



def call_tool(name, args, state: ReconState):
    target = args.get("target")

    web_tools = katana_tools | whatweb_tools
    if name in web_tools:
        target = build_web_targets(state)
    if name == "run_service_detection":
        return run_service_detection(target)
    elif name == "run_os_detection":
        return run_os_detection(target)
    elif name == "run_default_scripts":
        return run_default_scripts(target)
    elif name == "run_udp_scan":
        return run_udp_scan(target)
    elif name == "run_vulnerability_scan":
        return run_vulnerability_scan(target)
    elif name == "run_full_port_scan":
        return run_full_port_scan(target)
    elif name == "run_whois_lookup":
        return run_whois_lookup(target)
    elif name == "run_basic_fingerprint":
        return run_basic_fingerprint(target)
    elif name == "run_aggressive_fingerprint":
        return run_aggressive_fingerprint(target)
    elif name == "run_full_fingerprint":
        return run_full_fingerprint(target)
    elif name == "run_cve_scan":
        return run_cve_scan(target)
    elif name == "run_rce_scan":
        return run_rce_scan(target)
    elif name == "run_exposure_scan":
        return run_exposure_scan(target)
    elif name == "run_misconfiguration_scan":
        return run_misconfiguration_scan(target)
    elif name == "run_default_login_scan":
        return run_default_login_scan(target)
    elif name == "run_apache_scan":
        return run_apache_scan(target)
    elif name == "run_tomcat_scan":
        return run_tomcat_scan(target)
    elif name == "run_wordpress_scan":
        return run_wordpress_scan(target)
    elif name == "run_basic_crawl":
        return run_basic_crawl(target)
    elif name == "run_deep_crawl":
        return run_deep_crawl(target)
    elif name == "run_js_crawl":
        return run_js_crawl(target)
    elif name == "run_form_discovery":
        return run_form_discovery(target)
    elif name == "run_passive_crawl":
        return run_passive_crawl(target)
    else:
        raise ValueError(f"Unknown tool name: {name}")


# ---------------------------------------------------------------------------
# Completion gate — recon used to hand off the instant the LLM emitted no tool
# call, sometimes after just an nmap + a single nuclei pass. These helpers let
# the loop notice an obviously premature stop (web ports never fingerprinted,
# no vuln scan at all, coverage too thin) and nudge the agent to keep going.
# The gate only *questions* an early stop; the agent still decides what to run,
# and a nudge budget guarantees the loop always terminates.
# ---------------------------------------------------------------------------

# ports that usually speak HTTP(S) or an app protocol worth web-enumerating
_WEB_PORTS = {80, 81, 443, 591, 3000, 5000, 8000, 8008, 8009, 8080, 8081,
              8090, 8180, 8443, 8834, 8888, 8983, 9000, 9080, 9090, 9200, 9443}


def _port_num(entry):
    """Pull an int port out of an open_ports entry (dict | int | str)."""
    if isinstance(entry, dict):
        entry = entry.get("port")
    try:
        return int(str(entry).split("/")[0])
    except (ValueError, AttributeError, TypeError):
        return None


def _web_ports(state) -> list:
    """Open ports that look like web/app services, by number or service label."""
    web = set()
    for p in state.open_ports:
        n = _port_num(p)
        if n is None:
            continue
        svc = str(p.get("service", "")) if isinstance(p, dict) else ""
        svc = svc or str(state.services.get(n, ""))
        if n in _WEB_PORTS or any(k in svc.lower() for k in ("http", "ajp", "web")):
            web.add(n)
    return sorted(web)


def _coverage_gaps(state, tools_used: set) -> list:
    """Return human-readable coverage gaps if recon looks premature; else []."""
    gaps = []
    ran_nuclei  = bool(tools_used & nuclei_tools)
    ran_whatweb = bool(tools_used & whatweb_tools)
    ran_katana  = bool(tools_used & katana_tools)

    # 1. ports are open but nothing was ever scanned for vulnerabilities
    if state.open_ports and not ran_nuclei:
        gaps.append("no Nuclei vulnerability scan has run yet against any service")

    # 2. web ports discovered but never fingerprinted / crawled
    web = _web_ports(state)
    if web:
        ports_str = ", ".join(str(p) for p in web)
        if not ran_whatweb:
            gaps.append(f"open web port(s) {ports_str} have not been fingerprinted with WhatWeb")
        if not ran_katana:
            gaps.append(f"open web port(s) {ports_str} have not been crawled with Katana")

    # 3. suspiciously shallow: many ports open, very few recon actions taken
    if len(state.open_ports) >= 5 and len(tools_used) < 3:
        gaps.append(
            f"{len(state.open_ports)} ports are open but only {len(tools_used)} "
            f"recon action(s) have run — coverage is thin"
        )
    return gaps


def run_recon_agent(target: str) -> ReconState:
    """
    Runs the full recon ReAct loop, returns populated reconState for the vuln agent
    """
    state = ReconState(target=target)

    events.phase("Recon Agent", "reconnaissance")

    messages = [
    {"role": "system", "content": System_prompt},
    {"role": "user", "content": f"Given the presented set of tools, Perform a reconnaissance operation on this local authorised virtual machine:{target}, follow the tools descriptions and the rules provided in the system prompt. Only call one tool at a time, wait for the result, analyze it, and then decide on the next step. Stop when you have enough information for a useful pentest report."},
]

    tools_used = set()      # every tool name the agent has actually run
    nudges_used = 0         # completion-gate nudges spent
    steps = 0               # total loop iterations, runaway guard
    MAX_NUDGES = 2          # how many times the gate may refuse a premature stop
    MAX_STEPS = 40          # hard ceiling so the loop can never run away

    while True:
        if steps >= MAX_STEPS:
            print(f"[GATE] hit MAX_STEPS ({MAX_STEPS}) — forcing handoff.")
            events.thought(
                f"Reached the recon step ceiling ({MAX_STEPS} actions). "
                f"Handing off with what we have.",
                who="completion gate",
            )
            break
        steps += 1

        state_message = {
            "role": "user",
            "content": f"Current state:\n{state.summary()}"
        }

        context = (
            [messages[0]] + [messages[1]] + [state_message]+ messages[-4:]
        )

        completion = _llm_create_with_retry(
        client,
        model=LLM_MODEL,
        messages= context,
        tools=tools,
        )
        response_message = completion.choices[0].message
        messages.append(response_message)

        print(f"[DEBUG] content: {response_message.content}")
        print(f"[DEBUG] tool_calls count: {len(response_message.tool_calls) if response_message.tool_calls else 0}")    
        reasoning = (
            getattr(response_message, "reasoning", None)
            or response_message.content
            or None
        )

        if reasoning:
            print(f"Agent's reasoning: {reasoning}")
            events.thought(reasoning)


        if not response_message.tool_calls:
            gaps = _coverage_gaps(state, tools_used)
            if gaps and nudges_used < MAX_NUDGES:
                nudges_used += 1
                gap_text = "; ".join(gaps)
                print(f"[GATE] premature stop — nudging ({nudges_used}/{MAX_NUDGES}): {gap_text}")
                events.thought(
                    f"Holding the handoff — coverage still looks thin: {gap_text}. "
                    f"Continuing recon.",
                    who="completion gate",
                )
                messages.append({
                    "role": "user",
                    "content": (
                        "Before handing off to the vulnerability agent, this recon looks "
                        f"incomplete: {gap_text}. Use the appropriate tool(s) to close these "
                        "gaps now. If a gap genuinely cannot be addressed (for example a tool "
                        "is not applicable to this target), briefly say why, then you may stop."
                    ),
                })
                continue
            print("No tool calls detected. Stopping.")
            print(response_message.content)
            events.thought(response_message.content, who="summary")
            break
        tool_call= response_message.tool_calls[0]
        tool_name = tool_call.function.name
        tool_args = json.loads(tool_call.function.arguments)
        tools_used.add(tool_name)
        print(f"Running : {tool_name}")

        # stream the command card (spinner + live timer) while it runs
        web_tools = katana_tools | whatweb_tools
        resolved_target = (
            build_web_targets(state) if tool_name in web_tools
            else tool_args.get("target", target)
        )
        _cid = events.tool_start(_tool_family(tool_name), _recon_cmd(tool_name, resolved_target))
        _t0 = time.time()
        try:
            result = call_tool(tool_name, tool_args, state)
            events.tool_end(_cid, time.time() - _t0, result, ok=True)
        except Exception as _e:
            events.tool_end(_cid, time.time() - _t0, f"{type(_e).__name__}: {_e}", ok=False)
            raise
    


        if tool_name in httpx_tools:
            # httpx output — don't run nmap parser on it
            parsed = parse_httpx_output(result)
            state.web_services.extend(parsed["web_services"])
            state.technologies.extend(parsed["technologies"])
            state.tls_issues.extend(parsed["tls_issues"])
            state.missing_headers.extend(parsed["missing_headers"])
            state.findings.extend(parsed["key_findings"])

        elif tool_name in whois_tools:
            parsed = parse_whois_output(result)
            state.findings.extend(parsed["key_findings"])

        elif tool_name in whatweb_tools:
            parsed = parse_whatweb_output(result)
            state.technologies.extend(parsed["technologies"])
            state.findings.extend(parsed["key_findings"])

        elif tool_name in nuclei_tools:
            parsed = parse_nuclei_output(result)
            # evidence layer — full structured findings preserved
            state.nuclei_findings.extend(parsed["findings"])
            # agent layer — compact summaries only
            state.nuclei_summary.extend(parsed["key_findings"])
            # severity counts — accumulate across multiple nuclei scans
            state.nuclei_critical_count += parsed["critical_count"]
            state.nuclei_high_count += parsed["high_count"]
            state.nuclei_medium_count += parsed["medium_count"]
            # also push into general findings so agent sees them in state summary
            state.findings.extend([
                f for f in parsed["key_findings"]
                if not f.startswith("Nuclei:")  # avoid double-counting
            ])
    
        elif tool_name in katana_tools:
            parsed = parse_katana_output(result)
            state.katana_endpoints.extend(parsed["endpoints"])
            state.katana_forms.extend(parsed["forms"])
            state.katana_interesting.extend(parsed["interesting_endpoints"])
            state.katana_emails.extend(parsed["emails"])
            state.katana_stats = parsed["crawl_stats"]
            state.findings.extend(parsed["key_findings"])

        else:
            # nmap output — safe to parse as nmap
            parsed = parse_nmap_output(result)
            if parsed["open_ports"]:          # only update if parser found something
                state.open_ports = parsed["open_ports"]
                state.services = {p["port"]: p["service"] for p in parsed["open_ports"]}
            state.findings.extend(parsed["key_findings"])

        state.scans_run.append(tool_name)
    
        print(f"Result from {tool_name}:")
        print(result)

        messages.append(
            {"role": "tool",
            "tool_call_id": tool_call.id,
            "content": f"PARSED RESULTS:\n{parsed}\n\nSTATE:\n{state.summary()}"}
        )


    return state
    
    
if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else input("Enter the target IP address or hostname: ")
    final_state = run_recon_agent(target)
    print(final_state.summary())

    