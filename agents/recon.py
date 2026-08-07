import json
import os
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field
from tools.nmap.nmap import run_service_detection, run_os_detection, run_default_scripts, run_udp_scan, run_vulnerability_scan, run_full_port_scan
""" from tools.httpx.httpx import run_http_probe, run_http_tls_analysis, run_http_header_analysis """
from tools.whois.whois import run_whois_lookup
from utilities.state import ReconState
from utilities.parser import parse_nmap_output, parse_whois_output, parse_httpx_output
import json

load_dotenv()
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY")
)



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

tools = tools_nmap + tools_whois

target = input("Enter the target IP address or hostname: ")

state = ReconState(target=target)

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

After each result, reason out loud:
- What did I find?
- Does this change my plan?
- What is the single most valuable next scan, or should I stop?

When you have gathered sufficient information, stop calling tools and summarize your findings."""

messages = [
    {"role": "system", "content": System_prompt},
    {"role": "user", "content": f"Please perform reconnaissance on the target: {target}."}
]



def call_tool(name, target):
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
    else:
        raise ValueError(f"Unknown tool name: {name}")
    
while True:
    state_message = {
        "role": "user",
        "content": f"Current state:\n{state.summary()}"
    }

    context = (
        [messages[0]] + [messages[1]] + [state_message]+ messages[-4:]
    )

    completion = client.chat.completions.create(
    model= "laguna-s-2.1:free",
    messages= context,
    tools=tools,
    )
    response_message = completion.choices[0].message
    messages.append(response_message)

    print(f"[DEBUG] content: {response_message.content}")
    print(f"[DEBUG] tool_calls count: {len(response_message.tool_calls) if response_message.tool_calls else 0}")    

    if response_message.content:
        print("Agent's reasoning:")
        print(response_message.content)
    

    if not response_message.tool_calls:
        print("No tool calls detected. Stopping.")
        print(response_message.content)
        break
    tool_call= response_message.tool_calls[0]
    tool_name = tool_call.function.name

    print(f"Running : {tool_name}")
    result = call_tool(tool_name, target)

    httpx_tools = {"run_http_probe", "run_http_tls_analysis", "run_http_header_analysis"}
    whois_tools = {"run_whois_lookup"}
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

    if not response_message.content:
        print("No reasoning provided. Stopping.")
        break
    
    
print(completion)

    