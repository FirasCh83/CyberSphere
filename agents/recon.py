import json
import os
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field
from tools.nmap import run_service_detection, run_os_detection, run_default_scripts, run_udp_scan, run_vulnerability_scan, run_full_port_scan
from tools.httpx import run_http_probe, run_http_tls_analysis, run_http_header_analysis
from utilities.state import ReconState
from utilities.parser import parse_nmap_output
import json

load_dotenv()
client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY")
)



tools = [
    {
        "type": "function",
        "function": {
            "name": "run_service_detection",
            "description": "Identify services and versions running on the target using Nmap service detection.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target IP address or hostname."
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
            "name": "run_os_detection",
            "description": "Attempt to identify the operating system running on the target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string"
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
            "description": "Execute Nmap default NSE scripts against the target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string"
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
            "name": "run_udp_scan",
            "description": "Scan UDP ports on the target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string"
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
            "name": "run_vulnerability_scan",
            "description": "Run the Nmap vulnerability NSE scripts against the target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string"
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
            "name": "run_full_port_scan",
            "description": "Scan all 65535 TCP ports on the target.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string"
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
            "name": "run_http_probe",
            "description": (
                "Probe an HTTP/HTTPS service to collect basic web information, "
                "including HTTP status code, page title, detected technologies, "
                "server banner, and redirect information."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target URL including the protocol and port if known "
                            "(e.g. 'http://192.168.1.10:80' or "
                            "'https://example.com:443')."
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
            "name": "run_http_tls_analysis",
            "description": (
                "Gather TLS and HTTPS security information from a web service, "
                "including certificate details, TLS configuration, and security "
                "headers. Use only against HTTPS-enabled targets."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target HTTPS URL including the protocol and port if "
                            "known (e.g. 'https://192.168.1.10:443')."
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
            "name": "run_http_header_analysis",
            "description": (
                "Collect HTTP response headers from a web service, including "
                "server banners, cookies, and security-related headers for "
                "reconnaissance."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": (
                            "Target URL including the protocol and port if known "
                            "(e.g. 'http://192.168.1.10:8080')."
                        )
                    }
                },
                "required": ["target"],
                "additionalProperties": False
            },
            "strict": True,
        },
    }
]

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
    elif name == "run_http_probe":
        return run_http_probe(target)
    elif name == "run_http_tls_analysis":
        return run_http_tls_analysis(target)
    elif name == "run_http_header_analysis":
        return run_http_header_analysis(target)
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
    model= "openrouter/free",
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

    parsed = parse_nmap_output(result)

    state.scans_run.append(tool_name)
    state.open_ports = parsed["open_ports"] or state.open_ports
    state.services = {p["port"]: p["service"] for p in parsed["open_ports"] or state.services}
    state.findings.extend(parsed["key_findings"])
    
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

    