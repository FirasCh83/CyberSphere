import json
import os
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field

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
    }
]
