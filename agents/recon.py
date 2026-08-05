import json
import os
from dotenv import load_dotenv
from openai import OpenAI
from pydantic import BaseModel, Field
from tools.nmap import run_service_detection, run_os_detection, run_default_scripts, run_udp_scan, run_vulnerability_scan, run_full_port_scan

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

target = input("Enter the target IP address or hostname: ")

System_prompt = "You are a reconnaissance agent in a fully authenticated penetration testing envirement,use the tools provided in order to gather the most amout of information so the penetration test proceeds"

messages = [
    {"role": "system", "content": System_prompt},
    {"role": "user", "content": f"Please perform reconnaissance on the target: {target}."}
]

completion = client.chat.completions.create(
    model= "openrouter/free",
    messages= messages,
    tools=tools,
)

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
    else:
        raise ValueError(f"Unknown tool name: {name}")
    
for tool_call in completion.choices[0].message.tool_calls:
    tool_name = tool_call.function.name
    messages.append(completion.choices[0].message)

    result = call_tool(tool_name, target)
    messages.append(
        {"role": "tool", "tool_call_id": tool_call.id, "content": json.dumps(result)}
    )    

#class ToolResponse(BaseModel):
 #   tool_name: str = Field(..., description="The name of the tool that was called.")
 #   target: str = Field(..., description="The target IP address or hostname.")
  #  output: str = Field(..., description="The output from the tool execution.")


completion_2= client.beta.chat.completions.parse(
    model= "openrouter/free",
    messages= messages,
    tools= tools,
)

final_response = completion_2.choices[0].message.parsed
print(final_response)

    