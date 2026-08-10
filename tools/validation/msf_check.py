import docker
import docker.errors
import json
from typing import Dict

def run_msf_check(
        target: str,
        port: int,
        msf_module: str,
) -> Dict:
    """
    Runs Metasploit's check() command against target.
    Returns structured result with vulnreable/safe/error status.
    """
    result = {
        "target": target,
        "port": port,
        "module": msf_module,
        "status": "unknown",
        "output": "",
        "error": "",
    }

    if not msf_module:
        result["status"] = "unsupported"
        result["error"] = "No Metasploit module available for this CVE."
        return result
    
    # Build msfconsole resource script, -x runs commands directly, -q suppresses banner
    msf_commands = (
        f"use {msf_module};"
        f"set RHOSTS {target};"
        f"set RPORT {port};"
        f"set ConnectTimeout 5;"
        f"check;"
        f"exit -y"
    )

    try:
        client = docker.from_env()
    except docker.errors.DockerException as e:
        result["status"] = "error"
        result["error"] = f"Docker error: {str(e)}"
        return result
    
    try:
        output = client.containers.run(
            image="metasploitframework/metasploit-framework:latest",
            command=["./msfconsole", "-q", "-x", msf_commands],
            working_dir="/usr/src/metasploit-framework",
            remove=True,
            stderr=True,
            stdout=True,
            network_mode="bridge",
            dns=["8.8.8.8", "1.1.1.1"],
            mem_limit="512m",
            detach=False,
        )
        raw = output.decode("utf-8", errors="replace")
        result["output"] = raw
        result["status"] = _parse_msf_check_output(raw)

    except docker.errors.ContainerError as e:
        stderr = e.stderr.decode("utf-8", errors="replace") if e.stderr else ""
        result["status"] = "error"
        result["error"] = stderr
    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)

    return result

def _parse_msf_check_output(output: str) -> str:
    """
    Parse msfconsole check output into clean status.
    """

    output_lower = output.lower()
    if "appears to be vulnerable" in output_lower:
        return "vulnerable"
    elif "target is not exploitable" in output_lower:
        return "safe"
    elif "does not support check" in output_lower:
        return "unsupported"
    elif "unreachable" in output_lower or "refused" in output_lower:
        return "unreachable"
    elif "error" in output_lower:
        return "error"
    else:
        return "unknown"