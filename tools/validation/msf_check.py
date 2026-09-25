import docker
import docker.errors
import json
from typing import Dict

MSF_IMAGE = "metasploitframework/metasploit-framework:latest"


def run_msf_check(
        target: str,
        port: int,
        msf_module: str,
) -> Dict:
    """
    Runs Metasploit's check() command against target.
    Returns structured result with vulnerable/safe/unsupported/error status.
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
        result["status"] = "no_module"
        result["error"] = "No Metasploit module available for this CVE."
        return result

    # Build msfconsole resource script — -x runs commands directly, -q suppresses banner
    msf_commands = (
        f"use {msf_module};\n"
        f"set RHOSTS {target};\n"
        f"set RPORT {port};\n"
        f"set ConnectTimeout 5;\n"
        f"check;\n"
        f"exit -y"
    )

    try:
        client = docker.from_env()
    except docker.errors.DockerException as e:
        result["status"] = "error"
        result["error"] = f"Docker error: {e}"
        return result

    try:
        output = client.containers.run(
            image=MSF_IMAGE,
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
        result["error"] = f"{type(e).__name__}: {e}"

    return result


def _parse_msf_check_output(output: str) -> str:
    """
    Parse msfconsole check output into clean status.
    """
    output_lower = output.lower()
    # Module never loaded — msfconsole couldn't resolve the name (usually a
    # hallucinated / non-existent module). Distinct from "safe": we learned
    # nothing about the target, so callers must NOT treat this as validated.
    if "failed to load module" in output_lower or "no results from search" in output_lower:
        return "invalid_module"
    if "appears to be vulnerable" in output_lower:
        return "vulnerable"
    elif "target is not exploitable" in output_lower:
        return "safe"
    elif "does not support check" in output_lower or "unknown command: check" in output_lower:
        return "unsupported"
    elif "unreachable" in output_lower or "refused" in output_lower:
        return "unreachable"
    elif "error" in output_lower:
        return "error"
    else:
        return "unknown"
