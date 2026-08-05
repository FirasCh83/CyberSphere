import docker
import docker.errors
from typing import Any, List

def execute_nmap_scan(args: List[str]) -> Any:
    image = "instrumentisto/nmap:latest"
    try:
        client = docker.from_env()
    except docker.errors.DockerException as e:
        raise RuntimeError(f"Failed to connect to Docker: {e}")
    
    cap_add = ["NET_RAW"]
    try:
        output = client.containers.run(
            image=image,
            command=args,
            cap_add=cap_add if "-sU" or "-O" or "-sS" in args else None,
            remove=True,
            stdout=True,
            stderr=True,
            network_mode= "bridge",
            mem_limit="256m",
            cpu_period=100000,
            cpu_quota=50000,
            detach=False,
        )
        result = output.decode("utf-8", errors= "replace")
        return result
    except docker.errors.ContainerError as e:
        return e.stderr.decode("utf-8", errors="replace") if e.stderr else str(e)