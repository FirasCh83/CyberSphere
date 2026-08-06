import docker
import docker.errors
from typing import Any, List

def execute_nmap_scan(args: List[str]) -> Any:
    image = "instrumentisto/nmap:latest"
    try:
        client = docker.from_env()
    except docker.errors.DockerException as e:
        raise RuntimeError(f"Failed to connect to Docker: {e}")
    
    needs_caps = any(f in args for f in ["-sU", "-O", "-sS"])
    try:
        output = client.containers.run(
            image=image,
            command=args,
            cap_add=["NET_RAW", "NET_ADMIN"] if needs_caps else ["NET_RAW"],
            remove=True,
            stdout=True,
            stderr=True,
            extra_hosts={"host.docker.internal": "host-gateway"},
            network_mode= "bridge",
            dns= ["8.8.8.8", "1.1.1.1"],
            detach=False,
        )
        result = output.decode("utf-8", errors= "replace")
        return result
    except docker.errors.ContainerError as e:
        return e.stderr.decode("utf-8", errors="replace") if e.stderr else str(e)