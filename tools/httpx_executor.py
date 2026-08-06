import docker
import docker.errors
from typing import Any, List

def execute_httpx_scan(args: List[str]) -> Any:
    image = "projectdiscovery/httpx:latest"
    try:
        client = docker.from_env()
    except docker.errors.DockerException as e:
        raise RuntimeError(f"Failed to connect to Docker: {e}")
    
    try:
        output = client.containers.run(
            image=image,
            command=args,
            remove=True,
            stdout=True,
            stderr=True,
            extra_hosts={"host.docker.internal": "host-gateway"},
            network_mode= "bridge",
            dns= ["8.8.8.8", "1.1.1.1"],
            volumes= {
                "httpx-cache": {
                    "bind": "/root/.dit",
                    "mode": "rw"
                }
            },
            detach=False,
        )
        result = output.decode("utf-8", errors= "replace")
        return result
    except docker.errors.ContainerError as e:
        return e.stderr.decode("utf-8", errors="replace") if e.stderr else str(e)