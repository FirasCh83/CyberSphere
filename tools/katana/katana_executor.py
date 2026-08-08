import docker
import docker.errors
from typing import Any, List

def execute_katana_scan(args: List[str]) -> Any:
    image= "projectdiscovery/katana:v1.6.1"
    try:
        client = docker.from_env()
    except docker.errors.DockerException as e:
        raise RuntimeError(f"Failed to connect to Docker: {e}")
    
    try:
        output = client.containers.run(
            image= image,
            command= args,
            remove= True,
            stdout= True,
            stderr=False,
            network_mode= "bridge",
            dns= ["8.8.8.8", "1.1.1.1"],
            detach= False,
        )
        result = output.decode("utf-8", errors= "replace")
        return result
    except docker.errors.ContainerError as e:
        return e.stderr.decode("utf-8", errors="replace") if e.stderr else str(e)