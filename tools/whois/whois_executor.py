import docker
import docker.errors
from typing import Any, List

def execute_whois_scan(args: List[str]) -> Any:
    image = "cybersphere-whois:latest"
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
            stderr= True,
            detach= False,
        )
        result = output.decode("utf-8", errors= "replace")
        return result
    except docker.errors.ContainerError as e:
        return e.stderr.decode("utf-8", errors="replace") if e.stderr else str(e)