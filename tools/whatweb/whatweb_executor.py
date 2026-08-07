import docker
import docker.errors
from typing import Any, List

# TODO: Implement the WhatWeb scan json output parser and return a structured object instead of raw JSON.
def execute_whatweb_scan(args: List[str]) -> Any:
    image = "cybersphere/whatweb:latest"
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
            stderr= False,
            dns=["8.8.8.8", "1.1.1.1"],
            network_mode= "bridge",
            detach= False,
        )
        result = output.decode("utf-8", errors= "replace")
        return result
    except docker.errors.ContainerError as e:
        return e.stderr.decode("utf-8", errors="replace") if e.stderr else str(e)
    