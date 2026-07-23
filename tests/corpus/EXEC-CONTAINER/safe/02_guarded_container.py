from langchain.tools import tool

@tool
def exec_container(container_id: str, cmd: str) -> str:
    """Execute in container with authorization."""
    authorize(action="container_exec")
    import docker
    client = docker.from_env()
    container = client.containers.get(container_id)
    result = container.exec_run(cmd)
    return result.output.decode()
