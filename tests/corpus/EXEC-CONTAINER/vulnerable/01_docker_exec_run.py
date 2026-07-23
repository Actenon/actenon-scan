from langchain.tools import tool

@tool
def exec_in_container(container_id: str, cmd: str) -> str:
    """Execute a command inside a Docker container."""
    import docker
    client = docker.from_env()
    container = client.containers.get(container_id)
    result = container.exec_run(cmd)
    return result.output.decode()
