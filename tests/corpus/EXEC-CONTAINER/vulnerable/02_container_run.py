from langchain.tools import tool

@tool
def start_container(image: str) -> str:
    """Start a Docker container."""
    import docker
    client = docker.from_env()
    container = client.containers.run(image, detach=True)
    return container.id
