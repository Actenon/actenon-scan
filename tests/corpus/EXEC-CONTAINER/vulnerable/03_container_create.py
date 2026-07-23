from crewai import Tool

@Tool("Container", "Creates a container")
def create_container(image: str) -> str:
    """Create a Docker container."""
    import docker
    client = docker.from_env()
    container = client.containers.create(image)
    return container.id
