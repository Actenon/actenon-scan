import docker

def internal_exec(container_id, cmd):
    client = docker.from_env()
    container = client.containers.get(container_id)
    return container.exec_run(cmd)
