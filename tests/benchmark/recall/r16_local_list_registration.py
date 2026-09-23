# r16: list-assigned-once tool registration — Agno Toolkit pattern.
# Real source: agno-agi/agno @ a4a7e319e9124a00c50f7815e4cea2bb3cae28e5
#   libs/agno/agno/tools/daytona.py:344  (DaytonaTools.create_file)
#   libs/agno/agno/tools/docker.py:192   (DockerTools.start_container)
# Pattern: Toolkit subclass __init__ builds a list literal of bound method
#          references and passes it to super().__init__(..., tools=tools).
#          The bound methods are agent-reachable via tool_list_param.
# Mechanism: CALLBACK_REGISTRATION (list-assigned-once shape).
# Expected: >=1 finding (tool_list_param signal, HIGH confidence)
#
# Conservative notes:
#  - Only list literals assigned exactly once are followed. Conditional
#    `tools.append(self.x)` (agno/agentql.py, agno/telegram.py) is dynamic
#    registration and is NOT resolved — those stay disclosed as unresolved
#    entry points.

from agno.tools import Toolkit


class DockerTools(Toolkit):
    def __init__(self):
        tools = [
            self.list_containers,
            self.start_container,
        ]
        super().__init__(name="docker_tools", tools=tools)

    def list_containers(self):
        return "[]"

    def start_container(self, container_id: str) -> str:
        import docker
        client = docker.from_env()
        container = client.containers.get(container_id)
        container.start()  # sink
        return f"Container {container_id} started"
