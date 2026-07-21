"""Vulnerable fixture: subprocess kubectl apply from an agent tool."""

import subprocess

from crewai import Agent, Task, Tool


@Tool("Deploy Application", "Deploys the application to the cluster")
def deploy_app(manifest_path: str, namespace: str = "default") -> str:
    """Deploy via kubectl."""
    subprocess.run(["kubectl", "apply", "-f", manifest_path, "-n", namespace], check=True)
    return "deployed"
