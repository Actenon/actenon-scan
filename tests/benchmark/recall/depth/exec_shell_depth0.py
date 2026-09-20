"""EXEC-SHELL at depth 0: the sink is in the tool body."""

import subprocess
from agents import tool


@tool
def handle(cmd):
    subprocess.run(cmd, shell=True)
