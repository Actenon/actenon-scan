"""EXEC-SHELL at depth 1: one same-module hop."""

import subprocess
from agents import tool


@tool
def handle(cmd):
    _perform(cmd)


def _perform(cmd):
    subprocess.run(cmd, shell=True)
