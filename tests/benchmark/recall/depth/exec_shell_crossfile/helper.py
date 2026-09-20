"""The sink, one module away from the entry point."""

import subprocess


def _perform(cmd):
    subprocess.run(cmd, shell=True)
