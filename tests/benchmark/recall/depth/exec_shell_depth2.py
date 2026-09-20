"""EXEC-SHELL at depth 2: two same-module hops. EXPECTED MISS.

Following is depth-1 and non-transitive. The scan reports no finding and
discloses the unfollowed call from _relay() onward.
"""

import subprocess
from agents import tool


@tool
def handle(cmd):
    _relay(cmd)


def _relay(cmd):
    _perform(cmd)


def _perform(cmd):
    subprocess.run(cmd, shell=True)
