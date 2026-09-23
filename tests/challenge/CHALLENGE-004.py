# CHALLENGE-004: @patch from unittest.mock scored HIGH as a web route (bare-verb collision)
# Fixed: bare names removed from resource_boundary_decorators (Task 4c, commit 69203f8).
# Expected: no finding (bare @patch is never matched, even with --resource-boundary)
from unittest.mock import patch
import subprocess

@patch("__main__.subprocess.run")
def mock_handler(mock_run):
    subprocess.run("ls", shell=True)
