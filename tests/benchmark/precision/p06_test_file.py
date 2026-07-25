# p06: tests/test_*.py with shutil.rmtree — must produce 0 findings
# (test files are excluded by default)
import shutil
import os
import tempfile

def test_cleanup():
    d = tempfile.mkdtemp()
    try:
        assert os.path.isdir(d)
    finally:
        shutil.rmtree(d)
