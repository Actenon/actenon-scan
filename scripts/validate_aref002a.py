"""Run the immutable amendment validator without rewriting its M0 preservation seal.

AREF-002A records the failed M0's production/test hashes as historical evidence.
The unchanged validator must therefore run against that exact Git snapshot.
Current-runtime conformance is a separate mandatory pytest gate; passing this
script alone does not establish conformance of repaired production records.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
import zipfile


def main() -> int:
    # Fail immediately if the required verifier is absent. Never skip or fall back.
    import jsonschema  # noqa: F401
    import referencing  # noqa: F401

    root = Path(__file__).resolve().parents[1]
    amendment = root / "specs" / "AREF-002A"
    preservation = json.loads((amendment / "input_preservation.json").read_text())
    m0 = "a93b013383ce773b10708d3f30b2a1660e141527"
    if preservation["m0_commit"] != m0:
        raise ValueError("amendment preservation context is not the reviewed M0")
    # Using a snapshot must not hide any modification to the frozen architecture.
    for path, expected in preservation["files"].items():
        if path.startswith(("specs/AREF-001/", "specs/AREF-002/")):
            if hashlib.sha256((root / path).read_bytes()).hexdigest() != expected:
                raise ValueError("frozen architecture changed: " + path)
    archive = subprocess.run(["git", "archive", "--format=zip", m0], cwd=root,
                             check=True, capture_output=True).stdout
    with tempfile.TemporaryDirectory(prefix="aref002a-preservation-") as directory:
        snapshot = Path(directory)
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            for member in zipped.namelist():
                path = PurePosixPath(member)
                if path.is_absolute() or ".." in path.parts:
                    raise ValueError("unsafe archive path")
            zipped.extractall(snapshot)
        shutil.copytree(amendment, snapshot / "specs" / "AREF-002A")
        print("Normative preservation context: " + m0, flush=True)
        for spec in ("AREF-002", "AREF-002A"):
            result = subprocess.run([sys.executable, "-B", "specs/" + spec + "/validate.py"],
                                    cwd=snapshot)
            if result.returncode:
                return result.returncode
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ImportError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print("FATAL: required architecture verifier failed: " + str(error), file=sys.stderr)
        raise SystemExit(2)
