"""Access to the frozen AREF-002 artefacts the M0 model is checked against."""

from __future__ import annotations

import json
from pathlib import Path

SPEC_DIR = Path(__file__).resolve().parents[2] / "specs" / "AREF-002"
EXAMPLES = SPEC_DIR / "examples"


def load_json(name: str) -> dict:
    return json.loads((SPEC_DIR / name).read_text(encoding="utf-8"))


def manifest() -> dict:
    return load_json("architecture_manifest.json")


def schema(name: str) -> dict:
    return json.loads((SPEC_DIR.parent / "AREF-002A" / f"{name}.schema.json").read_text())


def historical_schema(name: str) -> dict:
    return load_json(f"{name}.schema.json")


def amended_example(name: str) -> dict:
    return json.loads((SPEC_DIR.parent / "AREF-002A" / "examples" / f"{name}.json").read_text())


def example(name: str) -> dict:
    """A frozen example with its human annotations removed."""
    data = json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}
