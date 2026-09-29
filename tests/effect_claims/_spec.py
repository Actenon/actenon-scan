"""Frozen historical artefacts and the explicitly superseding current profiles."""

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
    profile = "AREF-002B" if name in ("effect_claim", "effect_receipt", "budget_provenance") else "AREF-002A"
    return json.loads((SPEC_DIR.parent / profile / f"{name}.schema.json").read_text())


def schema_resources() -> tuple[dict, ...]:
    # Keep inherited IDs available: B only supersedes the claim/receipt budget clauses.
    return tuple(json.loads(p.read_text()) for profile in ("AREF-002A", "AREF-002B")
                 for p in sorted((SPEC_DIR.parent / profile).glob("*.schema.json")))


def historical_schema(name: str) -> dict:
    return load_json(f"{name}.schema.json")


def amended_example(name: str) -> dict:
    return json.loads((SPEC_DIR.parent / "AREF-002A" / "examples" / f"{name}.json").read_text())


def example(name: str) -> dict:
    """A frozen example with its human annotations removed."""
    data = json.loads((EXAMPLES / f"{name}.json").read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}
