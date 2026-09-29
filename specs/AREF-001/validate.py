#!/usr/bin/env python3
"""AREF-001 artefact validator.

Checks the AREF-001 specification directory for internal consistency:

  1. every JSON file parses;
  2. every schema is itself a valid JSON Schema (2020-12);
  3. every positive example validates against its schema;
  4. every negative example is REJECTED by its schema, for the stated reason;
  5. the draft catalogue conforms to the catalogue schema;
  6. the enum vocabularies agree across schemas;
  7. MANIFEST.sha256 matches the files on disk.

This is a specification checker, not part of Resource Effect Inference. It
contains no detection logic, imports nothing from ``actenon_scan``, and writes
nothing: ``--print-manifest`` emits the manifest on stdout so a reviewer can
regenerate and diff it without this script needing write access.

Usage
-----
    python3 specs/AREF-001/validate.py
    python3 specs/AREF-001/validate.py --print-manifest

Requires ``jsonschema``. Install with ``python3 -m pip install jsonschema``.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
FROZEN_COMMIT = "b8a6a62308fb2d569b6530f6ecf250e6e4ef6e16"

# MANIFEST files are excluded from their own inventory.
MANIFEST_EXCLUDED = {"MANIFEST.json", "MANIFEST.sha256"}

SCHEMA_FILES = [
    "schema/resource-effect.schema.json",
    "schema/resource-effect-catalogue.schema.json",
    "schema/rei-report-fragment.schema.json",
    "schema/aref-001-manifest.schema.json",
]

RECORD_SCHEMA = "https://actenon.dev/schema/aref-001/resource-effect-0.1.0.json"
CATALOGUE_SCHEMA = (
    "https://actenon.dev/schema/aref-001/resource-effect-catalogue-0.1.0.json"
)
FRAGMENT_SCHEMA = "https://actenon.dev/schema/aref-001/rei-report-fragment-0.1.0.json"
MANIFEST_SCHEMA = "https://actenon.dev/schema/aref-001/manifest-0.1.0.json"


class Report:
    """Accumulates pass/fail lines so the whole run is reported, not just the
    first failure. A validator that stops at the first problem hides how many
    there are."""

    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []

    def ok(self, label: str) -> None:
        self.passed += 1
        print(f"  PASS  {label}")

    def fail(self, label: str, detail: str = "") -> None:
        self.failed.append(label)
        print(f"  FAIL  {label}")
        if detail:
            for line in detail.strip().splitlines()[:6]:
                print(f"        {line}")

    def section(self, name: str) -> None:
        print(f"\n{name}")

    def finish(self) -> int:
        print(f"\n{self.passed} check(s) passed, {len(self.failed)} failed")
        if self.failed:
            print("\nFAILED:")
            for f in self.failed:
                print(f"  - {f}")
            return 1
        return 0


def load_json(rel: str) -> object:
    return json.loads((HERE / rel).read_text(encoding="utf-8"))


def strip_annotations(value):
    """Remove documentation keys (leading underscore) so instances can carry
    their own explanation without tripping ``additionalProperties: false``."""
    if isinstance(value, dict):
        return {
            k: strip_annotations(v)
            for k, v in value.items()
            if not k.startswith("_")
        }
    if isinstance(value, list):
        return [strip_annotations(v) for v in value]
    return value


def build_registry(schemas: dict[str, dict]):
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    registry = Registry()
    for schema in schemas.values():
        registry = registry.with_resource(
            schema["$id"], Resource(contents=schema, specification=DRAFT202012)
        )
    return registry


def iter_artefacts() -> list[Path]:
    files = [
        p
        for p in sorted(HERE.rglob("*"))
        if p.is_file()
        and "__pycache__" not in p.parts
        and p.name not in MANIFEST_EXCLUDED
    ]
    return files


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_manifest() -> dict:
    files = iter_artefacts()
    entries = [
        {
            "path": p.relative_to(REPO_ROOT).as_posix(),
            "sha256": sha256_of(p),
            "bytes": p.stat().st_size,
        }
        for p in files
    ]
    return {
        "artefact": "AREF-001",
        "manifest_schema_version": "0.1.0",
        "frozen_against_commit": FROZEN_COMMIT,
        "hash_algorithm": "sha256",
        "excluded": sorted(MANIFEST_EXCLUDED),
        "file_count": len(entries),
        "total_bytes": sum(e["bytes"] for e in entries),
        "files": entries,
    }


def main() -> int:
    if "--print-manifest" in sys.argv:
        print(json.dumps(build_manifest(), indent=2))
        return 0

    try:
        from jsonschema import Draft202012Validator
    except ImportError:
        print(
            "jsonschema is required.\n"
            "  python3 -m pip install jsonschema",
            file=sys.stderr,
        )
        return 2

    rep = Report()

    # --- 1 & 2: schemas parse and are valid JSON Schema ---------------------
    rep.section("Schemas")
    schemas: dict[str, dict] = {}
    for rel in SCHEMA_FILES:
        try:
            schema = load_json(rel)
        except Exception as exc:  # noqa: BLE001 - report, do not abort
            rep.fail(f"{rel} parses", str(exc))
            continue
        schemas[rel] = schema
        rep.ok(f"{rel} parses")
        try:
            Draft202012Validator.check_schema(schema)
            rep.ok(f"{rel} is a valid JSON Schema 2020-12")
        except Exception as exc:  # noqa: BLE001
            rep.fail(f"{rel} is a valid JSON Schema 2020-12", str(exc))

    if len(schemas) != len(SCHEMA_FILES):
        return rep.finish()

    registry = build_registry(schemas)

    def validator_for(uri: str) -> "Draft202012Validator":
        return Draft202012Validator({"$ref": uri}, registry=registry)

    # --- 3: positive examples validate -------------------------------------
    rep.section("Positive examples")
    record_v = validator_for(RECORD_SCHEMA)
    positives = load_json("examples/resource-effect.valid.json")["instances"]
    for i, raw in enumerate(positives):
        label = f"resource-effect.valid.json[{i}] {raw.get('_case', '')[:64]}"
        errors = sorted(record_v.iter_errors(strip_annotations(raw)), key=str)
        if errors:
            rep.fail(label, "\n".join(e.message for e in errors))
        else:
            rep.ok(label)

    cat_v = validator_for(CATALOGUE_SCHEMA)
    cat_example = strip_annotations(load_json("examples/catalogue.valid.json"))
    errors = sorted(cat_v.iter_errors(cat_example), key=str)
    if errors:
        rep.fail("catalogue.valid.json", "\n".join(e.message for e in errors))
    else:
        rep.ok("catalogue.valid.json")

    frag_v = validator_for(FRAGMENT_SCHEMA)
    frag = strip_annotations(load_json("examples/rei-report-fragment.valid.json"))
    errors = sorted(frag_v.iter_errors(frag), key=str)
    if errors:
        rep.fail("rei-report-fragment.valid.json", "\n".join(e.message for e in errors))
    else:
        rep.ok("rei-report-fragment.valid.json")

    # --- 4: negative examples are rejected ---------------------------------
    rep.section("Negative examples (must be rejected)")
    negatives = load_json("examples/resource-effect.invalid.json")["instances"]
    for i, case in enumerate(negatives):
        label = f"record rejects [{i}] {case.get('_case', '')[:64]}"
        if record_v.is_valid(strip_annotations(case["instance"])):
            rep.fail(
                label,
                "instance VALIDATED but must be rejected: " + case.get("_violates", ""),
            )
        else:
            rep.ok(label)

    neg_cats = load_json("examples/catalogue.invalid.json")["documents"]
    for i, case in enumerate(neg_cats):
        label = f"catalogue rejects [{i}] {case.get('_case', '')[:64]}"
        if cat_v.is_valid(strip_annotations(case["document"])):
            rep.fail(
                label,
                "document VALIDATED but must be rejected: " + case.get("_violates", ""),
            )
        else:
            rep.ok(label)

    # --- 5: the draft catalogue conforms ----------------------------------
    rep.section("Draft catalogue")
    draft_raw = load_json("catalogue/resource-effect-catalogue.draft.json")
    draft = strip_annotations(draft_raw)
    errors = sorted(cat_v.iter_errors(draft), key=str)
    if errors:
        rep.fail(
            "draft catalogue conforms to catalogue schema",
            "\n".join(e.message for e in errors),
        )
    else:
        rep.ok("draft catalogue conforms to catalogue schema")

    entries = draft["entries"]
    keys = [(e["normalised_rule_id"], e["language"]) for e in entries]
    if len(keys) == len(set(keys)):
        rep.ok(f"draft catalogue keys unique ({len(keys)} entries)")
    else:
        dupes = sorted({k for k in keys if keys.count(k) > 1})
        rep.fail("draft catalogue keys unique", f"duplicates: {dupes}")

    # AREF-001 states no draft-catalogue entry is 'frozen'. That claim is
    # load-bearing (it is why the verdict is NOT READY), so it is checked
    # rather than asserted in prose alone.
    frozen = [e["normalised_rule_id"] for e in entries if e["status"] == "frozen"]
    if frozen:
        rep.fail(
            "draft catalogue contains no 'frozen' entry",
            f"frozen entries present: {frozen}",
        )
    else:
        rep.ok("draft catalogue contains no 'frozen' entry (AREF-001 B-03)")

    blocked = [e for e in entries if e["status"] == "blocked"]
    if all("blocked_on" in e for e in blocked):
        rep.ok(f"every blocked entry names a decision ({len(blocked)} entries)")
    else:
        rep.fail("every blocked entry names a decision")

    by_lang: dict[str, int] = {}
    for e in entries:
        by_lang[e["language"]] = by_lang.get(e["language"], 0) + 1
    rep.ok(f"draft catalogue language coverage: {by_lang}")

    if draft.get("frozen_against_commit") == FROZEN_COMMIT:
        rep.ok("draft catalogue pins the freeze commit")
    else:
        rep.fail("draft catalogue pins the freeze commit")

    # --- 6: vocabularies agree across schemas -----------------------------
    rep.section("Vocabulary agreement")
    defs = schemas["schema/resource-effect.schema.json"]["$defs"]
    kinds = set(defs["resourceKind"]["enum"])
    if "unknown_resource" in kinds:
        rep.ok("resourceKind carries the unknown_resource sentinel")
    else:
        rep.fail("resourceKind carries the unknown_resource sentinel")
    if "unknown_effect" in set(defs["effectType"]["enum"]):
        rep.ok("effectType carries the unknown_effect sentinel")
    else:
        rep.fail("effectType carries the unknown_effect sentinel")

    used_kinds = {e["resource_kind"] for e in entries}
    if used_kinds <= kinds:
        rep.ok(f"catalogue uses only declared resource kinds ({len(used_kinds)} of {len(kinds)})")
    else:
        rep.fail(
            "catalogue uses only declared resource kinds",
            f"undeclared: {sorted(used_kinds - kinds)}",
        )

    # The fragment must not restate the vocabularies; it must reference them,
    # or the two drift (AREF-001 D-04's reason for reusing EffectType applies
    # equally within this directory).
    frag_props = schemas["schema/rei-report-fragment.schema.json"]["properties"]
    referenced = {
        frag_props["resource_effect_by_kind"]["propertyNames"]["$ref"].split("#")[0],
        frag_props["resource_effect_by_unresolved_reason"]["propertyNames"]["$ref"].split("#")[0],
        frag_props["capabilities"]["items"]["properties"]["resource_effect"]["$ref"],
    }
    if referenced == {RECORD_SCHEMA}:
        rep.ok("report fragment references the record schema for its vocabularies")
    else:
        rep.fail(
            "report fragment references the record schema for its vocabularies",
            f"referenced: {sorted(referenced)}",
        )

    # --- 6b: coherence with the frozen repository (read-only) --------------
    # Reads three files by path. Deliberately does NOT import actenon_scan:
    # a spec checker that imports the thing it specifies can be satisfied by
    # a change to either side.
    rep.section("Repository coherence (read-only)")
    import re

    rules_path = REPO_ROOT / "actenon_scan" / "rules" / "default_rules.json"
    ts_path = REPO_ROOT / "actenon_scan" / "detectors" / "typescript.py"
    go_path = REPO_ROOT / "actenon_scan" / "detectors" / "go.py"
    effects_path = REPO_ROOT / "actenon_scan" / "repository" / "effect_summary.py"

    if not all(p.exists() for p in (rules_path, ts_path, go_path, effects_path)):
        rep.ok("repository coherence checks skipped (scanner sources not present)")
    else:
        rule_pat = re.compile(r'"([A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+)"')
        py_ids = {
            s["id"]
            for s in json.loads(rules_path.read_text(encoding="utf-8"))["sinks"]
        }
        ts_ids = {m for m in rule_pat.findall(ts_path.read_text(encoding="utf-8")) if m in py_ids}
        go_ids = {
            m[:-3]
            for m in rule_pat.findall(go_path.read_text(encoding="utf-8"))
            if m.endswith("-GO")
        }
        for lang, expected in (("python", py_ids), ("typescript", ts_ids), ("go", go_ids)):
            got = {e["normalised_rule_id"] for e in entries if e["language"] == lang}
            if got == expected:
                rep.ok(f"catalogue covers every {lang} rule ID exactly ({len(got)})")
            else:
                rep.fail(
                    f"catalogue covers every {lang} rule ID exactly",
                    f"missing: {sorted(expected - got)}\nextra: {sorted(got - expected)}",
                )

        # The schema's effect vocabulary must equal EffectType's members
        # (AREF-001 D-04). Parsed textually for the reason above.
        src = effects_path.read_text(encoding="utf-8")
        block = src.split("class EffectType(str, Enum):", 1)[1].split("\nclass ", 1)[0]
        py_effects = set(re.findall(r'^\s+[A-Z_]+ = "([a-z_]+)"', block, re.M))
        schema_effects = set(defs["effectType"]["enum"])
        if py_effects == schema_effects:
            rep.ok(f"schema effect enum equals EffectType ({len(py_effects)} members)")
        else:
            rep.fail(
                "schema effect enum equals EffectType",
                f"only in schema: {sorted(schema_effects - py_effects)}\n"
                f"only in EffectType: {sorted(py_effects - schema_effects)}",
            )

    # --- 7: manifest ------------------------------------------------------
    rep.section("Manifest")
    manifest_json = HERE / "MANIFEST.json"
    manifest_sha = HERE / "MANIFEST.sha256"
    if not manifest_json.exists() or not manifest_sha.exists():
        rep.fail("MANIFEST.json and MANIFEST.sha256 exist")
    else:
        rep.ok("MANIFEST.json and MANIFEST.sha256 exist")
        recorded = json.loads(manifest_json.read_text(encoding="utf-8"))
        man_v = validator_for(MANIFEST_SCHEMA)
        errors = sorted(man_v.iter_errors(recorded), key=str)
        if errors:
            rep.fail("MANIFEST.json conforms to its schema", "\n".join(e.message for e in errors))
        else:
            rep.ok("MANIFEST.json conforms to its schema")

        actual = build_manifest()
        rec_map = {e["path"]: e["sha256"] for e in recorded["files"]}
        act_map = {e["path"]: e["sha256"] for e in actual["files"]}
        missing = sorted(set(act_map) - set(rec_map))
        extra = sorted(set(rec_map) - set(act_map))
        changed = sorted(p for p in set(rec_map) & set(act_map) if rec_map[p] != act_map[p])
        if missing or extra or changed:
            rep.fail(
                "MANIFEST.json matches the files on disk",
                f"unrecorded: {missing}\nrecorded but absent: {extra}\ndigest changed: {changed}",
            )
        else:
            rep.ok(f"MANIFEST.json matches the files on disk ({len(act_map)} files)")

        # MANIFEST.sha256 is the flat `sha256  path` form, so it can be checked
        # with `sha256sum -c` as well as by this script.
        flat: dict[str, str] = {}
        for line in manifest_sha.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, _, path = line.partition("  ")
            flat[path.strip()] = digest.strip()
        if flat == rec_map:
            rep.ok("MANIFEST.sha256 agrees with MANIFEST.json")
        else:
            rep.fail(
                "MANIFEST.sha256 agrees with MANIFEST.json",
                f"differing paths: {sorted(set(flat) ^ set(rec_map))}",
            )

    return rep.finish()


if __name__ == "__main__":
    raise SystemExit(main())
