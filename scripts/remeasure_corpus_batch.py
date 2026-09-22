#!/usr/bin/env python3
"""Batch corpus re-measurement: processes repos in groups to avoid timeouts.

Saves intermediate results to /tmp/corpus-batch-results.json so we can
resume if interrupted. Merges all batches at the end and writes the
final corpus-results.json.
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from actenon_scan.engine import scan_path
from actenon_scan.rules.loader import load_rules

PAT = os.environ.get("GITHUB_TOKEN", "")
PINNED_FILE = REPO_ROOT / "tests" / "benchmark" / "pinned_repos.json"
OUTPUT_FILE = REPO_ROOT / "tests" / "benchmark" / "corpus-results.json"
CHECKPOINT_FILE = Path("/tmp/corpus-batch-checkpoint.json")

import shutil
import subprocess
import tempfile


def clone_repo(repo_full_name: str, sha: str, dest: Path) -> bool:
    url = f"https://{PAT}@github.com/{repo_full_name}.git" if PAT else f"https://github.com/{repo_full_name}.git"
    try:
        shutil.rmtree(dest, ignore_errors=True)
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dest)],
            capture_output=True, text=True, timeout=120, check=True,
        )
        subprocess.run(
            ["git", "fetch", "--depth", "1", "origin", sha],
            capture_output=True, text=True, timeout=120, check=True,
            cwd=str(dest),
        )
        subprocess.run(
            ["git", "checkout", sha],
            capture_output=True, text=True, timeout=30, check=True,
            cwd=str(dest),
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"    CLONE FAILED: {e}", file=sys.stderr)
        return False


def scan_repo(repo_path: Path) -> list[dict]:
    try:
        result = scan_path(repo_path, cache=None, repository_analysis=False)
        findings = []
        for f in result.findings:
            if f.suppressed:
                continue
            findings.append({
                "file": f.file, "line": f.line, "rule_id": f.rule_id,
                "severity": f.severity, "confidence": f.confidence,
                "description": f.description, "call_text": f.call_text,
                "category": f.category,
            })
        return findings
    except Exception as e:
        print(f"    SCAN ERROR: {e}", file=sys.stderr)
        return []


def main():
    with open(PINNED_FILE) as f:
        pinned = json.load(f)

    repos = pinned["repos"]
    total = len(repos)

    # Load checkpoint if it exists
    checkpoint = {}
    if CHECKPOINT_FILE.exists():
        checkpoint = json.loads(CHECKPOINT_FILE.read_text())
        print(f"Resuming from checkpoint: {len(checkpoint)} repos already scanned")

    work_dir = Path(tempfile.mkdtemp(prefix="corpus-batch-"))

    for i, repo in enumerate(repos):
        name = repo["name"]
        if name in checkpoint:
            print(f"[{i+1}/{total}] {name} — already scanned (skipping)")
            continue

        full_name = repo.get("repo", repo.get("full_name", name))
        sha = repo["sha"]
        category = repo.get("category", "unknown")
        print(f"[{i+1}/{total}] {name} ({category})...", end=" ", flush=True)

        dest = work_dir / name
        if not clone_repo(full_name, sha, dest):
            checkpoint[name] = {"findings": -1, "error": "clone_failed", "category": category}
            print("CLONE FAILED")
            CHECKPOINT_FILE.write_text(json.dumps(checkpoint))
            continue

        findings = scan_repo(dest)
        print(f"{len(findings)} finding(s)")

        checkpoint[name] = {
            "findings": len(findings),
            "category": category,
            "sha": sha,
            "finding_list": findings,
        }
        CHECKPOINT_FILE.write_text(json.dumps(checkpoint))

        shutil.rmtree(dest, ignore_errors=True)

    # Merge into corpus-results.json format
    results = {
        "totals_by_category": {},
        "total_findings": 0,
        "repos": {},
        "findings": [],
        "measured_at_sha": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT), text=True
        ).strip(),
    }

    for name, data in sorted(checkpoint.items()):
        findings = data.get("finding_list", [])
        cat = data.get("category", "unknown")
        results["repos"][name] = {
            "findings": len(findings) if findings != -1 else -1,
            "category": cat,
            "sha": data.get("sha", ""),
        }
        results["total_findings"] += len(findings) if findings != -1 else 0
        for f in findings:
            f["repo"] = name
            results["findings"].append(f)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2, sort_keys=True)
        f.write("\n")

    # Print summary
    print(f"\n=== CORPUS RE-MEASUREMENT COMPLETE ===")
    print(f"Total findings: {results['total_findings']}")
    print(f"Repos scanned: {len(results['repos'])}")

    controls = {r["name"] for r in repos if r.get("category") == "control"}
    ctrl_findings = 0
    for name in controls:
        data = results["repos"].get(name, {})
        n = data.get("findings", 0)
        ctrl_findings += n if n >= 0 else 0
        print(f"  {name} (CONTROL): {n} findings")

    print(f"\nControl repo total: {ctrl_findings} (must be 0)")

    # Print per-repo
    for name, data in sorted(results["repos"].items()):
        n = data.get("findings", 0)
        cat = data.get("category", "?")
        ctrl = " (CONTROL)" if name in controls else ""
        if n > 0 or ctrl:
            print(f"  {name}: {n} findings ({cat}){ctrl}")

    shutil.rmtree(work_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
