#!/usr/bin/env python3
"""Three-way version coherence gate: pyproject.toml / git tag / PyPI.

Replaces the one-directional version-drift gate (WO-19 4.5), which only
asked "does a tag exist for the pyproject version?". That check misses a
rollback (the OLD tag still exists) and would miss a tagged-but-unpublished
release. This gate asserts agreement between all three sources of truth:

  ASSERT A (always; PR and main) — HARD FAIL
      pyproject_version >= pypi_latest
      You can never label a source build as older than what is published.
      This is the rollback check.

  ASSERT B (main only) — HARD FAIL
      newest_tag == pypi_latest
      Everything tagged gets published; nothing published is untagged.
      This is the WO-19 check — a fix sitting in a tag that never reached
      users, or a publish that failed silently after the tag was pushed.

  ASSERT C (main only) — WARN
      pyproject_version == newest_tag
      A bump merged to main but not yet tagged is a legitimate transient
      state, so this only warns — unless the version-bump commit is older
      than 7 days, in which case it hard-fails (a "transient" state that
      lasts a week is drift).

Release tags are selected by pattern (v<major>.<minor>.<patch>) across all
tags in the repo, newest by packaging.version — NOT by git describe. Repos
in this org carry foreign-namespace tags (ts-sdk-v*, ts-types-v*, v1,
v1.0.0-integration) that must not be compared against the Python package
version, and at least one release tag is not an ancestor of main after a
history rewrite, which topology-based selection would silently skip.

Comparisons use packaging.version.Version, never string comparison.
A repo with no release tags or no PyPI release is treated as 0.0.0 and the
relevant assertion is skipped with a printed note.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request

from packaging.version import InvalidVersion, Version

RELEASE_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+)$")
STALE_BUMP_SECONDS = 7 * 24 * 3600  # ASSERT C escalates past this age

ZERO = Version("0.0.0")


def read_pyproject() -> tuple[str, Version]:
    with open("pyproject.toml", "rb") as f:
        data = tomllib.load(f)
    project = data["project"]
    return project["name"], Version(project["version"])


def newest_release_tag() -> Version | None:
    out = subprocess.run(
        ["git", "tag", "-l"], check=True, capture_output=True, text=True
    ).stdout
    versions = []
    for tag in out.split():
        m = RELEASE_TAG_RE.match(tag)
        if m:
            try:
                versions.append(Version(m.group(1)))
            except InvalidVersion:
                print(f"note: ignoring unparsable release tag {tag!r}")
    return max(versions) if versions else None


def pypi_latest(package: str) -> Version | None:
    url = f"https://pypi.org/pypi/{package}/json"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            info = json.load(resp)["info"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise
    return Version(info["version"])


def version_bump_age_seconds(version: Version) -> int | None:
    """Age of the commit that set pyproject.toml to `version`, or None."""
    out = subprocess.run(
        [
            "git",
            "log",
            "-1",
            "--format=%ct",
            "-S",
            f'version = "{version}"',
            "--",
            "pyproject.toml",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not out:
        return None
    return int(time.time()) - int(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=["pr", "main"],
        required=True,
        help="pr: ASSERT A only. main: ASSERT A + B + C.",
    )
    args = parser.parse_args()

    name, py_version = read_pyproject()
    tag_version = newest_release_tag()
    pypi_version = pypi_latest(name)

    print(f"package:        {name}")
    print(f"pyproject.toml: {py_version}")
    print(f"newest tag:     {'v' + str(tag_version) if tag_version else '<none>'}")
    print(f"PyPI latest:    {pypi_version if pypi_version else '<none>'}")

    failed = False

    # ASSERT A — pyproject >= PyPI (always).
    if pypi_version is None:
        print("note: no PyPI release found; skipping ASSERT A (treating PyPI as 0.0.0)")
    elif py_version >= pypi_version:
        print(f"ASSERT A OK: pyproject ({py_version}) >= PyPI ({pypi_version})")
    else:
        print(
            f"::error::ASSERT A FAILED: pyproject.toml ({py_version}) is BEHIND "
            f"PyPI ({pypi_version}). Never lower a version to pass a check — "
            f"bump forward instead."
        )
        failed = True

    if args.mode == "main":
        # ASSERT B — newest tag == PyPI latest (main only).
        if tag_version is None and pypi_version is None:
            print("note: no release tags and no PyPI release; skipping ASSERT B")
        elif tag_version is None:
            print(
                f"::error::ASSERT B FAILED: PyPI serves {pypi_version} but the repo "
                f"has no release tag. Everything published must be tagged."
            )
            failed = True
        elif pypi_version is None:
            print(
                f"::error::ASSERT B FAILED: tag v{tag_version} exists but the package "
                f"has no PyPI release. Everything tagged must be published — check "
                f"the publish workflow for a silent failure."
            )
            failed = True
        elif tag_version == pypi_version:
            print(f"ASSERT B OK: newest tag (v{tag_version}) == PyPI ({pypi_version})")
        else:
            print(
                f"::error::ASSERT B FAILED: newest tag (v{tag_version}) != PyPI "
                f"({pypi_version}). Everything tagged gets published; nothing "
                f"published is untagged. If the tag is newer, the publish failed "
                f"or is pending — rerun it. If PyPI is newer, push the missing tag."
            )
            failed = True

        # ASSERT C — pyproject == newest tag (main only; warn, escalate at 7 days).
        effective_tag = tag_version if tag_version is not None else ZERO
        if tag_version is None:
            print("note: no release tags; comparing pyproject against 0.0.0 for ASSERT C")
        if py_version == effective_tag:
            print(f"ASSERT C OK: pyproject ({py_version}) == newest tag")
        else:
            age = version_bump_age_seconds(py_version)
            age_days = (age / 86400) if age is not None else None
            if age is not None and age > STALE_BUMP_SECONDS:
                print(
                    f"::error::ASSERT C FAILED: pyproject ({py_version}) != newest tag "
                    f"(v{effective_tag}) and the bump commit is {age_days:.1f} days "
                    f"old. An untagged bump is fine during a release, not for a week "
                    f"— tag and publish {py_version}, or explain in FINDINGS.md."
                )
                failed = True
            else:
                age_note = (
                    f"bump is {age_days:.1f} days old"
                    if age_days is not None
                    else "bump commit not found in history"
                )
                print(
                    f"::warning::ASSERT C: pyproject ({py_version}) != newest tag "
                    f"(v{effective_tag}) — {age_note}. Legitimate mid-release state; "
                    f"escalates to a failure after 7 days."
                )

    if failed:
        return 1
    print("version coherence: all assertions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
