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
from datetime import UTC, date, datetime, timedelta
import json
from pathlib import Path
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
MAX_WAIVER_DAYS = 14
WAIVER_BLOCK_RE = re.compile(
    r"```version-waiver\s*\n(.*?)\n```",
    re.DOTALL,
)

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


def validate_staged_candidate_waiver(
    package: str,
    staged_version: Version,
    published_version: Version | None,
    *,
    findings_path: str | Path = "FINDINGS.md",
    today: date | None = None,
) -> tuple[bool, dict[str, str] | str]:
    """Validate a structured, bounded candidate-only version waiver in FINDINGS.md.

    Prose substring matches (e.g. ``"Do not publish 1.6.0"`` or ``"11.6.0"``) are
    rejected. A valid waiver must be a fenced ``version-waiver`` JSON block with:
      - ``package`` == exact package name
      - ``staged_version`` == exact pyproject version
      - ``published_version`` == exact current PyPI version (or ``"<none>"``)
      - ``status`` == ``"RELEASE_BLOCKED"``
      - non-empty ``owner`` and ``reason``
      - ``expires_at`` (ISO-8601 ``YYYY-MM-DD``) in ``[today, today + 14 days]``
    """
    ref_day = today or datetime.now(UTC).date()
    try:
        text = Path(findings_path).read_text(encoding="utf-8")
    except OSError as exc:
        return False, f"unable to read {findings_path}: {exc}"

    blocks = WAIVER_BLOCK_RE.findall(text)
    if not blocks:
        return False, "no structured ```version-waiver JSON block found in FINDINGS.md"

    expected_published = str(published_version) if published_version is not None else "<none>"
    last_error = "no matching package/staged_version block found"

    for raw_block in blocks:
        try:
            entry = json.loads(raw_block.strip())
        except json.JSONDecodeError as exc:
            last_error = f"invalid JSON in version-waiver block: {exc}"
            continue
        if not isinstance(entry, dict):
            last_error = "version-waiver block must be a JSON object"
            continue

        if entry.get("package") != package:
            continue
        raw_staged = entry.get("staged_version")
        if not isinstance(raw_staged, str) or raw_staged != str(staged_version):
            last_error = (
                f"staged_version {raw_staged!r} does not exactly match {str(staged_version)!r}"
            )
            continue
        try:
            if Version(raw_staged) != staged_version:
                last_error = f"parsed staged_version {raw_staged!r} != {staged_version}"
                continue
        except InvalidVersion:
            last_error = f"invalid staged_version {raw_staged!r}"
            continue

        raw_published = entry.get("published_version")
        if raw_published != expected_published:
            last_error = (
                f"published_version {raw_published!r} does not match PyPI {expected_published!r}"
            )
            continue

        if entry.get("status") != "RELEASE_BLOCKED":
            last_error = (
                f"waiver status must be 'RELEASE_BLOCKED', got {entry.get('status')!r}"
            )
            continue

        owner = str(entry.get("owner") or "").strip()
        reason = str(entry.get("reason") or "").strip()
        if not owner or not reason:
            last_error = "waiver must specify non-empty 'owner' and 'reason'"
            continue

        raw_expires = str(entry.get("expires_at") or "").strip()
        try:
            expires_day = date.fromisoformat(raw_expires)
        except ValueError:
            last_error = f"invalid expires_at date {raw_expires!r} (expected YYYY-MM-DD)"
            continue

        if expires_day < ref_day:
            last_error = f"waiver expired on {expires_day.isoformat()} (today is {ref_day.isoformat()})"
            continue
        if expires_day > ref_day + timedelta(days=MAX_WAIVER_DAYS):
            last_error = (
                f"waiver expiry {expires_day.isoformat()} exceeds {MAX_WAIVER_DAYS}-day bound"
            )
            continue

        return True, {
            "package": package,
            "staged_version": str(staged_version),
            "published_version": expected_published,
            "status": "RELEASE_BLOCKED",
            "owner": owner,
            "reason": reason,
            "expires_at": expires_day.isoformat(),
        }

    return False, last_error


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=["pr", "main", "release"],
        required=True,
        help="pr: ASSERT A only. main: candidate stage (ASSERT A + B + C with structured waiver). release: strict release gate (no waivers permitted).",
    )
    parser.add_argument(
        "--stage",
        choices=["candidate", "release"],
        default=None,
        help="Explicit stage override ('release' disallows any staged candidate waiver).",
    )
    args = parser.parse_args(argv)
    require_release = args.mode == "release" or args.stage == "release"

    name, py_version = read_pyproject()
    tag_version = newest_release_tag()
    pypi_version = pypi_latest(name)

    print(f"package:        {name}")
    print(f"pyproject.toml: {py_version}")
    print(f"newest tag:     {'v' + str(tag_version) if tag_version else '<none>'}")
    print(f"PyPI latest:    {pypi_version if pypi_version else '<none>'}")
    print(f"check stage:    {'release' if require_release else args.mode}")

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

    if args.mode in ("main", "release"):
        # ASSERT B — newest tag == PyPI latest (main and release).
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

        # ASSERT C — pyproject == newest tag.
        effective_tag = tag_version if tag_version is not None else ZERO
        if tag_version is None:
            print("note: no release tags; comparing pyproject against 0.0.0 for ASSERT C")
        if py_version == effective_tag:
            print(f"ASSERT C OK: pyproject ({py_version}) == newest tag (v{effective_tag})")
        elif require_release:
            print(
                f"::error::RELEASE_BLOCKED: pyproject ({py_version}) != newest tag "
                f"(v{effective_tag}) and PyPI ({pypi_version}). Candidate waivers are "
                f"not valid for release readiness."
            )
            failed = True
        else:
            age = version_bump_age_seconds(py_version)
            age_days = (age / 86400) if age is not None else None
            waiver_ok, waiver_info = validate_staged_candidate_waiver(
                name, py_version, pypi_version
            )
            if age is not None and age > STALE_BUMP_SECONDS and not waiver_ok:
                print(
                    f"::error::ASSERT C FAILED: pyproject ({py_version}) != newest tag "
                    f"(v{effective_tag}), bump commit is {age_days:.1f} days old, and "
                    f"no valid structured version-waiver was found ({waiver_info})."
                )
                failed = True
            elif waiver_ok and isinstance(waiver_info, dict):
                print(
                    f"::warning::CANDIDATE_STAGE_OK [RELEASE_BLOCKED]: "
                    f"package={waiver_info['package']} staged={waiver_info['staged_version']} "
                    f"published={waiver_info['published_version']} owner={waiver_info['owner']} "
                    f"expires_at={waiver_info['expires_at']} — source candidate is staged; "
                    f"public release remains BLOCKED until tag v{py_version} and PyPI match."
                )
            else:
                age_note = (
                    f"bump is {age_days:.1f} days old"
                    if age_days is not None
                    else "bump commit not found in history"
                )
                print(
                    f"::warning::ASSERT C [RELEASE_BLOCKED]: pyproject ({py_version}) != newest tag "
                    f"(v{effective_tag}) — {age_note}. Legitimate mid-release state; "
                    f"escalates to a failure after 7 days unless a valid structured "
                    f"version-waiver is present."
                )

    if failed:
        return 1
    if args.mode in ("main", "release") and py_version != (tag_version if tag_version is not None else ZERO):
        print(f"version coherence: CANDIDATE_STAGE_OK (release status: RELEASE_BLOCKED for {name}=={py_version})")
    else:
        print("version coherence: all assertions passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
