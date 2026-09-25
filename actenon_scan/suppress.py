"""Inline suppression — parses ``# actenon-scan: ignore[rule-id]`` and
``# actenon-scan: suppress rule-id`` comments.

Both syntaxes are accepted. The README previously documented only the
``suppress RULE`` form while the code only matched ``ignore[RULE]`` —
copy-paste from the README was a silent no-op. Both now work.
"""

from __future__ import annotations

import re
from pathlib import Path


# Primary syntax: # actenon-scan: ignore[EXEC-SHELL]
SUPPRESSION_PATTERN_IGNORE = re.compile(r"#\s*actenon-scan:\s*ignore\[([^\]]+)\]")
# Alternative syntax documented in the README: # actenon-scan: suppress EXEC-SHELL
SUPPRESSION_PATTERN_SUPPRESS = re.compile(r"#\s*actenon-scan:\s*suppress\s+([A-Z][A-Z0-9\-_]*)")


class SuppressionSet(set):
    """Set of ``(filename, rule_id, comment_line)`` suppression entries.

    A suppression comment on line N covers a finding on line N (trailing
    comment) or N+1 (comment on the line above) — never every finding of
    that rule elsewhere in the file. Membership tests with the older
    ``(filename, rule_id)`` pair still answer "does this file carry a
    suppression for this rule?" so existing callers keep working.
    """

    def __contains__(self, item: object) -> bool:
        if isinstance(item, tuple) and len(item) == 2:
            return any(
                isinstance(e, tuple) and e[:2] == item for e in set.__iter__(self)
            )
        return set.__contains__(self, item)


def parse_suppressions(source: str, filename: str) -> SuppressionSet:
    """Parse inline suppression comments from source code.

    Returns a :class:`SuppressionSet` of ``(filename, rule_id, line)``
    entries, where ``line`` is the 1-based line of the comment. A
    suppression on line N suppresses a finding on line N or N+1 (see
    :func:`is_suppressed`).

    Both ``ignore[RULE-ID]`` and ``suppress RULE-ID`` syntaxes are accepted.
    """
    suppressions = SuppressionSet()
    lines = source.splitlines()
    for i, line in enumerate(lines, start=1):
        # Try the bracketed ignore[RULE-ID] form first.
        match = SUPPRESSION_PATTERN_IGNORE.search(line)
        if match:
            rule_id = match.group(1).strip()
            suppressions.add((filename, rule_id, i))
            continue
        # Then the README-documented suppress RULE-ID form.
        match = SUPPRESSION_PATTERN_SUPPRESS.search(line)
        if match:
            rule_id = match.group(1).strip()
            suppressions.add((filename, rule_id, i))
    return suppressions


def is_suppressed(
    suppressions: set | None,
    filename: str,
    rule_id: str,
    line: int,
) -> bool:
    """Return True if an inline suppression covers this finding.

    ``rule_id`` may carry a guard-state suffix (``-WEAK``/``-UNBOUND``); a
    suppression for the base rule covers it. Line-scoped entries
    ``(file, rule, comment_line)`` match a finding on ``comment_line`` or
    ``comment_line + 1``. A legacy ``(file, rule)`` pair supplied by an API
    caller keeps its old file-wide meaning.
    """
    if not suppressions:
        return False
    rule_ids = {rule_id}
    for suffix in ("-WEAK", "-UNBOUND"):
        if rule_id.endswith(suffix):
            rule_ids.add(rule_id[: -len(suffix)])
    for rid in rule_ids:
        for entry in ((filename, rid, line), (filename, rid, line - 1)):
            if set.__contains__(suppressions, entry):
                return True
        if set.__contains__(suppressions, (filename, rid)):
            return True
    return False


def _normalize_key(filepath: Path, target: Path | None) -> str:
    """Compute the (file, rule_id) key the SAME way the engine does.

    The engine matches suppressions against
    ``rel = str(filepath.relative_to(target) if target.is_dir() else filepath.name)``.
    Without this normalization, suppressions keyed by absolute path never
    matched findings keyed by relative path (the universal case in CI, where
    ``scan .`` resolves to an absolute workspace path).
    """
    if target is not None:
        try:
            if target.is_dir():
                return str(filepath.relative_to(target))
            if filepath == target:
                return filepath.name
        except ValueError:
            # filepath is not under target — fall through to name-based key,
            # which still matches the engine's behaviour for the file-target
            # case.
            pass
    # Fallback that matches engine.py's behaviour when no target is given:
    # use the relative form if possible, else the absolute path. The engine
    # uses ``str(filepath.relative_to(target))`` so we MUST produce the same
    # string. When we don't know target, the safest fallback is the file's
    # name — which the engine also uses when ``target.is_file()``.
    return filepath.name


def collect_suppressions_from_file(
    filepath: Path,
    target: Path | None = None,
) -> SuppressionSet:
    """Read a file and parse its suppression comments.

    ``target`` is the scan root passed to ``scan_path``. It MUST be supplied
    when collecting suppressions for a directory scan — otherwise the
    suppression keys (absolute path) will not match the engine's finding
    keys (path relative to target), and suppressions silently become no-ops
    in CI (which uses absolute paths).
    """
    try:
        # utf-8-sig strips a UTF-8 BOM if present, matching engine.py's
        # behaviour. Without this, BOM-prefixed files raise UnicodeDecodeError
        # here and silently lose all their suppressions.
        source = filepath.read_text(encoding="utf-8-sig")
        key = _normalize_key(filepath, target)
        return parse_suppressions(source, key)
    except (OSError, UnicodeDecodeError):
        return SuppressionSet()
