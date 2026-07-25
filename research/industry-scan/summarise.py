#!/usr/bin/env python3
from __future__ import annotations
import json, sys
from collections import Counter
from pathlib import Path

report_path = Path(sys.argv[1])
metadata_path = Path(sys.argv[2])
meta = json.loads(metadata_path.read_text())
data = json.loads(report_path.read_text())

findings = data.get("findings", [])
unsupported = data.get("unsupported_files", [])
severity = Counter(str(f.get("severity", "unknown")).lower() for f in findings)
category = Counter(str(f.get("category", "unknown")) for f in findings)
rules = Counter(str(f.get("rule_id", f.get("id", "unknown"))) for f in findings)

print(f"## {meta['repository']}")
print()
print(f"- Category: `{meta['category']}`")
print(f"- Target commit: `{meta['commit']}`")
print(f"- Findings: **{len(findings)}**")
print(f"- Unsupported files: **{len(unsupported)}**")
print(f"- Severity: `{dict(severity)}`")
print()
if category:
    print("### Finding categories")
    for key, value in category.most_common(12):
        print(f"- `{key}`: {value}")
if rules:
    print()
    print("### Rules")
    for key, value in rules.most_common(12):
        print(f"- `{key}`: {value}")
print()
print("> These are scanner candidates, not confirmed vulnerabilities. Manual review must determine reachability, caller control, guard dominance, fixture/test status, and whether the code sits at a real execution or resource boundary.")
