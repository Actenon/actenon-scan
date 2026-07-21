# Contributing to actenon-scan

Contributions are welcome. This is a security tool — accuracy and
trust are the entire product.

## Getting started

```bash
git clone https://github.com/Actenon/actenon-scan.git
cd actenon-scan
pip install -e ".[dev]"
pytest tests/ -v
```

## Adding a new sink rule

1. Add the rule to `actenon_scan/rules/default_rules.json`
2. Add a test fixture in `tests/fixtures/vulnerable/` that triggers the rule
3. Add a safe fixture in `tests/fixtures/safe/` that guards the same sink
4. Run `pytest tests/` to confirm both classify correctly

## Adding a new guard pattern

1. Add the pattern to the `guards` array in `default_rules.json`
2. Add a test fixture that uses the guard before a sink
3. Confirm the fixture produces zero findings

## Guidelines

- **Zero runtime dependencies** in the core. stdlib only. PyYAML is optional.
- **Tests must pass** on Python 3.10, 3.11, and 3.12.
- **False positives are worse than false negatives** for a security tool.
  When in doubt, be conservative — don't raise a finding unless you're confident.
- **Document limitations honestly**. If a detection is heuristic, say so in the code comment.

## Pull requests

- Keep PRs focused — one rule or one fix per PR.
- Include test fixtures that prove the detection works.
- Update the README if the CLI interface changes.
