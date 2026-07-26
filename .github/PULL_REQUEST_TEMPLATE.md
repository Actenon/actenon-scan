<!-- Thanks for contributing to actenon-scan! Please fill in the sections below. -->

## Summary

<!-- One paragraph explaining what this PR changes and why. -->

## Type of change

<!-- Check all that apply. -->

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (new sink rule, guard pattern, agent framework, output format)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Refactor (no functional change)

## Verification

<!-- How did you verify this change works? Include test names, commands, or screenshots. -->

- [ ] `pytest tests/` passes locally
- [ ] `python scripts/check_coverage_contract.py` passes (if rules changed)
- [ ] `python scripts/check_corpus_triage.py` passes (if corpus changed)
- [ ] `actenon-scan scan .` self-scan still reports 0 findings (if production code changed)

## Fixture change justification

<!-- If this PR modifies any file under tests/benchmark/ or tests/corpus/,
     you MUST include this section. CI will fail without it. See
     CONTRIBUTING.md for the rationale. -->

<!-- Delete this block if no benchmark/corpus files were changed.

Fixture changed: <path>
Reason: <why the old fixture was wrong>
Score against OLD fixture: <n>/<m>
Score against NEW fixture: <n>/<m>
-->

## Related issues

<!-- "Fixes #123" or "Refs #123". Delete if none. -->

## Checklist

- [ ] I have read CONTRIBUTING.md
- [ ] My code follows the project's code style (ruff)
- [ ] I have added tests that prove my fix is effective or my feature works
- [ ] I have updated docs/COVERAGE.md if I added/changed a rule or architecture
- [ ] I have updated the README if I added/changed a user-facing feature
- [ ] The CHANGELOG has an entry for this change (under `[Unreleased]`)
