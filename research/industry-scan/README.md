# Actenon consequential-action industry scan

This campaign scans **63 important repositories** across agent frameworks, computer-use agents, workflow automation, MCP tooling, infrastructure-as-code, resource boundaries, payments, commerce, communications, data operations, and security response.

## Evidence standard

A raw scanner finding is a candidate, not automatically a vulnerability or true positive. Review each candidate for:

1. Is the sink reachable from an external, agent, model, workflow, or user-controlled boundary?
2. Can the caller influence the consequential parameters?
3. Is there an authority, policy, approval, proof, or invariant check that dominates the sink?
4. Is the code production code rather than a test, fixture, demo, migration, generated file, or example?
5. Does the action cross a meaningful resource boundary or cause a consequential side effect?
6. Is refusal fail-closed and machine-readable?
7. Can the same operation be replayed or duplicated?
8. Is there durable evidence tying intent, authority, execution, and result together?

## Output

Each matrix job records:

- target repository and immutable commit SHA;
- Actenon scanner commit;
- JSON report;
- SARIF report;
- scanner exit code;
- Markdown summary.

## Important interpretation rule

Do not market the total finding count as vulnerabilities. Publish three separate numbers:

- raw candidates;
- manually reviewed reachable consequential actions;
- confirmed unguarded execution gaps.

That prevents the campaign from overstating precision.
