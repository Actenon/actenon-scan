# Rapsheet × Scan: recorded agent behaviour as a test of static coverage

Rapsheet reads what coding agents actually did from their session logs. Scan
reads what agent code could do. This study used the first to find places where
the second was blind, then fixed the strongest one.

| File | Contents |
|---|---|
| [BASELINE.md](BASELINE.md) | Frozen commits, reproduced benchmark and CI figures, discrepancies found |
| [BEHAVIOUR-EVIDENCE.md](BEHAVIOUR-EVIDENCE.md) | 30 recorded consequential operations with provenance, authority and verified effect; Rapsheet's own defects |
| [SCAN-GAPS.md](SCAN-GAPS.md) | Demonstrated misses, false positives, limitations and ranked opportunities |
| [BREAKTHROUGH.md](BREAKTHROUGH.md) | The improvement: mechanism, evidence chain, reproduction, limits |
| [BEFORE-AFTER.md](BEFORE-AFTER.md) | Baseline `ef8487a` vs candidate `5020b44`, with ablation per mechanism |
| `tools/` | The ablation driver, the comparison script, and the cross-session persistence check |

Private projects are pseudonymised (Repo A–E, P-SALES, P-EVAL, P-QUAL). No
transcript, credential or private source is included; the mapping and the raw
evidence extracts are kept outside the repository.
