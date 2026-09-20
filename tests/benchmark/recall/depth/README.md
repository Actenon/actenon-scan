# Hop-depth recall axis

Recall is not one number. It varies with how far the sink sits from the
entry point, and reporting it as a scalar hid that entirely.

Three sink families — NET-EGRESS, EXEC-SHELL, DATA-DELETE-SQL — at four
distances:

| Suffix       | Shape                                                    | Expected |
|--------------|----------------------------------------------------------|----------|
| `_depth0`    | sink in the tool body                                     | found    |
| `_depth1`    | tool calls a module-level helper in the same file         | found    |
| `_depth2`    | tool -> helper -> helper, same file                       | **MISSED** |
| `_crossfile` | tool calls a helper imported from another module          | **MISSED** |

The `_depth2` and `_crossfile` fixtures are recorded as EXPECTED FAILURES in
`tests/benchmark/baseline.json`. They are not deleted and they are not
softened to make a number green — recording the miss is the entire purpose
of the file. Each one produces a disclosed unfollowed call, so the scanner
says out loud that it stopped there.

A fixture moving from expected-fail to pass is a real improvement and must
be recorded in the baseline as such. A fixture moving the other way is a
regression and fails the build.

These files live in `depth/` rather than beside the other recall fixtures
because the `recall/*.py` glob requires every file it matches to produce a
finding. A deliberately-missed fixture in that glob would either fail the
build or force the assertion to be weakened; here the misses can be recorded
honestly.
