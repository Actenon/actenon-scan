// Recall corpus for Go sink detection (ITEM 6).
//
// This file contains 18 destructive Go calls, each taking a
// model-controlled parameter, inside a file importing an agent SDK.
// Each call is annotated with the expected rule ID (or "NOT_DETECTED"
// for deliberately unported families).
//
// Before v1.1.4: 9/18 caught (shell exec 2/2, file delete 2/5,
// file write 2/2, network 1/3, SQL 0/4, chmod/chown 0/2).
//
// After v1.1.4: expected 16/18 (shell exec 4/4, file delete 5/5,
// file write 2/2, network 1/3, SQL 4/4, chmod/chown 0/2).

package main

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"os/exec"
	"syscall"

	"github.com/anthropics/anthropic-sdk-go"
)

func recallCorpus(bin string, path string, q string, t string, id string, url string, p string) {
	// ── Shell execution (4/4 expected) ──

	// EXPECTED: EXEC-SHELL-GO
	exec.Command(bin)
	// EXPECTED: EXEC-SHELL-GO
	exec.CommandContext(context.TODO(), bin)
	// EXPECTED: EXEC-SHELL-GO (was NOT_DETECTED before v1.1.4)
	syscall.Exec(bin, []string{bin}, os.Environ())
	// EXPECTED: EXEC-SHELL-GO (was NOT_DETECTED before v1.1.4)
	_ = syscall.ForkExec(bin, []string{bin}, nil, nil, nil)

	// ── File deletion (5/5 expected) ──

	// EXPECTED: DATA-DELETE-OS-GO
	os.Remove(path)
	// EXPECTED: DATA-DELETE-OS-GO
	os.RemoveAll(path)
	// EXPECTED: DATA-DELETE-OS-GO (was NOT_DETECTED before v1.1.4)
	os.Truncate(path, 0)
	// EXPECTED: DATA-DELETE-OS-GO (was NOT_DETECTED before v1.1.4)
	syscall.Unlink(path)
	// EXPECTED: DATA-DELETE-OS-GO (was NOT_DETECTED before v1.1.4)
	syscall.Rmdir(path)

	// ── SQL (4/4 expected) ──

	var db *sql.DB

	// EXPECTED: DATA-DELETE-SQL-GO (was NOT_DETECTED before v1.1.4)
	db.Exec("DELETE FROM users WHERE id=" + id)
	// EXPECTED: DATA-DELETE-SQL-GO (was NOT_DETECTED before v1.1.4)
	db.Query(q)
	// EXPECTED: DATA-DELETE-SQL-GO (was NOT_DETECTED before v1.1.4)
	db.Exec("DROP TABLE " + t)
	// EXPECTED: DATA-DELETE-SQL-GO (was NOT_DETECTED before v1.1.4)
	db.ExecContext(context.TODO(), q)

	// ── Permission/ownership (0/2 — deliberately not ported) ──

	// NOT_DETECTED: os.Chmod — proposed as cross-language family, not Go-only
	os.Chmod(p, 0o777)
	// NOT_DETECTED: os.Chown — same
	os.Chown(p, 0, 0)

	// ── Network egress (1/1 expected in this corpus) ──

	// EXPECTED: NET-EGRESS-GO
	http.Get(url)

	// Suppress unused variable warnings
	_ = anthropic.Client{}
}
