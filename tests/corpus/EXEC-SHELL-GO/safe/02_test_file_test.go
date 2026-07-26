package main

import (
    "os/exec"
    "testing"
)

func TestExec(t *testing.T) {
    out, err := exec.Command("echo", "hello").Output()
    if err != nil {
        t.Fatal(err)
    }
    _ = out
}
