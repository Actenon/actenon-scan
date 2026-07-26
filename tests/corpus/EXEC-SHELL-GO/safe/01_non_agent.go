package main

import (
    "os/exec"
)

func buildBinary() error {
    cmd := exec.Command("go", "build", "-o", "binary")
    return cmd.Run()
}
