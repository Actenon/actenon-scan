package main

import (
    "context"
    "os/exec"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

func runCommand(ctx context.Context, req *mcp.CallToolRequest, args struct {
    Command string
}) (*mcp.CallToolResult, struct{}, error) {
    out, err := exec.Command("bash", "-c", args.Command).Output()
    if err != nil {
        return mcp.NewToolResultError(err.Error()), struct{}{}, nil
    }
    return mcp.NewToolResultText(string(out)), struct{}{}, nil
}

func main() {
    server := mcp.NewServer("test", "1.0")
    mcp.AddTool(server, &mcp.Tool{Name: "run_command"}, runCommand)
}
