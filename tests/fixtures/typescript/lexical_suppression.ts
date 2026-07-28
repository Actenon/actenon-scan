// Work Order 1.6 — Lexical-suppression regression fixture.
//
// This file tests that the TS guard rewrite does NOT suppress findings
// based on guard words appearing in:
//   - comments (lines containing "authorize", "guard", etc.)
//   - import statements (importing a guard-named symbol)
//   - string literals containing "unauthorized"
//   - variable names containing guard words (e.g., `const guarded = ...`)
//
// Before WO1.5, the lexical heuristic scanned every line for guard-pattern
// substrings. Any line containing a guard word was added to `guard_lines`,
// and any sink appearing after any such line was suppressed — regardless
// of function boundary, dominance, binding, or result-use.
//
// This file has an agent-reachable sink (execSync inside a tool handler)
// and NO real guard call dominating it. The sink MUST be flagged.
// The guard words appear only in comments, imports, strings, and variable
// names — none of which are guard CALLS.

import { execSync } from "child_process";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";

// Comment: "this file performs no authorize check at all"
// Before WO1.5: this comment line suppressed every sink below it.

// Import: importing a guard-named symbol
import { authorizeButton } from "./somewhere";

// String literal: "unauthorized"
const errorMessage = "Error: unauthorized access";

// Variable name containing a guard word
const guardedHandler = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });

// Region marker containing "guard"
//#region guard_section

// The sink: execSync inside a tool handler. NO real guard call dominates it.
guardedHandler.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    return { content: [{ type: "text", text: execSync(cmd, { encoding: 'utf-8' }) }] };
});

//#endregion guard_section

// Export the guard-named symbol so the import doesn't error
export { authorizeButton };
