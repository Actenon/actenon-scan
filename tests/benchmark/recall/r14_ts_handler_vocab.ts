// p14: TypeScript handler vocabulary — exercises the sink vocabulary against
// realistic handler code. The corpus has 2,168 TS files and produced one sink
// candidate; this fixture covers the patterns the corpus did not.
//
// Expected: 3 findings (genuine child_process.exec, genuine global fetch,
// genuine fs.rmSync). Zero false positives from regex.exec, pool.spawn,
// handler.fetch, or unrelated member calls.
//
// Work Order 1.8.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { exec } from "child_process";
import * as fs from "fs";

const server = new Server({ name: "t", version: "1" }, { capabilities: { tools: {} } });

// ── Case 1: regex validation inside a tool handler. MUST NOT flag. ──
const SAFE = /^[a-z0-9_-]+$/;
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const name = req.params.arguments.name as string;
    const m = SAFE.exec(name);  // RegExp.prototype.exec — must NOT flag
    if (!m) return { content: [], isError: true };
    return { content: [{ type: "text", text: "ok" }] };
});

// ── Case 2: genuine child_process.exec. MUST flag. ──
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const cmd = req.params.arguments.cmd as string;
    const out = exec(cmd);  // genuine shell execution — MUST flag
    return { content: [{ type: "text", text: "ok" }] };
});

// ── Case 3: genuine global fetch. MUST flag. ──
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const url = req.params.arguments.url as string;
    const resp = await fetch(url);  // genuine egress — MUST flag
    return { content: [{ type: "text", text: await resp.text() }] };
});

// ── Case 4: genuine globalThis.fetch. MUST flag. ──
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const url = req.params.arguments.url as string;
    const resp = await globalThis.fetch(url);  // genuine egress — MUST flag
    return { content: [{ type: "text", text: await resp.text() }] };
});

// ── Case 5: handler.fetch (MCP handler entry point). MUST NOT flag. ──
const handler = new Server({ name: "h", version: "1" }, { capabilities: { tools: {} } });
handler.setRequestHandler(CallToolRequestSchema, async () => {
    return { content: [] };
});
const response = await handler.fetch(new Request("http://127.0.0.1/mcp"));  // MUST NOT flag

// ── Case 6: pool.spawn (unrelated method). MUST NOT flag. ──
class Pool { spawn(n: string) { return n; } }
const pool = new Pool();
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const n = req.params.arguments.n as string;
    const r = pool.spawn(n);  // unrelated method — MUST NOT flag
    return { content: [{ type: "text", text: r }] };
});

// ── Case 7: genuine fs.rmSync. MUST flag. ──
server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const path = req.params.arguments.path as string;
    fs.rmSync(path);  // genuine file deletion — MUST flag
    return { content: [{ type: "text", text: "ok" }] };
});
