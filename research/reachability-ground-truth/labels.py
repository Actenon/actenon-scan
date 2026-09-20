#!/usr/bin/env python3
"""Hand-assigned ground-truth labels for the 160-case stratified sample.

Every label below was assigned by reading the cited source in the pinned
checkout. `verified` records HOW: "path" = the full boundary->sink call path
was read hop by hop; "site" = the sink site, its enclosing definition, its
caller set and the absence/presence of any agent boundary were read.

DECISION RULE (stated because it materially moves the numbers):
AGENT_REACHABLE requires a path from an AGENT/TOOL/MODEL-controlled boundary.
A FastAPI/Flask route handler is a RESOURCE boundary driven by an HTTP client,
not by a model, so web-route-only paths are NOT_AGENT_REACHABLE and carry
`web_route: true`. The scanner itself treats resource boundaries as reachable;
that is a defensible product choice but a different question from the one this
study asks. The web-route count is reported separately so nothing is hidden.

AMBIGUOUS means the repository alone could not settle it. AMBIGUOUS is never
counted as safe and never enters the recall denominator.
"""
from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
R, N, A = "AGENT_REACHABLE", "NOT_AGENT_REACHABLE", "AMBIGUOUS"

# idx: (label, mechanism|reason, evidence, verified)
L: dict[int, tuple] = {
 # ---- AGENT_REACHABLE (path read hop by hop) ----
 6:  (R,"CALLBACK_REGISTRATION","AgentQLTools(Toolkit); tools.append(self.custom_scrape_website) agentql.py:36; sink inside the registered method","path"),
 7:  (R,"CALLBACK_REGISTRATION","AgentQLTools(Toolkit); tools.append(self.scrape_website) agentql.py:32; sink inside the registered method","path"),
 8:  (R,"CALLBACK_REGISTRATION","DaytonaTools(Toolkit); self.create_file registered in tools list daytona.py:115; sink in create_file:318","path"),
 9:  (R,"CALLBACK_REGISTRATION","DockerTools(Toolkit); self.start_container registered in tools list docker.py:82; sink in start_container:181","path"),
 10: (R,"CALLBACK_REGISTRATION","TelegramTools(Toolkit); tools.append(self.send_message) telegram.py:82; sink in send_message:118","path"),
 11: (R,"DYNAMIC_DISPATCH","Workspace(Toolkit) workspace.py:187 registers by NAME: alias map \"shell\"->\"run_command\" :250, sync_tools=[getattr(self,name) for name in registered] :287, super().__init__(tools=sync_tools) :303; sink in run_command:813","path"),
 18: (R,"DYNAMIC_DISPATCH","aider base_coder.py:2304 self.apply_edits(edits) on LLM-parsed edits; PatchCoder.apply_edits overrides and calls path_obj.unlink() patch_coder.py:589","path"),
 31: (R,"CROSS_MODULE_CALL","MultimodalWebSurfer executes MODEL tool calls via _execute_tool (:623,:628) which calls _playwright_controller.visit_page (:656/661/666/680) -> sink playwright_controller.py:210","path"),
 32: (R,"CROSS_MODULE_CALL","Same _execute_tool dispatch reaching PlaywrightController.fill_id -> sink playwright_controller.py:482","path"),
 53: (R,"MULTI_HOP_LOCAL_CALL","@self.server.call_tool() handle_call_tool cli_mcp.py:83; name=='browser_screenshot' -> self._screenshot:133 -> self._ensure_namespace:102 -> sink :105","path"),
 54: (R,"CALLBACK_REGISTRATION","handle_call_tool name=='browser_exec' -> asyncio.to_thread(self._execute, code) cli_mcp.py:91 (method passed BY REFERENCE, no call edge) -> sink _execute:128; code is arguments.get('code')","path"),
 66: (R,"LOCAL_HELPER_CALL","StagehandTool(BaseTool)._run:577 -> self._async_run(...) :613/:619/:660 -> sink :506","path"),
 89: (R,"LOCAL_HELPER_CALL","@tool grep_search file_search.py:209 -> self._ripgrep_search(...) :252 -> _ripgrep_search:292 -> sink :314","path"),
 91: (R,"LOCAL_HELPER_CALL","@tool(tool_name) file_tool anthropic_tools.py:716 -> self._handle_delete(...) :770 -> _handle_delete:1032 -> sink :1040","path"),
 102:(R,"CROSS_MODULE_CALL","@confluence_mcp.tool delete_attachment servers/confluence.py:2473 -> AttachmentsMixin.delete_attachment attachments.py:776 -> v2_adapter.delete_attachment :798 -> session.delete(url) v2_adapter.py:1383","path"),
 105:(R,"MULTI_HOP_LOCAL_CALL","@mcp.tool() remember memory.py:265 -> add_memory :271 -> new_memory.save(deps) :167 -> sink MemoryNode.save:116","path"),
 106:(R,"MULTI_HOP_LOCAL_CALL","@mcp.tool() remember :265 -> add_memory :271 -> merge_with :172 -> delete_memory(other.id) :146 -> sink :162","path"),
 111:(R,"SCHEMA_DISPATCH","@server.call_tool() call_tool server.py:487 -> match name case GitTools.SHOW :578 -> git_show(repo, arguments['revision']) :579 -> sink :230","path"),
 153:(R,"LLM_OUTPUT_TO_SINK","ToolOutputHandler.handle_tool_response(session, assistant_reply) output_handler.py:98; ReplaceTaskOutputHandler.handle calls eval(assistant_reply) :180 -- arbitrary code execution on raw model output","path"),
 154:(R,"CROSS_MODULE_CALL","DeleteFileTool(BaseTool)._execute delete_file.py:36 -> S3Helper().delete_file(final_path) :55 -> s3.delete_object s3_helper.py:107","path"),
 158:(R,"LOCAL_HELPER_CALL","ApolloSearchTool(BaseTool)._execute:57 -> self.apollo_search_results(...) :72 -> requests.post :127","path"),
 159:(R,"LOCAL_HELPER_CALL","SendEmailAttachmentTool(BaseTool)._execute:47 -> self.send_email_with_attachment(to,...) :82 -> smtp.send_message :141; recipient is agent-chosen","path"),

 # ---- NOT_AGENT_REACHABLE: build / CI / release / docs tooling ----
 23: (N,"build_tooling","aider benchmark harness, run from the repo not from an agent","site"),
 24: (N,"build_tooling","aider benchmark grid runner script","site"),
 25: (N,"build_tooling","aider scripts/recording_audio.py developer utility","site"),
 26: (N,"build_tooling","aider scripts/recording_audio.py main()","site"),
 27: (N,"build_tooling","aider scripts/update-history.py release tooling","site"),
 28: (N,"build_tooling","aider scripts/versionbump.py release tooling","site"),
 29: (N,"build_tooling","autogen fixup_generated_files.py codegen post-processing","site"),
 36: (N,"cli_entrypoint","autogenstudio cli.py ui command; operator CLI, no caller in repo","site"),
 42: (N,"cli_entrypoint","LiteStudio.shutdown_port; local dev server lifecycle","site"),
 63: (N,"cli_entrypoint","crewai checkpoint CLI inspection command","site"),
 64: (N,"cli_entrypoint","crewai kickoff_flow CLI command","site"),
 65: (N,"build_tooling","crewai_cli utils tree_find_and_replace invoked by ToolCommand.create (scaffolding CLI); BaseTool._run chain is a name collision on create()","path"),
 72: (N,"build_tooling","fastapi scripts/docs.py build_all","site"),
 73: (N,"build_tooling","fastapi scripts/label_approved.py CI script","site"),
 74: (N,"build_tooling","fastapi scripts/notify_translations.py CI script","site"),
 75: (N,"build_tooling","fastapi screenshot generation script","site"),
 76: (N,"build_tooling","fastapi scripts/sponsors.py CI script","site"),
 77: (N,"build_tooling","fastapi scripts/topic_repos.py CI script","site"),
 81: (N,"build_tooling","gpt-engineer scripts/clean_benchmarks.py","site"),
 82: (N,"build_tooling","gpt-engineer scripts/legacy_benchmark.py","site"),
 83: (N,"build_tooling","haystack .github/utils docs sync","site"),
 84: (N,"build_tooling","haystack .github/utils docs promotion","site"),
 85: (N,"build_tooling","haystack scripts/ruff_format_docs.py","site"),
 86: (N,"build_tooling","haystack scripts/ruff_format_docs.py","site"),
 93: (N,"build_tooling","llama-dev monorepo test tooling (_uv_sync)","site"),
 107:(N,"build_tooling","mcp-python-sdk README snippet updater","site"),
 109:(N,"build_tooling","mcp-servers scripts/release.py","site"),
 110:(N,"build_tooling","mcp-servers scripts/release.py","site"),
 118:(N,"build_tooling","metagpt setup.py InstallMermaidCLI; setuptools command. The Action.run chain is a name collision on run()","path"),
 119:(N,"build_tooling","open-interpreter .codex skill script gh_pr_watch","site"),
 120:(N,"build_tooling","open-interpreter .codex skill script issue digest","site"),
 121:(N,"build_tooling","open-interpreter codex-cli npm package build script","site"),
 122:(N,"build_tooling","open-interpreter provider catalog generator script","site"),
 123:(N,"build_tooling","openai-agents docs translation script","site"),
 131:(N,"build_tooling","openhands .github PR script","site"),
 138:(N,"build_tooling","openhands scripts/update_openapi.py","site"),
 139:(N,"build_tooling","pydantic-ai .github docs preview script","site"),
 141:(N,"build_tooling","pydantic-ai scripts/scrub_cassette.py test-fixture tooling","site"),
 152:(N,"build_tooling","superagi run_gui.py launcher","site"),
 155:(N,"infrastructure","superagi tool_helper.download_tool: toolkit INSTALLER, runs at deploy time","site"),
 157:(N,"infrastructure","superagi tool_manager.download_tool: toolkit installer, called from tool_manager:134","path"),

 # ---- NOT_AGENT_REACHABLE: control repos / general-purpose libraries ----
 60: (N,"control_library","click internal stream handling; click is a corpus CONTROL repo","site"),
 61: (N,"control_library","click pager implementation; control repo","site"),
 62: (N,"control_library","click temp-file pager; control repo","site"),
 78: (N,"control_library","flask tutorial example init_db; control repo","site"),
 79: (N,"control_library","flask CLI shell command; control repo","site"),
 143:(N,"control_library","requests atomic_open utility; control repo","site"),
 144:(N,"control_library","requests atomic_open utility; control repo","site"),
 145:(N,"control_library","rich ansi module; control repo","site"),
 146:(N,"control_library","rich Console.save_svg; control repo","site"),
 142:(N,"test_support","pydantic-ai tests/example_modules/bank_database.py support module","site"),

 # ---- NOT_AGENT_REACHABLE: LLM transport / auth / config internals ----
 16: (N,"llm_transport","aider Coder.run_stream: the LLM call itself, endpoint fixed by config","site"),
 17: (N,"llm_transport","aider Coder.run_one: LLM call loop","site"),
 21: (N,"auth_flow","aider onboarding OAuth code exchange","site"),
 34: (N,"config_load","autogen AnthropicBedrock _from_config component deserialization","site"),
 35: (N,"config_load","autogen OpenAI _from_config component deserialization","site"),
 51: (N,"llm_transport","browser-use ChatAnthropicBedrock.ainvoke; provider call, fixed endpoint","site"),
 52: (N,"llm_transport","browser-use ChatMistral._post; provider call","site"),
 68: (N,"config_load","crewai AgentCardSigningConfig.get_private_key; signing key load","site"),
 90: (N,"config_load","langchain ChatAnthropic._client_params secret read","site"),
 92: (N,"auth_flow","langchain chatgpt_oauth _apost_form","site"),
 94: (N,"config_load","llamaindex WatsonxEmbeddings.__init__ credential read","site"),
 97: (N,"llm_transport","llamaindex vertex _completion_with_retry; provider call","site"),
 104:(N,"llm_transport","mcp-python-sdk simple-chatbot LLMClient.get_response; provider call","site"),
 108:(N,"framework_internal","mcp-python-sdk win32 stdio transport fallback","site"),
 133:(N,"auth_flow","openhands TokenManager bitbucket token refresh","site"),
 147:(N,"config_load","semantic-kernel OpenAIResponsesAgent.setup_resources credential read","site"),
 148:(N,"framework_internal","semantic-kernel SequentialAgentActor internal message passing between orchestration actors","site"),
 149:(N,"llm_transport","semantic-kernel realtime create_session; provider WebRTC setup","site"),
 151:(N,"not_registered","semantic-kernel SessionsPythonTool.download_file is NOT decorated @kernel_function (cf. :261/:329/:386), so the model cannot invoke it","path"),
 41: (N,"infrastructure","autogenstudio SchemaManager.ensure_schema_up_to_date; migration at startup","site"),
 50: (N,"framework_internal","browser-use BrowserProfile._download_extension; profile setup","site"),
 55: (N,"framework_internal","browser-use TokenCost cache housekeeping","site"),
 56: (N,"framework_internal","browser-use get_git_info diagnostics","site"),
 69: (N,"framework_internal","crewai a2a PollingHandler.execute; the BaseTool._run chain is a name collision on execute()","path"),
 71: (N,"trusted_config","crewai ScriptAction._compile_handler exec() runs DEVELOPER-authored flow YAML, gated by CREWAI_ALLOW_FLOW_SCRIPT_EXECUTION; not model input (source comment :268-274)","path"),
 96: (N,"framework_internal","llamaindex gaudi setup_distributed_model; model init","site"),
 114:(N,"research_harness","metagpt SELA experiment runner; Action.run chain is a name collision","site"),
 19: (N,"dead_helper","aider search_replace git_cherry_pick helper, no caller in repo","site"),
 20: (N,"dead_helper","aider search_replace git_cherry_pick helper, no caller in repo","site"),
 14: (N,"infrastructure","agno_infra AWS RDS provisioning library","site"),
 15: (N,"infrastructure","agno_infra AWS SecretsManager provisioning library","site"),
 0:  (N,"demo_script","agno cookbook AgentOS studio demo","site"),
 1:  (N,"demo_script","agno cookbook streaming demo, module level","site"),
 47: (N,"demo_script","browser-use actor playground flights demo","site"),
 48: (N,"demo_script","browser-use actor playground mixed automation demo","site"),
 124:(N,"demo_script","openai-agents example launches a local SSE server","site"),
 126:(N,"demo_script","openai-agents sandbox example main()","site"),
 140:(N,"demo_script","pydantic-ai bank_support example, module level","site"),
 80: (N,"framework_internal","gpt-engineer Config.to_toml serializer, no caller","site"),

 # ---- NOT_AGENT_REACHABLE: web route only (HTTP client, not model) ----
 3:  (N,"web_route_only","agno SurrealDb.clear_memories reached only via router.delete chain","site"),
 30: (N,"web_route_only","autogen BaseGroupChat.run_stream; app.get chain","site"),
 33: (N,"web_route_only","autogen ACA dynamic sessions executor; app.get chain","site"),
 37: (N,"web_route_only","autogenstudio DatabaseManager.reset_db; app.post chain","site"),
 38: (N,"web_route_only","autogenstudio DatabaseManager.upsert <- gallery.py router POST","path"),
 39: (N,"web_route_only","autogenstudio DatabaseManager.get <- router GET","site"),
 40: (N,"web_route_only","autogenstudio DatabaseManager.delete <- @router.delete gallery.py:62 db.delete(Gallery,...) :69","path"),
 43: (N,"web_route_only","autogenstudio MCPWebSocketBridge elicitation response; websocket route","site"),
 98: (N,"web_route_only","llamaindex AzStorageBlobReader; router.post chain via ReaderConfig","site"),
 99: (N,"web_route_only","llamaindex BoardDocsReader; router.post chain","site"),
 100:(N,"web_route_only","llamaindex IMDB scraper; router.post chain","site"),
 112:(N,"web_route_only","metagpt DABench example driven by app.route","site"),
 115:(N,"web_route_only","metagpt spo app.py streamlit/route driven","site"),
 125:(N,"web_route_only","openai-agents realtime example websocket server","site"),
 132:(N,"web_route_only","openhands SlackManager.start_job via integration webhook route","site"),
 134:(N,"web_route_only","openhands ApiKeyStore.create_api_key <- provision_user route","site"),
 135:(N,"web_route_only","openhands SaasSettingsStore.load <- router.get","site"),
 136:(N,"web_route_only","openhands UserStore.migrate_user <- router.post chain","site"),
 137:(N,"web_route_only","openhands DockerSandboxService.get_sandbox <- router.post","site"),
 156:(N,"web_route_only","superagi Agent.create_agent_with_config <- router.post","site"),

 # ---- AMBIGUOUS ----
 2:  (A,"unresolved_db_layer","agno postgres utils ais_table_available; DB helper, no concrete agent path in repo","site"),
 4:  (A,"unresolved_db_layer","agno DbFileSystem.move; storage layer reachable from several callers, none an agent boundary in-repo","site"),
 5:  (A,"framework_router","agno AgentOS telegram interface helper sends agent output; entry is an inbound webhook, model controls the text but not the sink target","site"),
 12: (A,"unresolved_utility","agno utils.media.download_file; 19 callers, none traced to a registered tool","site"),
 13: (A,"unresolved_utility","agno utils.shell.run_shell_command; only a docstring reference found, no resolvable caller","path"),
 22: (A,"unresolved_input","aider Scraper.scrape_with_playwright <- Scraper.scrape:107; could not establish whether url is model- or user-supplied","path"),
 44: (A,"sample_app","autogen gitty sample DB layer","site"),
 45: (A,"sample_app","autogen gitty sample DB layer","site"),
 46: (A,"sample_app","autogen gitty sample shells out to gh; no caller found","site"),
 49: (A,"unresolved_framework","browser-use CloudBrowserClient.stop_browser; chain to call_tool passes through generic close()","site"),
 57: (A,"sample_app","browser-use msg-use example scheduler","site"),
 58: (A,"sample_app","browser-use news-use example save_article","site"),
 59: (A,"sample_app","browser-use custom-functions file_upload example","site"),
 67: (A,"unresolved_framework","crewai OAuth2ClientCredentials._fetch_token; a2a auth, agent-initiated a2a calls possible but unproven","site"),
 70: (A,"unresolved_framework","crewai SQLiteFlowPersistence._save_state_sql; flow persistence, BaseTool chain is generic","site"),
 87: (A,"unresolved_framework","langchain natbot Crawler.go_to_page; natbot chain drives a browser from LLM output but no caller found in repo","site"),
 88: (A,"unresolved_framework","langchain SQLRecordManager.adelete_keys; indexing API callable from a pipeline","site"),
 95: (A,"unresolved_framework","llamaindex TiDBPropertyGraphStore.upsert_nodes; vector store write reachable from RAG tooling","site"),
 101:(A,"unresolved_framework","llamaindex Oracle drop_table_purge; chain via LoadAndSearchToolSpec.load is generic","site"),
 103:(A,"unresolved_framework","mcp-atlassian AttachmentsMixin.download_attachment; sibling of a confirmed tool path but its own tool wrapper not located","site"),
 113:(A,"unresolved_framework","metagpt MinecraftExtEnv.pause; env control surface","site"),
 116:(A,"unresolved_framework","metagpt GitRepository.create_pull; plausible agent action, no concrete path","site"),
 117:(A,"unresolved_framework","metagpt mermaid_to_file via WritePRD; Action.run chain plausible but passes through generic run()","site"),
 127:(A,"sample_app","openai-agents computer_use example; LocalPlaywrightComputer used as a computer tool","site"),
 128:(A,"unresolved_framework","openai-agents AdvancedSQLiteSession._copy_sync; no caller found","site"),
 129:(A,"unresolved_framework","openai-agents FuseMountPattern.apply; _LoadSkillTool.run chain passes through generic load/run","site"),
 130:(A,"unresolved_framework","openai-agents BaseSandboxSession.mkdir; sandbox sessions are agent-driven but the traced chain is an app.post route","site"),
 150:(A,"unresolved_framework","semantic-kernel SqlServerCollection.ensure_collection_exists; kernel_function chain passes through generic create_collection","site"),
}


def main() -> int:
    sample = json.loads((HERE / "sample.json").read_text())["rows"]
    ev = {e["id"]: e for e in json.loads((HERE / "evidence.json").read_text())}
    missing = [i for i in range(len(sample)) if i not in L]
    if missing:
        raise SystemExit(f"UNLABELLED indices: {missing}")
    out = []
    for i, r in enumerate(sample):
        lab, mech, evid, ver = L[i]
        out.append({
            "idx": i, "id": r["id"], "repo": r["repo"], "repo_name": r["repo_name"],
            "sha": r["sha"], "file": r["file"], "line": r["line"],
            "rule_id": r["rule_id"], "category": r["category"], "tier": r["tier"],
            "repo_category": r["repo_category"],
            "enclosing_function": r["enclosing_function"],
            "enclosing_class": r["enclosing_class"],
            "stratum": r["stratum"], "weight": r["weight"],
            "label": lab,
            "mechanism": mech if lab == R else None,
            "reason": None if lab == R else mech,
            "evidence": evid,
            "verified": ver,
            "web_route": (mech == "web_route_only"),
            "actenon_detected": False,  # by construction: every row scored 'none'
        })
    (HERE / "labels.json").write_text(json.dumps(out, indent=1))
    from collections import Counter
    c = Counter(x["label"] for x in out)
    print(f"labelled {len(out)}: " + "  ".join(f"{k}={v}" for k, v in c.most_common()))
    print(f"  verified by full path: {sum(1 for x in out if x['verified']=='path')}")
    print(f"  web-route-only (inside NOT): {sum(1 for x in out if x['web_route'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
