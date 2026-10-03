"""Structured authority evidence (actenon_scan.authority).

Each case is a small project written to a temp directory; the assertions are on the structured fields
(action, resource, resource_state, provenance), never on source text.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from actenon_scan.authority import HOLE, ResourceState, classify_http, extract_authority, resource_matches


def scan(tmp_path: Path, files: dict[str, str], env: dict[str, str] | None = None, **kw):
    for name, src in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(src))
    return extract_authority(tmp_path, env=env or {}, **kw)


def entries(report, *, reads=True):
    return {(e.action, e.resource, e.resource_state.value) for e in report.evidence
            if reads or e.action != "github.repo.read"}


def writes(report):
    return [e for e in report.evidence if e.action != "github.repo.read"]


# --- the four limitations of the finding-oriented scanner -------------------------------------------


def test_requests_request_with_literal_method_is_visible(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import requests
        def go():
            requests.request("DELETE", "https://api.example.com/sessions/1")
    """})
    assert entries(r) == {("http.delete", "api.example.com/sessions/1", "RESOLVED")}
    assert r.evidence[0].via == "requests.request"


def test_requests_request_with_dynamic_method_is_http_request(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import requests
        def go(method):
            requests.request(method, "https://api.example.com/items")
    """})
    (ev,) = r.evidence
    assert ev.action == "http.request" and ev.resource == "api.example.com/items"


def test_call_is_never_truncated(tmp_path):
    long_path = "/".join(["segment"] * 40)
    r = scan(tmp_path, {"a.py": f"""
        import requests
        def go():
            requests.post("https://hooks.example.com/{long_path}", json={{"a": 1}}, timeout=30)
    """})
    (ev,) = r.evidence
    assert len(ev.call) > 200 and ev.call.endswith("timeout=30)")
    assert ev.resource == f"hooks.example.com/{long_path}"


def test_structured_target_fields(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import requests
        BASE = "https://api.example.com"
        def go():
            requests.put(BASE + "/v2/widgets", json={})
    """})
    (ev,) = r.evidence
    assert (ev.action, ev.resource, ev.method, ev.url) == ("http.put", "api.example.com/v2/widgets", "put", "https://api.example.com/v2/widgets")
    assert any(s.kind == "constant" and s.name == "BASE" for s in ev.sources)
    assert ev.file == "a.py" and ev.line == 5 and ev.function == "go"


def test_pygithub_capabilities_map_to_github_actions(tmp_path):
    r = scan(tmp_path, {"bot.py": """
        import os
        from github import Github
        gh = Github(os.environ["GITHUB_TOKEN"])
        REPO = "acme/support"
        def triage(title, number):
            repo = gh.get_repo(REPO)
            repo.create_issue(title=title)
            repo.get_issue(number).create_comment("thanks")
            repo.get_pull(number).merge()
            repo.delete_file("docs/x.md", "rm", "sha")
        def nuke():
            gh.get_repo("acme/project").delete()
        def make():
            gh.get_organization("acme").create_repo("new")
            gh.get_user().create_repo("mine")
    """})
    assert {e for e in entries(r) if e[0] == "github.repo.read"} == {
        ("github.repo.read", "github.com/acme/support", "RESOLVED"), ("github.repo.read", "github.com/acme/project", "RESOLVED")}
    assert entries(r, reads=False) == {
        ("github.issue.create", "github.com/acme/support", "RESOLVED"),
        ("github.issue.comment", "github.com/acme/support", "RESOLVED"),
        ("github.pull.merge", "github.com/acme/support", "RESOLVED"),
        ("github.contents.delete", "github.com/acme/support", "RESOLVED"),
        ("github.repo.delete", "github.com/acme/project", "RESOLVED"),
        ("github.repo.create", "github.com/acme", "RESOLVED"),
        ("github.repo.create", "github.com", "RESOLVED"),
    }


# --- dynamic authority stays unresolved -----------------------------------------------------------


def test_tool_parameter_host_is_unresolved_not_wildcard(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import requests
        from langchain_core.tools import tool
        @tool
        def post_anywhere(url: str, body: dict):
            return requests.post(url, json=body)
    """})
    (ev,) = r.evidence
    assert ev.resource is None and ev.resource_state is ResourceState.UNRESOLVED
    assert ev.unresolved_parts == ("host",) and ev.tool_entry
    assert "parameter of tool function 'url'" in ev.reason


def test_unknown_repository_is_unresolved(tmp_path):
    r = scan(tmp_path, {"a.py": """
        from github import Github
        def act(name):
            Github().get_repo(name).create_issue(title="x")
        act_ref = act
    """})
    (ev,) = writes(r)
    assert ev.action == "github.issue.create" and ev.resource is None and ev.unresolved_parts == ("repository",)


def test_dynamic_path_segment_is_template(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import requests
        def remove(session_id):
            requests.delete(f"https://api.example.com/sessions/{session_id}")
        handlers = [remove]
    """})
    (ev,) = r.evidence
    assert ev.resource == "api.example.com/sessions/{}" and ev.resource_state is ResourceState.TEMPLATE
    assert ev.template_params == ("session_id",)


def test_reassigned_variable_is_not_guessed(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import requests
        def go(flag):
            url = "https://a.example.com/x"
            if flag:
                url = "https://b.example.com/y"
            requests.post(url)
    """})
    (ev,) = r.evidence
    assert ev.resource is None and ev.resource_state is ResourceState.UNRESOLVED


# --- interprocedural resolution -------------------------------------------------------------------


def test_helper_parameters_resolved_at_each_call_site(tmp_path):
    r = scan(tmp_path, {"client.py": """
        import requests
        def _post(path, payload):
            return requests.post("https://api.example.com" + path, json=payload)
    """, "agent.py": """
        from client import _post
        def run():
            _post("/v1/tickets", {})
            _post("/v1/notes", {})
    """})
    assert entries(r) == {("http.post", "api.example.com/v1/tickets", "RESOLVED"), ("http.post", "api.example.com/v1/notes", "RESOLVED")}
    assert all(ev.call_path[-1] == "_post" and ev.call_path[0] == "run" for ev in r.evidence)


def test_self_attributes_from_constructor_argument(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import httpx
        class Notifier:
            def __init__(self, base):
                self.base = base
                self.client = httpx.Client()
            def notify(self, text):
                self.client.post(f"{self.base}/notify", json={"text": text})
        n = Notifier("https://alerts.example.com/api")
    """})
    assert entries(r) == {("http.post", "alerts.example.com/api/notify", "RESOLVED")}


def test_httpx_client_base_url(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import httpx
        client = httpx.Client(base_url="https://api.example.com/v1")
        def go():
            client.patch("/users/me", json={})
    """})
    assert entries(r) == {("http.patch", "api.example.com/v1/users/me", "RESOLVED")}


# --- configuration ----------------------------------------------------------------------------------


def test_env_values_resolve_with_provenance(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import os
        from github import Github
        def go():
            Github().get_repo(os.environ["GITHUB_REPOSITORY"]).create_issue(title="t")
    """, ".env": "GITHUB_REPOSITORY=acme/support\n"})
    (ev,) = writes(r)
    assert ev.resource == "github.com/acme/support"
    assert any(s.kind == "env" and s.name == "GITHUB_REPOSITORY" for s in ev.sources)
    assert r.env_files == [".env"]


def test_unset_env_without_default_is_unresolved(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import os, requests
        def go():
            requests.post(os.getenv("TARGET_URL"))
    """})
    (ev,) = r.evidence
    assert ev.resource_state is ResourceState.UNRESOLVED and "TARGET_URL is not set" in ev.reason


def test_secret_env_values_are_never_inlined(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import os, requests
        def go():
            requests.post(os.environ["SLACK_WEBHOOK_URL"], json={})
    """}, env={"SLACK_WEBHOOK_URL": "https://hooks.slack.com/services/T0/B0/SECRETSECRET"})
    (ev,) = r.evidence
    assert ev.resource is None and "SECRET" not in repr(ev.to_dict())


def test_openai_client_base_url_from_env(tmp_path):
    r = scan(tmp_path, {"a.py": """
        from openai import OpenAI
        client = OpenAI()
        def ask():
            client.chat.completions.create(model="m", messages=[])
    """}, env={"OPENAI_BASE_URL": "https://llm.internal.example/v1"})
    assert entries(r) == {("http.post", "llm.internal.example/v1/chat/completions", "RESOLVED")}


# --- files, processes, mail ---------------------------------------------------------------------------


def test_file_writes_and_deletes(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import os, shutil
        from pathlib import Path
        OUT = Path("reports")
        def go(name):
            with open("logs/run.log", "a") as f:
                f.write("x")
            (OUT / "summary.md").write_text("y")
            open(f"reports/{name}.txt", "w")
            open("config.json")
            os.remove("cache/old.db")
            shutil.rmtree(name)
        handlers = [go]
    """})
    assert entries(r) == {
        ("filesystem.write", "./logs/run.log", "RESOLVED"),
        ("filesystem.write", "./reports/summary.md", "RESOLVED"),
        ("filesystem.write", "./reports/{}.txt", "TEMPLATE"),
        ("filesystem.delete", "./cache/old.db", "RESOLVED"),
        ("filesystem.delete", None, "UNRESOLVED"),
    }


def test_process_execution(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import subprocess, os
        def go(cmd):
            subprocess.run(["git", "push", "origin", "main"])
            os.system("rm -rf build")
            subprocess.run(cmd, shell=True)
        handlers = [go]
    """})
    assert entries(r) == {("process.exec", "git", "RESOLVED"), ("process.exec", "rm", "RESOLVED"), ("process.exec", None, "UNRESOLVED")}


def test_reads_are_not_reported(tmp_path):
    r = scan(tmp_path, {"a.py": """
        from pathlib import Path
        def go():
            open("data.csv").read()
            Path("x.txt").read_text()
    """})
    assert r.evidence == []


def test_tests_are_excluded_by_default(tmp_path):
    files = {"tests/test_x.py": "import requests\nrequests.post('https://x.example.com/a')\n"}
    assert scan(tmp_path, files).evidence == []
    assert len(extract_authority(tmp_path, include_tests=True).evidence) == 1


def test_parse_errors_are_reported_not_fatal(tmp_path):
    r = scan(tmp_path, {"bad.py": "def (:\n", "good.py": "import requests\nrequests.post('https://x.example.com/a')\n"})
    assert r.parse_errors and r.parse_errors[0]["file"] == "bad.py"
    assert entries(r) == {("http.post", "x.example.com/a", "RESOLVED")}


# --- route vocabulary (shared with runtime enforcement) ---------------------------------------------


@pytest.mark.parametrize("method,url,action,resource", [
    ("POST", "https://api.github.com/repos/acme/support/issues", "github.issue.create", "github.com/acme/support"),
    ("DELETE", "https://api.github.com/repos/acme/project", "github.repo.delete", "github.com/acme/project"),
    ("PUT", "https://api.github.com/repos/o/r/contents/a/b.md", "github.contents.write", "github.com/o/r"),
    ("GET", "https://api.github.com/repos/o/r/issues?state=open", "github.repo.read", "github.com/o/r"),
    ("POST", "https://api.github.com/orgs/acme/repos", "github.repo.create", "github.com/acme"),
    ("POST", "https://api.openai.com:443/v1/chat/completions", "http.post", "api.openai.com/v1/chat/completions"),
    ("DELETE", "https://api.example.com/sessions/42?force=1", "http.delete", "api.example.com/sessions/42"),
])
def test_classify_http(method, url, action, resource):
    a = classify_http(method, url)
    assert (a.action, a.resource, a.state) == (action, resource, ResourceState.RESOLVED)


def test_classify_http_unknown_parts_never_widen():
    a = classify_http("post", f"https://api.github.com/repos/{HOLE}/issues")
    assert a.action == "github.issue.create" and a.resource is None and a.state is ResourceState.UNRESOLVED
    b = classify_http("post", f"https://{HOLE}/x")
    assert b.resource is None and b.unresolved_parts == ("host",)


def test_resource_matching_is_exact_or_single_segment_template():
    assert resource_matches("api.example.com/sessions/{}", "api.example.com/sessions/42")
    assert not resource_matches("api.example.com/sessions/{}", "api.example.com/sessions/42/keys")
    assert not resource_matches("api.example.com/sessions/{}", "api.example.com/sessions/..")
    assert not resource_matches("api.example.com/sessions", "api.example.com/sessions/42")
    assert not resource_matches("github.com/acme/support", "github.com/acme/support-evil")
    assert resource_matches("./reports/{}.txt", "./reports/june.txt")
    assert not resource_matches("./reports/{}.txt", "./reports/.txt")


def test_litellm_known_model_maps_to_provider_and_unknown_stays_unresolved(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import litellm
        def ask(messages, model):
            litellm.completion(model="gpt-4o", messages=messages)
            litellm.completion(model="anthropic/claude-sonnet-4", messages=messages)
            litellm.acompletion(model=model, messages=messages)
        handlers = [ask]
    """})
    assert entries(r) == {
        ("http.post", "api.openai.com/v1/chat/completions", "RESOLVED"),
        ("http.post", "api.anthropic.com/v1/messages", "RESOLVED"),
        ("http.post", None, "UNRESOLVED"),
    }
    (u,) = [e for e in r.evidence if e.resource is None]
    assert u.unresolved_parts == ("provider",) and u.via == "litellm.acompletion"


def test_object_kinds_join_across_assignments_and_factory_methods(tmp_path):
    r = scan(tmp_path, {"p.py": """
        from github import Github, Auth
        class Provider:
            def __init__(self, url):
                self.repo_obj = None
                self.client = self._client()
                self.repo = url.split("/")[-2]
            def _client(self):
                if True:
                    return Github(auth=Auth.Token("t"))
                return Github()
            def _repo(self):
                if self.repo_obj is None:
                    self.repo_obj = self.client.get_repo(self.repo)
                return self.repo_obj
            def comment(self, n, body):
                self._repo().get_pull(n).create_issue_comment(body)
    """})
    (ev,) = writes(r)
    assert ev.action == "github.issue.comment" and ev.resource_state is ResourceState.UNRESOLVED
    assert ev.unresolved_parts == ("repository",)


def test_pygithub_reads_need_repo_read(tmp_path):
    r = scan(tmp_path, {"a.py": """
        from github import Github
        def go(n):
            repo = Github().get_repo("acme/support")
            repo.get_pull(n).get_files()
        h = [go]
    """})
    assert ("github.repo.read", "github.com/acme/support", "RESOLVED") in entries(r)


def test_pygithub_raw_requester_and_object_urls(tmp_path):
    r = scan(tmp_path, {"a.py": """
        from github import Github
        REPO = "acme/support"
        def label(n, kinds):
            pr = Github().get_repo(REPO).get_pull(n)
            pr._requester.requestJsonAndCheck("PUT", f"{pr.issue_url}/labels", input=kinds)
            pr._requester.requestJsonAndCheck("POST", "/graphql", input={})
        h = [label]
    """})
    assert ("github.issue.label", "github.com/acme/support", "RESOLVED") in entries(r)
    assert ("github.graphql", "github.com", "RESOLVED") in entries(r)


def test_unknown_segments_before_the_last_are_unresolved_not_templates(tmp_path):
    r = scan(tmp_path, {"a.py": """
        import requests
        def go(ws, repo, item):
            requests.post(f"https://api.bitbucket.org/2.0/repositories/{ws}/{repo}/src")
            requests.delete(f"https://api.github.com/repos/{repo}/pulls/1/reviews/{item}")
            requests.delete(f"https://api.example.com/sessions/{item}")
            open(f"out/{ws}/report.txt", "w")
        h = [go]
    """})
    by = {(e.action, e.url.split('/')[2] if e.url else e.via): e for e in r.evidence}
    states = sorted((e.action, e.resource, e.resource_state.value, e.unresolved_parts) for e in r.evidence)
    assert ("http.post", None, "UNRESOLVED", ("path",)) in states
    assert ("github.pull.review", None, "UNRESOLVED", ("owner", "repository")) in states or \
           ("http.delete", None, "UNRESOLVED", ("repository",)) in states
    assert ("http.delete", "api.example.com/sessions/{}", "TEMPLATE", ()) in states
    assert ("filesystem.write", None, "UNRESOLVED", ("path",)) in states
    assert all("{}" not in (e.resource or "")[:-2] for e in r.evidence)
