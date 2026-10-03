"""Library API -> effect tables used by the Python authority extractor.

Each table maps a canonical callee (``module.Class.method`` after import resolution) to the effect it
performs. HTTP effects are named through ``routes.classify_http`` so static and runtime agree.
"""

from __future__ import annotations

HTTP_VERBS = ("get", "post", "put", "patch", "delete", "head", "options")

# Plain HTTP client functions/methods: canonical callee -> (method or None = taken from an argument,
# index of the URL positional argument, index of the method positional argument or None).
HTTP_CALLS: dict[str, tuple[str | None, int, int | None]] = {}
for _verb in HTTP_VERBS:
    for _prefix in ("requests", "requests.Session", "requests.sessions.Session", "httpx", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession"):
        HTTP_CALLS[f"{_prefix}.{_verb}"] = (_verb, 0, None)
for _prefix in ("requests", "requests.Session", "requests.sessions.Session", "httpx", "httpx.Client", "httpx.AsyncClient", "aiohttp.ClientSession"):
    HTTP_CALLS[f"{_prefix}.request"] = (None, 1, 0)
HTTP_CALLS["httpx.Client.stream"] = (None, 1, 0)
HTTP_CALLS["httpx.AsyncClient.stream"] = (None, 1, 0)
HTTP_CALLS["httpx.stream"] = (None, 1, 0)

# Constructors that create an HTTP client object; value = keyword holding a base URL (or None).
HTTP_CLIENT_CONSTRUCTORS: dict[str, str | None] = {
    "requests.Session": None,
    "requests.session": None,
    "requests.sessions.Session": None,
    "httpx.Client": "base_url",
    "httpx.AsyncClient": "base_url",
    "aiohttp.ClientSession": "base_url",
}

# LLM provider SDKs: constructor -> (default base URL, env var overriding it, constructor kwarg).
LLM_CLIENTS: dict[str, tuple[str, str, str]] = {
    "openai.OpenAI": ("https://api.openai.com/v1", "OPENAI_BASE_URL", "base_url"),
    "openai.AsyncOpenAI": ("https://api.openai.com/v1", "OPENAI_BASE_URL", "base_url"),
    "anthropic.Anthropic": ("https://api.anthropic.com", "ANTHROPIC_BASE_URL", "base_url"),
    "anthropic.AsyncAnthropic": ("https://api.anthropic.com", "ANTHROPIC_BASE_URL", "base_url"),
    "langchain_openai.ChatOpenAI": ("https://api.openai.com/v1", "OPENAI_BASE_URL", "base_url"),
    "langchain_openai.OpenAIEmbeddings": ("https://api.openai.com/v1", "OPENAI_BASE_URL", "base_url"),
    "langchain_anthropic.ChatAnthropic": ("https://api.anthropic.com", "ANTHROPIC_BASE_URL", "base_url"),
}
# Methods on those clients: attribute path after the client -> (HTTP method, path appended to the base).
LLM_METHODS: dict[str, dict[str, tuple[str, str]]] = {
    "openai": {
        "chat.completions.create": ("post", "/chat/completions"),
        "beta.chat.completions.parse": ("post", "/chat/completions"),
        "chat.completions.parse": ("post", "/chat/completions"),
        "responses.create": ("post", "/responses"),
        "completions.create": ("post", "/completions"),
        "embeddings.create": ("post", "/embeddings"),
        "images.generate": ("post", "/images/generations"),
        "moderations.create": ("post", "/moderations"),
        "audio.speech.create": ("post", "/audio/speech"),
        "audio.transcriptions.create": ("post", "/audio/transcriptions"),
    },
    "anthropic": {
        "messages.create": ("post", "/v1/messages"),
        "messages.stream": ("post", "/v1/messages"),
        "beta.messages.create": ("post", "/v1/messages"),
    },
    # LangChain chat models: any invocation is one completion request.
    "langchain_openai.ChatOpenAI": {m: ("post", "/chat/completions") for m in ("invoke", "ainvoke", "stream", "astream", "batch", "abatch", "predict", "__call__")},
    "langchain_openai.OpenAIEmbeddings": {m: ("post", "/embeddings") for m in ("embed_documents", "embed_query", "aembed_documents", "aembed_query")},
    "langchain_anthropic.ChatAnthropic": {m: ("post", "/v1/messages") for m in ("invoke", "ainvoke", "stream", "astream", "batch", "abatch")},
}

# PyGithub object model. Constructors and accessor methods produce typed objects; mutating methods map to
# the route vocabulary's GitHub actions. ``repo`` means the resource is the object's repository.
PYGITHUB_CONSTRUCTORS = ("github.Github", "github.MainClass.Github")
# (object kind, method) -> resulting object kind, for accessors
PYGITHUB_ACCESSORS: dict[tuple[str, str], str] = {
    ("Github", "get_repo"): "Repository",
    ("Github", "get_user"): "AuthenticatedUser",
    ("Github", "get_organization"): "Organization",
    ("Organization", "get_repo"): "Repository",
    ("AuthenticatedUser", "get_repo"): "Repository",
    ("Repository", "get_issue"): "Issue",
    ("Repository", "get_pull"): "PullRequest",
    ("Repository", "get_git_ref"): "GitRef",
    ("Repository", "get_release"): "GitRelease",
    ("Repository", "get_label"): "Label",
    ("Repository", "create_issue"): "Issue",
    ("Repository", "create_pull"): "PullRequest",
    ("PullRequest", "as_issue"): "Issue",
}
PYGITHUB_EFFECTS: dict[tuple[str, str], str] = {
    ("Repository", "create_issue"): "github.issue.create",
    ("Repository", "create_pull"): "github.pull.create",
    ("Repository", "create_file"): "github.contents.write",
    ("Repository", "update_file"): "github.contents.write",
    ("Repository", "delete_file"): "github.contents.delete",
    ("Repository", "delete"): "github.repo.delete",
    ("Repository", "edit"): "github.repo.update",
    ("Repository", "create_git_ref"): "github.ref.create",
    ("Repository", "create_git_blob"): "github.git.write",
    ("Repository", "create_git_tree"): "github.git.write",
    ("Repository", "create_git_commit"): "github.git.write",
    ("Repository", "create_git_tag"): "github.git.write",
    ("Repository", "create_git_release"): "github.release.create",
    ("Repository", "create_fork"): "github.repo.fork",
    ("Repository", "add_to_collaborators"): "github.collaborator.add",
    ("Repository", "remove_from_collaborators"): "github.collaborator.remove",
    ("Repository", "create_hook"): "github.webhook.create",
    ("Repository", "create_label"): "github.label.create",
    ("Repository", "merge"): "github.branch.merge",
    ("Repository", "create_secret"): "github.secret.write",
    ("Repository", "create_repository_dispatch"): "github.workflow.dispatch",
    ("Repository", "create_deployment"): "github.deployment.create",
    ("Repository", "create_check_run"): "github.check.create",
    ("Issue", "create_comment"): "github.issue.comment",
    ("Issue", "edit"): "github.issue.update",
    ("Issue", "add_to_labels"): "github.issue.label",
    ("Issue", "set_labels"): "github.issue.label",
    ("Issue", "remove_from_labels"): "github.issue.label",
    ("Issue", "add_to_assignees"): "github.issue.assign",
    ("PullRequest", "set_labels"): "github.issue.label",
    ("PullRequest", "add_to_labels"): "github.issue.label",
    ("PullRequest", "remove_from_labels"): "github.issue.label",
    ("PullRequest", "add_to_assignees"): "github.issue.assign",
    ("Issue", "lock"): "github.issue.lock",
    ("PullRequest", "merge"): "github.pull.merge",
    ("PullRequest", "edit"): "github.pull.update",
    ("PullRequest", "create_review"): "github.pull.review",
    ("PullRequest", "create_issue_comment"): "github.issue.comment",
    ("PullRequest", "create_review_comment"): "github.pull.comment",
    ("PullRequest", "create_comment"): "github.pull.comment",
    ("PullRequest", "create_review_request"): "github.pull.request_review",
    ("GitRef", "delete"): "github.ref.delete",
    ("GitRef", "edit"): "github.ref.update",
    ("GitRelease", "delete_release"): "github.release.delete",
    ("GitRelease", "update_release"): "github.release.update",
    ("AuthenticatedUser", "create_repo"): "github.repo.create",
    ("Organization", "create_repo"): "github.repo.create",
    ("AuthenticatedUser", "create_gist"): "github.gist.create",
}

FILE_WRITE_FUNCS = {
    "shutil.copy": 1, "shutil.copy2": 1, "shutil.copyfile": 1, "shutil.move": 1, "shutil.copytree": 1,
    "os.rename": 1, "os.replace": 1,
}
FILE_DELETE_FUNCS = {"os.remove": 0, "os.unlink": 0, "os.rmdir": 0, "shutil.rmtree": 0, "os.removedirs": 0}
PATH_WRITE_METHODS = {"write_text", "write_bytes", "touch", "mkdir"}
PATH_DELETE_METHODS = {"unlink", "rmdir"}

PROCESS_FUNCS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
    "os.system", "os.popen", "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell",
    "os.execv", "os.execvp", "os.execl", "os.execlp", "os.spawnl", "os.spawnv",
}

SMTP_CONSTRUCTORS = ("smtplib.SMTP", "smtplib.SMTP_SSL")
SMTP_SEND_METHODS = ("sendmail", "send_message")

TOOL_DECORATOR_HINTS = ("tool", "function_tool", "action", "kernel_function", "skill")

SECRET_NAME_HINTS = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "PRIVATE", "CREDENTIAL", "WEBHOOK", "AUTH")

# LiteLLM: the provider (and so the host) is chosen by the model string.
LITELLM_FUNCS = {
    "litellm.completion", "litellm.acompletion", "litellm.text_completion", "litellm.atext_completion",
    "litellm.main.completion", "litellm.main.acompletion", "litellm.responses", "litellm.aresponses",
}
LITELLM_EMBED_FUNCS = {"litellm.embedding", "litellm.aembedding"}
# model prefix -> (chat completion URL, embedding URL)
LITELLM_PROVIDERS: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("openai/", "gpt-", "o1", "o3", "o4", "chatgpt-", "text-embedding-"), "https://api.openai.com/v1/chat/completions", "https://api.openai.com/v1/embeddings"),
    (("anthropic/", "claude"), "https://api.anthropic.com/v1/messages", ""),
    (("gemini/",), "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent", "https://generativelanguage.googleapis.com/v1beta/models/{}:embedContent"),
    (("groq/",), "https://api.groq.com/openai/v1/chat/completions", ""),
    (("mistral/",), "https://api.mistral.ai/v1/chat/completions", "https://api.mistral.ai/v1/embeddings"),
    (("deepseek/",), "https://api.deepseek.com/chat/completions", ""),
    (("openrouter/",), "https://openrouter.ai/api/v1/chat/completions", ""),
    (("together_ai/",), "https://api.together.xyz/v1/chat/completions", ""),
    (("cohere/", "command-"), "https://api.cohere.com/v2/chat", "https://api.cohere.com/v2/embed"),
)

# PyGithub's raw requester (``obj._requester.requestJsonAndCheck(verb, url)``), and the API URL attributes of
# its objects: attribute -> {object kind: path appended after repos/<owner>/<repo>} ("" = the repository).
PYGITHUB_REQUESTER_METHODS = {"requestJsonAndCheck", "requestJson", "requestBlobAndCheck", "requestMultipartAndCheck",
                              "requestMemoryBlobAndCheck"}
PYGITHUB_REQUESTER_ATTRS = {"_requester", "_Github__requester", "requester", "_Requester"}
PYGITHUB_URL_ATTRS = {
    "url": {"PullRequest": "/pulls/", "Issue": "/issues/", "Repository": ""},
    "issue_url": {"PullRequest": "/issues/", "Issue": "/issues/"},
}
