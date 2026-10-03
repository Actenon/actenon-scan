"""HTTP request -> (action, resource): the single vocabulary shared by static discovery and runtime.

``classify_http(method, url)`` is called by the static extractor with URL *templates* (unknown parts are
``HOLE``) and by Airlock's edge with the exact request URL. Both therefore name the same authority entry
for the same request. Unknown parts never widen: an unknown host or repository is UNRESOLVED, an unknown
whole path segment becomes a ``{}`` template segment, and nothing becomes a wildcard.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .model import ResourceState

HOLE = "\x00"  # marks an unknown part inside a URL template (never valid in a real URL)
TEMPLATE_SEGMENT = "{}"  # how an unknown whole segment is written in a resource

READ_METHODS = frozenset({"get", "head", "options"})


@dataclass(frozen=True)
class HttpAuthority:
    action: str
    resource: str | None
    state: ResourceState
    read_only: bool
    unresolved_parts: tuple[str, ...] = ()
    template_params: tuple[str, ...] = ()
    host: str = ""
    route: str = ""  # the matched route pattern, e.g. "repos/{owner}/{repo}/issues"


# GitHub REST routes. ``{owner}``/``{repo}`` (or ``{org}``) decide the resource; any other ``{x}`` is a
# per-request value inside that resource (issue number, file path) and does not change the authority.
# ``{path+}`` matches one or more remaining segments.
_GITHUB_ROUTES: tuple[tuple[str, str, str], ...] = (
    ("post", "repos/{owner}/{repo}/issues", "github.issue.create"),
    ("patch", "repos/{owner}/{repo}/issues/{number}", "github.issue.update"),
    ("post", "repos/{owner}/{repo}/issues/{number}/comments", "github.issue.comment"),
    ("patch", "repos/{owner}/{repo}/issues/comments/{id}", "github.issue.comment.update"),
    ("delete", "repos/{owner}/{repo}/issues/comments/{id}", "github.issue.comment.delete"),
    ("post", "repos/{owner}/{repo}/issues/{number}/labels", "github.issue.label"),
    ("put", "repos/{owner}/{repo}/issues/{number}/labels", "github.issue.label"),
    ("delete", "repos/{owner}/{repo}/issues/{number}/labels/{name}", "github.issue.label"),
    ("post", "repos/{owner}/{repo}/issues/{number}/assignees", "github.issue.assign"),
    ("put", "repos/{owner}/{repo}/issues/{number}/lock", "github.issue.lock"),
    ("post", "repos/{owner}/{repo}/labels", "github.label.create"),
    ("post", "repos/{owner}/{repo}/pulls", "github.pull.create"),
    ("patch", "repos/{owner}/{repo}/pulls/{number}", "github.pull.update"),
    ("put", "repos/{owner}/{repo}/pulls/{number}/merge", "github.pull.merge"),
    ("post", "repos/{owner}/{repo}/pulls/{number}/reviews", "github.pull.review"),
    ("put", "repos/{owner}/{repo}/pulls/{number}/reviews/{id}", "github.pull.review"),
    ("delete", "repos/{owner}/{repo}/pulls/{number}/reviews/{id}", "github.pull.review"),
    ("post", "repos/{owner}/{repo}/pulls/{number}/reviews/{id}/events", "github.pull.review"),
    ("post", "repos/{owner}/{repo}/pulls/{number}/comments", "github.pull.comment"),
    ("post", "repos/{owner}/{repo}/pulls/{number}/requested_reviewers", "github.pull.request_review"),
    ("put", "repos/{owner}/{repo}/contents/{path+}", "github.contents.write"),
    ("delete", "repos/{owner}/{repo}/contents/{path+}", "github.contents.delete"),
    ("post", "repos/{owner}/{repo}/git/refs", "github.ref.create"),
    ("patch", "repos/{owner}/{repo}/git/refs/{path+}", "github.ref.update"),
    ("delete", "repos/{owner}/{repo}/git/refs/{path+}", "github.ref.delete"),
    ("post", "repos/{owner}/{repo}/git/blobs", "github.git.write"),
    ("post", "repos/{owner}/{repo}/git/trees", "github.git.write"),
    ("post", "repos/{owner}/{repo}/git/commits", "github.git.write"),
    ("post", "repos/{owner}/{repo}/git/tags", "github.git.write"),
    ("post", "repos/{owner}/{repo}/merges", "github.branch.merge"),
    ("post", "repos/{owner}/{repo}/releases", "github.release.create"),
    ("patch", "repos/{owner}/{repo}/releases/{id}", "github.release.update"),
    ("delete", "repos/{owner}/{repo}/releases/{id}", "github.release.delete"),
    ("post", "repos/{owner}/{repo}/forks", "github.repo.fork"),
    ("patch", "repos/{owner}/{repo}", "github.repo.update"),
    ("delete", "repos/{owner}/{repo}", "github.repo.delete"),
    ("post", "repos/{owner}/{repo}/transfer", "github.repo.transfer"),
    ("put", "repos/{owner}/{repo}/collaborators/{username}", "github.collaborator.add"),
    ("delete", "repos/{owner}/{repo}/collaborators/{username}", "github.collaborator.remove"),
    ("post", "repos/{owner}/{repo}/hooks", "github.webhook.create"),
    ("delete", "repos/{owner}/{repo}/hooks/{id}", "github.webhook.delete"),
    ("post", "repos/{owner}/{repo}/keys", "github.deploy_key.create"),
    ("put", "repos/{owner}/{repo}/actions/secrets/{name}", "github.secret.write"),
    ("delete", "repos/{owner}/{repo}/actions/secrets/{name}", "github.secret.delete"),
    ("post", "repos/{owner}/{repo}/dispatches", "github.workflow.dispatch"),
    ("post", "repos/{owner}/{repo}/actions/workflows/{id}/dispatches", "github.workflow.dispatch"),
    ("post", "repos/{owner}/{repo}/actions/runs/{id}/rerun", "github.workflow.rerun"),
    ("put", "repos/{owner}/{repo}/branches/{branch}/protection", "github.branch_protection.write"),
    ("delete", "repos/{owner}/{repo}/branches/{branch}/protection", "github.branch_protection.delete"),
    ("post", "repos/{owner}/{repo}/statuses/{sha}", "github.status.create"),
    ("post", "repos/{owner}/{repo}/check-runs", "github.check.create"),
    ("patch", "repos/{owner}/{repo}/check-runs/{id}", "github.check.update"),
    ("post", "repos/{owner}/{repo}/deployments", "github.deployment.create"),
    ("post", "orgs/{org}/repos", "github.repo.create"),
    ("post", "user/repos", "github.repo.create"),
    ("post", "gists", "github.gist.create"),
    ("post", "graphql", "github.graphql"),
)


def _split_url(url: str) -> tuple[str, str, str, str]:
    """(scheme, host[:port], path, query). Holes may appear anywhere."""
    if "://" not in url:
        return "", "", url, ""
    scheme, rest = url.split("://", 1)
    host, sep, path = rest.partition("/")
    path = "/" + path if sep else "/"
    path, _, query = path.partition("?")
    path = path.split("#", 1)[0]
    return scheme.lower(), host.lower(), path, query


def _normalise_host(scheme: str, host: str) -> str:
    if host.endswith(":443") and scheme == "https":
        return host[:-4]
    if host.endswith(":80") and scheme == "http":
        return host[:-3]
    return host


def _segments(path: str) -> list[str]:
    return [s for s in path.split("/") if s != ""]


def _match_route(pattern: str, segs: list[str]) -> dict[str, str] | None:
    pat = pattern.split("/")
    out: dict[str, str] = {}
    for i, p in enumerate(pat):
        if p.endswith("+}"):
            if i >= len(segs):
                return None
            out[p[1:-2]] = "/".join(segs[i:])
            return out
        if i >= len(segs):
            return None
        s = segs[i]
        if p.startswith("{") and p.endswith("}"):
            out[p[1:-1]] = s
        elif s != p:
            return None
    return out if len(pat) == len(segs) else None


def _match_route_with_holes(pattern: str, segs: list[str]) -> dict[str, str] | None:
    """Like ``_match_route``, but a segment that is entirely unknown may stand for one or two segments
    (a variable holding ``owner/repo``). Unknown parts can only make the match's parameters unknown."""
    hole_idx = [i for i, s in enumerate(segs) if s == HOLE]
    if not hole_idx or len(hole_idx) > 3:
        return _match_route(pattern, segs)
    for mask in range(1 << len(hole_idx)):
        variant: list[str] = []
        for i, s in enumerate(segs):
            if i in hole_idx and mask & (1 << hole_idx.index(i)):
                variant.extend([HOLE, HOLE])
            else:
                variant.append(s)
        params = _match_route(pattern, variant)
        if params is not None:
            return params
    return None


def _template_segment(seg: str) -> str:
    """A path segment with unknown parts: the unknown parts become ``{}``."""
    return seg.replace(HOLE, TEMPLATE_SEGMENT) if HOLE in seg else seg


def classify_http(method: str, url: str, *, hole_names: tuple[str, ...] = ()) -> HttpAuthority:
    """Name the authority an HTTP request needs.

    ``url`` is either a concrete URL (runtime) or a template whose unknown parts are ``HOLE``.
    ``hole_names`` optionally names the holes in order (for TEMPLATE parameter names).
    """
    m = method.lower() if method and HOLE not in method else ""
    scheme, host, path, _query = _split_url(url)
    read_only = m in READ_METHODS
    action_prefix = f"http.{m}" if m else "http.request"
    if not m:
        # Unknown method: the request may be anything, so it is consequential and its action is unknown.
        read_only = False
    if not host or HOLE in host or HOLE in scheme:
        return HttpAuthority(action_prefix, None, ResourceState.UNRESOLVED, read_only, ("host",), (), host)
    host = _normalise_host(scheme, host)
    segs = _segments(path)

    if host == "api.github.com" and m:
        for route_method, pattern, action in _GITHUB_ROUTES:
            if route_method != m:
                continue
            params = _match_route_with_holes(pattern, segs)
            if params is None:
                continue
            return _github_authority(action, params, read_only=False, pattern=pattern)
        if read_only and len(segs) >= 3 and segs[0] == "repos":
            return _github_authority(
                "github.repo.read", {"owner": segs[1], "repo": segs[2]}, read_only=True, pattern="repos/{owner}/{repo}/..."
            )

    # Generic HTTP: exact host, exact path. Only the final segment may be unknown ("{}": an item of that
    # collection). An unknown earlier segment chooses *which* collection, account or repository the request acts
    # on: that is unresolved, never a template (a "{}" there would cover every tenant the credential can reach).
    if any(HOLE in s for s in segs[:-1]):
        parts = ("repository",) if host == "api.github.com" and segs and segs[0] == "repos" and any(HOLE in s for s in segs[1:3]) else ("path",)
        return HttpAuthority(action_prefix, None, ResourceState.UNRESOLVED, read_only, parts, (), host, "")
    tsegs = [_template_segment(s) for s in segs]
    resource = host + ("/" + "/".join(tsegs) if tsegs else "")
    if any(HOLE in s for s in segs):
        n = sum(s.count(HOLE) for s in segs)
        names = tuple(hole_names[-n:]) if hole_names and len(hole_names) >= n else tuple(f"segment{i + 1}" for i in range(n))
        return HttpAuthority(action_prefix, resource, ResourceState.TEMPLATE, read_only, (), names, host, "")
    return HttpAuthority(action_prefix, resource, ResourceState.RESOLVED, read_only, (), (), host, "")


def _github_authority(action: str, params: dict[str, str], *, read_only: bool, pattern: str) -> HttpAuthority:
    if "org" in params:
        owner, repo = params["org"], None
    else:
        owner, repo = params.get("owner"), params.get("repo")
    unknown: list[str] = []
    if owner is not None and HOLE in owner:
        unknown.append("owner")
    if repo is not None and HOLE in repo:
        unknown.append("repository")
    if unknown:
        return HttpAuthority(action, None, ResourceState.UNRESOLVED, read_only, tuple(unknown), (), "api.github.com", pattern)
    if owner is None:  # user/repos, gists, graphql: the authenticated account
        resource = "github.com"
    elif repo is None:
        resource = f"github.com/{owner}"
    else:
        resource = f"github.com/{owner}/{repo}"
    return HttpAuthority(action, resource, ResourceState.RESOLVED, read_only, (), (), "api.github.com", pattern)


def resource_matches(entry_resource: str, request_resource: str) -> bool:
    """Does a concrete request resource fall inside an authority entry's resource?

    Exact equality, or a TEMPLATE entry whose ``{}`` parts each match exactly one non-empty path segment
    part (no ``/``, no ``..``). Nothing else: no prefixes, no globs.
    """
    if entry_resource == request_resource:
        return True
    if TEMPLATE_SEGMENT not in entry_resource:
        return False
    e = entry_resource.split("/")
    r = request_resource.split("/")
    if len(e) != len(r):
        return False
    for es, rs in zip(e, r):
        if es == rs:
            continue
        if TEMPLATE_SEGMENT not in es:
            return False
        if rs in ("", ".", "..") or not _segment_template_match(es, rs):
            return False
    return True


def _segment_template_match(template: str, value: str) -> bool:
    pattern = "[^/]+".join(re.escape(p) for p in template.split(TEMPLATE_SEGMENT))
    return re.fullmatch(pattern, value) is not None


def url_template(url_parts: list[str | None]) -> str:
    """Join known parts (str) and unknown parts (None) into a template string."""
    return "".join(HOLE if p is None else p for p in url_parts)


def display_url(template: str) -> str:
    return template.replace(HOLE, TEMPLATE_SEGMENT)


def split_concrete_url(url: str) -> tuple[str, str, str]:
    """(scheme, host, path) of a concrete URL, for runtime use."""
    s = urlsplit(url)
    return s.scheme.lower(), (s.netloc or "").lower(), s.path or "/"
