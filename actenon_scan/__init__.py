"""actenon-scan: defensive static-analysis scanner for the AI-agent execution gap."""

from importlib.metadata import version as _pkg_version, PackageNotFoundError

try:
    __version__ = _pkg_version("actenon-scan")
except PackageNotFoundError:
    # Running from source without installation (e.g. in a dev checkout).
    # Fall back to reading pyproject.toml directly. The previous
    # implementation returned the literal "0.0.0+unknown" without reading
    # anything — `--version` and the SARIF `tool.driver.version` field
    # both lied when running from source.
    __version__ = "0.0.0+unknown"
    try:
        # Walk up from this file to find a pyproject.toml. The package
        # is at <repo>/actenon_scan/__init__.py, so the toml is one level up.
        from pathlib import Path as _Path
        _toml_path = _Path(__file__).resolve().parent.parent / "pyproject.toml"
        if _toml_path.exists():
            _toml_text = _toml_path.read_text(encoding="utf-8")
            # Match the first `version = "..."` line. We avoid a TOML
            # parser dependency here (Python 3.10 doesn't have tomllib
            # in stdlib, and we don't want to depend on tomli at runtime).
            import re as _re
            _m = _re.search(r'^version\s*=\s*"([^"]+)"', _toml_text, _re.MULTILINE)
            if _m:
                __version__ = _m.group(1)
    except Exception:
        # If anything goes wrong, keep the "0.0.0+unknown" fallback.
        pass
