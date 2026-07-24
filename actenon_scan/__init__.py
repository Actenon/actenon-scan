"""actenon-scan: defensive static-analysis scanner for the AI-agent execution gap."""

from importlib.metadata import version as _pkg_version, PackageNotFoundError

try:
    __version__ = _pkg_version("actenon-scan")
except PackageNotFoundError:
    # Running from source without installation (e.g. in a dev checkout).
    # Fall back to reading pyproject.toml directly.
    __version__ = "0.0.0+unknown"
