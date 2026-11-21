"""script-sentinel: self-hosted integrity monitoring for the third-party scripts your pages load."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("script-sentinel")
except PackageNotFoundError:  # pragma: no cover - only when running from a bare checkout
    __version__ = "0.0.0"
