"""Static Zero Trust scanner for multi-agent systems: agents, tools, APIs, databases and their
interactions found in the source tree, written as draft ZT-IR manifests and inventories.

    python -m zt_scanner --repo-root SRC --output-dir OUT      (or: zt-scan ...)
"""
from .scanner import main, run_scan

__all__ = ["main", "run_scan"]
