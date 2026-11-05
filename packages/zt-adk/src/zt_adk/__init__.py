"""Zero Trust Backplane for Google ADK multi-agent systems.

    zt-adk init / keys init / build      generate the protection bundle of an ADK application
    ZeroTrustPlugin                      enforce it in-process (ADK BasePlugin)
"""
__version__ = "0.1.0"

__all__ = ["ZeroTrustPlugin", "__version__"]


def __getattr__(name: str):
    if name == "ZeroTrustPlugin":
        from .plugin import ZeroTrustPlugin

        return ZeroTrustPlugin
    raise AttributeError(name)
