"""inbounds: check a target against a bug bounty program's scope."""

from inbounds.normalize import Target, UnclearTarget, normalize, normalize_hostname

__version__ = "0.1.0.dev0"

__all__ = ["Target", "UnclearTarget", "normalize", "normalize_hostname", "__version__"]
