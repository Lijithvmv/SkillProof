"""Moved to skillproof.engines.installed (see docs/ARCHITECTURE.md). This alias keeps `skillproof.installed` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import installed as _moved

sys.modules[__name__] = _moved
