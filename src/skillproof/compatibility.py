"""Moved to skillproof.engines.compatibility (see docs/ARCHITECTURE.md). This alias keeps `skillproof.compatibility` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import compatibility as _moved

sys.modules[__name__] = _moved
