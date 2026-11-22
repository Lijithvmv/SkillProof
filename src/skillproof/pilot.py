"""Moved to skillproof.engines.pilot (see docs/ARCHITECTURE.md). This alias keeps `skillproof.pilot` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import pilot as _moved

sys.modules[__name__] = _moved
