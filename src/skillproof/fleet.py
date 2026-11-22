"""Moved to skillproof.storage.fleet (see docs/ARCHITECTURE.md). This alias keeps `skillproof.fleet` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.storage import fleet as _moved

sys.modules[__name__] = _moved
