"""Moved to skillproof.engines.inventory (see docs/ARCHITECTURE.md). This alias keeps `skillproof.inventory` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import inventory as _moved

sys.modules[__name__] = _moved
