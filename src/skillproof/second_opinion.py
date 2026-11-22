"""Moved to skillproof.engines.second_opinion (see docs/ARCHITECTURE.md). This alias keeps `skillproof.second_opinion` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import second_opinion as _moved

sys.modules[__name__] = _moved
