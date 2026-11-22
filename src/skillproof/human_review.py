"""Moved to skillproof.engines.human_review (see docs/ARCHITECTURE.md). This alias keeps `skillproof.human_review` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import human_review as _moved

sys.modules[__name__] = _moved
