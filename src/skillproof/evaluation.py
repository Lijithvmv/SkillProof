"""Moved to skillproof.engines.evaluation (see docs/ARCHITECTURE.md). This alias keeps `skillproof.evaluation` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.engines import evaluation as _moved

sys.modules[__name__] = _moved
