"""Moved to skillproof.services.evaluation (see docs/ARCHITECTURE.md). This alias keeps `skillproof.evaluation_jobs` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.services import evaluation as _moved

sys.modules[__name__] = _moved
