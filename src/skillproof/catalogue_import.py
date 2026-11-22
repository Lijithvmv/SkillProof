"""Moved to skillproof.services.imports (see docs/ARCHITECTURE.md). This alias keeps `skillproof.catalogue_import` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.services import imports as _moved

sys.modules[__name__] = _moved
