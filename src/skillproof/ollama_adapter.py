"""Moved to skillproof.adapters.ollama (see docs/ARCHITECTURE.md). This alias keeps `skillproof.ollama_adapter` importing the same
module object, so existing imports, attributes and patches keep working."""
import sys

from skillproof.adapters import ollama as _moved

sys.modules[__name__] = _moved
