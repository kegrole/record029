"""desercheck: static detector for dangerous deserialization payloads.

Pure static analysis, Python standard library only. Never calls
eval/exec/pickle.loads or any other action that would execute a payload.
"""

from .detector import Finding, analyze_bytes, analyze_file

__all__ = ["Finding", "analyze_bytes", "analyze_file"]

__version__ = "0.1.0"
