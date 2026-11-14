"""Static pickle opcode scanner.

Uses pickletools.genops -- a pure decoder that walks opcodes and their
arguments WITHOUT importing anything or calling any callable. This is
the only part of the stdlib pickle machinery that is safe to point at
hostile bytes; pickle.loads is never used here.
"""

import pickletools

from .opcodes import DANGEROUS_OPCODES, DANGEROUS_REASONS


def scan_pickle(data):
    """Statically scan data (bytes) as a pickle stream.

    Returns a dict with keys:
        opcodes       -- list of all opcode names, in stream order
        dangerous     -- list of (opcode_name, byte_offset) hits
        first_offset  -- 0-based byte offset of the first dangerous
                         opcode, or None when the stream is safe

    Returns None when data is not a well-formed, complete pickle stream
    (must parse cleanly up to a final STOP opcode).
    """
    if not isinstance(data, (bytes, bytearray)) or not data:
        return None
    try:
        ops = list(pickletools.genops(bytes(data)))
    except Exception:
        # Any decode failure (bad opcode, truncated argument,
        # unterminated string, ...) means: not a pickle we can vouch for.
        return None
    if not ops:
        return None
    # A complete pickle stream ends with STOP. Requiring this keeps random
    # text that happens to start with an opcode byte (e.g. base64 starting
    # with "g" == BINPUT) from being misclassified as a pickle.
    if ops[-1][0].name != 'STOP':
        return None

    names = [opcode.name for opcode, _arg, _pos in ops]
    hits = [
        (opcode.name, pos)
        for opcode, _arg, pos in ops
        if opcode.name in DANGEROUS_OPCODES
    ]
    return {
        'opcodes': names,
        'dangerous': hits,
        'first_offset': hits[0][1] if hits else None,
    }


def danger_evidence(scan):
    """Build evidence strings for a pickle scan result."""
    evidence = []
    for name, offset in scan['dangerous']:
        reason = DANGEROUS_REASONS.get(name, 'execution semantics')
        evidence.append('opcode:%s@byte:%d (%s)' % (name, offset, reason))
    return evidence
