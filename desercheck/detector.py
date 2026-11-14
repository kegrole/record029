"""Detection orchestrator: route a byte blob to the right static scanner.

Recognition order (first match wins):
    1. Java native serialization (magic 0xACED0005 + TC_* markers)
    2. Binary pickle stream (full opcode walk to STOP)
    3. Text forms, after UTF-8 decoding:
       a. base64 text -> decode -> re-run 1/2 on the decoded bytes
       b. hex text    -> decode -> re-run 1/2 on the decoded bytes
       c. YAML dangerous custom tags
       d. JSON document (dangerous iff some object has a __reduce__ key)
    4. unknown

Everything here is static: no eval, no exec, no pickle.loads, no yaml
parser, no object construction. json.loads only builds dict/list/str/
int/float/bool/None -- it cannot execute anything.
"""

import base64
import binascii
import json
from dataclasses import dataclass, field

from .magic import scan_java
from .pickle_scan import danger_evidence, scan_pickle
from .yamltag import scan_yaml_tags

REDUCE_KEY = "__reduce__"


@dataclass
class Finding:
    """Verdict for one sample."""

    kind: str                       # pickle | java | yaml | json | unknown
    dangerous: bool
    evidence: list = field(default_factory=list)
    first_danger_offset: object = None   # 0-based byte offset, pickle only
    encoding: str = 'binary'        # binary | base64 | hex | text

    def to_dict(self):
        return {
            'kind': self.kind,
            'dangerous': self.dangerous,
            'evidence': list(self.evidence),
            'first_danger_offset': self.first_danger_offset,
            'encoding': self.encoding,
        }


def _java_finding(info, encoding):
    evidence = ['magic:0x' + info['magic']]
    evidence += ['marker:' + name for name in info['markers']]
    return Finding(
        kind='java',
        dangerous=bool(info['dangerous']),
        evidence=evidence,
        first_danger_offset=0,
        encoding=encoding,
    )


def _pickle_finding(scan, encoding):
    return Finding(
        kind='pickle',
        dangerous=bool(scan['dangerous']),
        evidence=danger_evidence(scan),
        first_danger_offset=scan['first_offset'],
        encoding=encoding,
    )


def _scan_binary_forms(data, encoding):
    """Try Java magic, then a full pickle opcode walk, on raw bytes."""
    info = scan_java(data)
    if info is not None:
        return _java_finding(info, encoding)
    scan = scan_pickle(data)
    if scan is not None:
        return _pickle_finding(scan, encoding)
    return None


def _json_has_reduce(node):
    """Recursively look for a dict carrying the __reduce__ key."""
    if isinstance(node, dict):
        if REDUCE_KEY in node:
            return True
        return any(_json_has_reduce(value) for value in node.values())
    if isinstance(node, list):
        return any(_json_has_reduce(item) for item in node)
    return False


def _scan_text_forms(data):
    try:
        text = data.decode('utf-8')
    except (UnicodeDecodeError, ValueError):
        return None
    stripped = text.strip()
    if not stripped:
        return None

    # base64 text form of a binary payload
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        decoded = None
    if decoded:
        finding = _scan_binary_forms(decoded, 'base64')
        if finding is not None:
            return finding

    # hex text form of a binary payload
    try:
        decoded = bytes.fromhex(stripped)
    except ValueError:
        decoded = None
    if decoded:
        finding = _scan_binary_forms(decoded, 'hex')
        if finding is not None:
            return finding

    # YAML dangerous custom tags
    tags = scan_yaml_tags(text)
    if tags:
        return Finding(
            kind='yaml',
            dangerous=True,
            evidence=['tag:' + tag for tag in tags],
            first_danger_offset=text.find(tags[0]),
            encoding='text',
        )

    # JSON document (json.loads is inert: it builds plain containers only)
    try:
        document = json.loads(stripped)
    except ValueError:
        return None
    dangerous = _json_has_reduce(document)
    evidence = ['key:' + REDUCE_KEY] if dangerous else ['json:plain-containers']
    return Finding(kind='json', dangerous=dangerous, evidence=evidence,
                   first_danger_offset=None, encoding='text')


def analyze_bytes(data):
    """Classify one sample (bytes) and return a Finding."""
    finding = _scan_binary_forms(data, 'binary')
    if finding is not None:
        return finding
    finding = _scan_text_forms(data)
    if finding is not None:
        return finding
    return Finding(kind='unknown', dangerous=False,
                   evidence=['no known serialization signature'],
                   encoding='binary')


def analyze_file(path):
    """Read a sample file and classify it (read-only, never executed)."""
    with open(path, 'rb') as handle:
        data = handle.read()
    return analyze_bytes(data)
