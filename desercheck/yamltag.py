"""Dangerous YAML custom-tag recognition (pure text scan, no YAML parser).

We deliberately do NOT import yaml: PyYAML is third-party and even its
SafeLoader would parse the payload. A regex over the text is enough --
the danger lives entirely in the tag names.
"""

import re

#: Tag families whose resolution instantiates arbitrary objects.
#: Covers PyYAML (!!python/object*, !!python/name:, !!python/module:),
#: Ruby Psych (!ruby/object:Foo), Perl and PHP object tags.
DANGEROUS_TAG_PATTERNS = [
    ('python/object', re.compile(
        r'!{1,2}(?:tag:yaml\.org,\d{4}:)?python/object(?:/(?:apply|new))?',
        re.IGNORECASE)),
    ('python/name', re.compile(
        r'!{1,2}(?:tag:yaml\.org,\d{4}:)?python/name:', re.IGNORECASE)),
    ('python/module', re.compile(
        r'!{1,2}(?:tag:yaml\.org,\d{4}:)?python/module:', re.IGNORECASE)),
    ('ruby/object', re.compile(r'!{1,2}ruby/object', re.IGNORECASE)),
    ('perl', re.compile(r'!{1,2}perl/(?:module|code)', re.IGNORECASE)),
    ('php/object', re.compile(r'!{1,2}php/object', re.IGNORECASE)),
]


def scan_yaml_tags(text):
    """Return the dangerous tag strings found in text (may be empty)."""
    if not isinstance(text, str):
        return []
    found = []
    for _family, pattern in DANGEROUS_TAG_PATTERNS:
        for match in pattern.finditer(text):
            tag = match.group(0)
            if tag not in found:
                found.append(tag)
    return found
