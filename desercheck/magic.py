"""Java native serialization recognition (static, magic + type markers)."""

#: Every Java ObjectOutputStream starts with STREAM_MAGIC 0xACED
#: followed by STREAM_VERSION 0x0005.
JAVA_MAGIC = b'\xac\xed\x00\x05'

#: Type markers (see java.io.ObjectStreamConstants).
TC_MARKERS = {
    0x70: 'TC_NULL',
    0x71: 'TC_REFERENCE',
    0x72: 'TC_CLASSDESC',
    0x73: 'TC_OBJECT',
    0x74: 'TC_STRING',
    0x75: 'TC_ARRAY',
    0x76: 'TC_CLASS',
    0x77: 'TC_BLOCKDATA',
    0x78: 'TC_ENDBLOCKDATA',
    0x79: 'TC_RESET',
    0x7A: 'TC_BLOCKDATALONG',
    0x7B: 'TC_EXCEPTION',
    0x7C: 'TC_LONGSTRING',
    0x7D: 'TC_PROXYCLASSDESC',
    0x7E: 'TC_ENUM',
}

#: Markers that make a stream dangerous: they describe reconstructed
#: objects / class descriptors, which is exactly where deserialization
#: gadgets (readObject, readResolve, ...) fire on the Java side.
DANGEROUS_TC = frozenset({
    'TC_OBJECT',
    'TC_CLASSDESC',
    'TC_CLASS',
    'TC_PROXYCLASSDESC',
    'TC_ENUM',
})


def scan_java(data):
    """Return marker info if data is a Java serialization stream.

    Result keys: magic (hex string), markers (TC_* names found, in order
    of first appearance), dangerous (the dangerous subset). Returns None
    when the magic header is absent or no TC_* marker appears at all.
    """
    if not isinstance(data, (bytes, bytearray)):
        return None
    data = bytes(data)
    if not data.startswith(JAVA_MAGIC):
        return None
    seen = []
    for byte in data[len(JAVA_MAGIC):]:
        name = TC_MARKERS.get(byte)
        if name and name not in seen:
            seen.append(name)
    if not seen:
        return None
    dangerous = [name for name in seen if name in DANGEROUS_TC]
    return {'magic': JAVA_MAGIC.hex(), 'markers': seen, 'dangerous': dangerous}
