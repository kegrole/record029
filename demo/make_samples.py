"""Regenerate demo/samples. Run from the repo root: python demo/make_samples.py

Sample construction uses pickle.dumps / json.dumps only to WRITE fixtures;
the detector itself never loads or executes them.
"""

import base64
import json
import os
import pickle

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, 'samples')


def build_samples():
    global_pickle = b'cos\nsystem\n.'  # protocol 0: GLOBAL cos system; STOP
    reduce_pickle = pickle.dumps(range(3))  # STACK_GLOBAL + REDUCE
    java_stream = (
        b'\xac\xed\x00\x05'          # STREAM_MAGIC + STREAM_VERSION
        b'\x73'                       # TC_OBJECT
        b'\x72\x00\x05Hello'          # TC_CLASSDESC, class name 'Hello'
        b'\x00\x00\x00\x00\x00\x00\x00\x01'  # serialVersionUID = 1
        b'\x02'                       # SC_SERIALIZABLE
        b'\x00\x00'                   # no fields
        b'\x78'                       # TC_ENDBLOCKDATA
        b'\x70'                       # TC_NULL (no superclass)
    )
    return {
        'pickle_global.pkl': global_pickle,
        'pickle_reduce.pkl': reduce_pickle,
        'java_magic.bin': java_stream,
        'yaml_tag.yaml': b"!!python/object/apply:os.system ['echo pwned']\n",
        'dict.pkl': pickle.dumps({'a': 1, 'b': [2, 3]}),
        'list.pkl': pickle.dumps([1, 'two', 3.5, None]),
        'plain.json': json.dumps({'name': 'demo', 'values': [1, 2, 3]}).encode(),
        'reduce.json': json.dumps(
            {'__reduce__': ['os.system', ['echo pwned']]}).encode(),
        'pickle_global.b64': base64.b64encode(global_pickle) + b'\n',
        'pickle_global.hex': global_pickle.hex().encode() + b'\n',
    }


def main():
    os.makedirs(SAMPLES, exist_ok=True)
    for name, data in build_samples().items():
        with open(os.path.join(SAMPLES, name), 'wb') as handle:
            handle.write(data)
    print('wrote %d samples to %s' % (len(build_samples()), SAMPLES))


if __name__ == '__main__':
    main()
