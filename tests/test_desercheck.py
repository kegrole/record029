"""Unittest suite for desercheck.

Every fixture is generated programmatically inside a temporary directory,
so the verdicts are checked against freshly built samples each run --
nothing is hard-coded to a specific sample directory.

Run from the tests/ directory:  python -m unittest test_desercheck -v
"""

import base64
import contextlib
import io
import json
import os
import pickle
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from desercheck.cli import main as cli_main
from desercheck.detector import analyze_bytes, analyze_file
from desercheck.report import build_report, summary_line


# ---------------------------------------------------------------- fixtures

def global_pickle_bytes():
    """Protocol-0 pickle whose first opcode is GLOBAL (cos system)."""
    return b'cos\nsystem\n.'


def stack_global_pickle_bytes():
    """Same payload expressed with STACK_GLOBAL instead of GLOBAL."""
    return (
        b'\x80\x02'        # PROTO 2
        b'\x8c\x03cos'      # SHORT_BINUNICODE 'cos'
        b'\x8c\x06system'   # SHORT_BINUNICODE 'system'
        b'\x93'             # STACK_GLOBAL  (byte offset 15)
        b'.'                # STOP
    )


def reduce_pickle_bytes():
    """A pickle that rebuilds range(3): STACK_GLOBAL + REDUCE."""
    return pickle.dumps(range(3))


def java_stream_bytes():
    return (
        b'\xac\xed\x00\x05'              # STREAM_MAGIC + STREAM_VERSION
        b'\x73'                           # TC_OBJECT
        b'\x72\x00\x05Hello'              # TC_CLASSDESC 'Hello'
        b'\x00\x00\x00\x00\x00\x00\x00\x01'  # serialVersionUID
        b'\x02\x00\x00\x78\x70'           # flags, no fields, end, null super
    )


def yaml_tag_bytes():
    return b"!!python/object/apply:os.system ['echo pwned']\n"


def plain_json_bytes():
    return json.dumps({'name': 'demo', 'values': [1, 2, 3]}).encode()


def reduce_json_bytes():
    return json.dumps({'__reduce__': ['os.system', ['echo pwned']]}).encode()


def build_eight_samples(directory):
    """Criterion 1: the eight canonical fixtures. Returns {name: path}."""
    samples = {
        'pickle_global.pkl': global_pickle_bytes(),
        'pickle_reduce.pkl': reduce_pickle_bytes(),
        'java_magic.bin': java_stream_bytes(),
        'yaml_tag.yaml': yaml_tag_bytes(),
        'dict.pkl': pickle.dumps({'a': 1, 'b': [2, 3]}),
        'list.pkl': pickle.dumps([1, 'two', 3.5, None]),
        'plain.json': plain_json_bytes(),
        'reduce.json': reduce_json_bytes(),
    }
    paths = {}
    for name, data in samples.items():
        path = os.path.join(directory, name)
        with open(path, 'wb') as handle:
            handle.write(data)
        paths[name] = path
    return paths


class TempDirTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='desercheck-test-')
        self.addCleanup(shutil_rmtree, self.tmp)


def shutil_rmtree(path):
    import shutil
    shutil.rmtree(path, ignore_errors=True)


# --------------------------------------------------------------------- tests

class TestEightSamples(TempDirTestCase):
    def setUp(self):
        super().setUp()
        self.paths = build_eight_samples(self.tmp)
        self.findings = {
            name: analyze_file(path) for name, path in self.paths.items()
        }

    def test_kinds_of_eight_samples(self):
        expected = {
            'pickle_global.pkl': 'pickle',
            'pickle_reduce.pkl': 'pickle',
            'java_magic.bin': 'java',
            'yaml_tag.yaml': 'yaml',
            'dict.pkl': 'pickle',
            'list.pkl': 'pickle',
            'plain.json': 'json',
            'reduce.json': 'json',
        }
        for name, kind in expected.items():
            with self.subTest(sample=name):
                self.assertEqual(self.findings[name].kind, kind)

    def test_exactly_five_dangerous(self):
        """Criterion 2: exactly the 4 named ones + the __reduce__ JSON."""
        dangerous = {
            name for name, finding in self.findings.items() if finding.dangerous
        }
        self.assertEqual(dangerous, {
            'pickle_global.pkl',
            'pickle_reduce.pkl',
            'java_magic.bin',
            'yaml_tag.yaml',
            'reduce.json',
        })
        self.assertEqual(len(dangerous), 5)

    def test_report_has_kind_and_evidence(self):
        """Criterion 3: every entry has kind+evidence; pickle opcodes named."""
        results = [(self.paths[name], self.findings[name]) for name in self.paths]
        report = build_report(results)
        self.assertEqual(report['summary']['samples'], 8)
        self.assertEqual(report['summary']['dangerous'], 5)
        for entry in report['samples']:
            with self.subTest(sample=entry['sample']):
                self.assertIn(entry['kind'], ('pickle', 'java', 'yaml', 'json'))
                self.assertIn('evidence', entry)
                if entry['dangerous']:
                    self.assertTrue(entry['evidence'])
        by_name = {
            entry['sample']: entry for entry in report['samples']
        }
        global_ev = ' '.join(by_name['pickle_global.pkl']['evidence'])
        reduce_ev = ' '.join(by_name['pickle_reduce.pkl']['evidence'])
        self.assertIn('GLOBAL', global_ev)
        self.assertIn('REDUCE', reduce_ev)
        # first dangerous opcode byte offsets are reported
        self.assertEqual(by_name['pickle_global.pkl']['first_danger_offset'], 0)
        self.assertIsNotNone(by_name['pickle_reduce.pkl']['first_danger_offset'])
        # java evidence names the magic bytes, yaml evidence names the tag
        java_ev = ' '.join(by_name['java_magic.bin']['evidence'])
        yaml_ev = ' '.join(by_name['yaml_tag.yaml']['evidence'])
        self.assertIn('aced0005', java_ev)
        self.assertIn('TC_OBJECT', java_ev)
        self.assertIn('!!python/object/apply', yaml_ev)


class TestTextForms(TempDirTestCase):
    def test_base64_pickle_same_verdict(self):
        """Criterion 4: base64 text form -> identical kind and verdict."""
        binary = analyze_bytes(global_pickle_bytes())
        path = os.path.join(self.tmp, 'payload.b64')
        with open(path, 'wb') as handle:
            handle.write(base64.b64encode(global_pickle_bytes()) + b'\n')
        text_form = analyze_file(path)
        self.assertEqual(text_form.kind, 'pickle')
        self.assertEqual(text_form.dangerous, binary.dangerous)
        self.assertTrue(text_form.dangerous)
        self.assertEqual(text_form.first_danger_offset, binary.first_danger_offset)
        self.assertEqual(text_form.encoding, 'base64')

    def test_hex_pickle_same_verdict(self):
        """Criterion 5 (text forms): hex text form -> identical verdict."""
        binary = analyze_bytes(global_pickle_bytes())
        path = os.path.join(self.tmp, 'payload.hex')
        with open(path, 'wb') as handle:
            handle.write(global_pickle_bytes().hex().encode() + b'\n')
        text_form = analyze_file(path)
        self.assertEqual(text_form.kind, 'pickle')
        self.assertEqual(text_form.dangerous, binary.dangerous)
        self.assertEqual(text_form.first_danger_offset, binary.first_danger_offset)
        self.assertEqual(text_form.encoding, 'hex')


class TestSafeSamples(TempDirTestCase):
    def test_three_safe_samples_never_flagged(self):
        """Criterion 5: dict pickle, list pickle, plain JSON stay safe."""
        paths = build_eight_samples(self.tmp)
        for name in ('dict.pkl', 'list.pkl', 'plain.json'):
            with self.subTest(sample=name):
                finding = analyze_file(paths[name])
                self.assertFalse(finding.dangerous)
                self.assertEqual(finding.evidence if finding.dangerous else [], [])


class TestOpcodeWhitelist(TempDirTestCase):
    def test_stack_global_variant_still_dangerous(self):
        """Criterion 6: whitelist is opcode-based, not string matching."""
        path = os.path.join(self.tmp, 'stack_global.pkl')
        with open(path, 'wb') as handle:
            handle.write(stack_global_pickle_bytes())
        finding = analyze_file(path)
        self.assertEqual(finding.kind, 'pickle')
        self.assertTrue(finding.dangerous)
        self.assertIn('STACK_GLOBAL', ' '.join(finding.evidence))
        # STACK_GLOBAL sits at byte offset 15 in this stream
        self.assertEqual(finding.first_danger_offset, 15)

    def test_whitelist_covers_all_listed_opcodes(self):
        from desercheck.opcodes import DANGEROUS_OPCODES
        self.assertEqual(DANGEROUS_OPCODES, {
            'GLOBAL', 'STACK_GLOBAL', 'REDUCE', 'INST', 'OBJ', 'BUILD',
            'NEWOBJ', 'NEWOBJ_EX', 'EXT1', 'EXT2', 'EXT4',
        })


class TestNoExecutionTraces(TempDirTestCase):
    def test_scan_leaves_no_traces(self):
        """Criterion 7: no new files in the sample dir, no executable
        payload fragments leaked into the report."""
        paths = build_eight_samples(self.tmp)
        before = sorted(os.listdir(self.tmp))
        out_path = os.path.join(self.tmp, '..', 'report-out', 'report.json')
        out_path = os.path.abspath(out_path)
        self.addCleanup(lambda: os.path.isdir(os.path.dirname(out_path))
                        and shutil_rmtree(os.path.dirname(out_path)))
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            cli_main(['--samples', self.tmp, '--out', out_path])
        after = sorted(os.listdir(self.tmp))
        self.assertEqual(before, after)  # scanning created nothing here
        with open(out_path, encoding='utf-8') as handle:
            report_text = handle.read()
        # the report carries verdicts/evidence, never payload code
        self.assertNotIn('os.system', report_text)
        self.assertNotIn('eval(', report_text)
        self.assertNotIn('__import__', report_text)
        self.assertIn('samples=8', stdout.getvalue())
        self.assertIn('dangerous=5', stdout.getvalue())


class TestVerdictFollowsSample(TempDirTestCase):
    def test_rerun_after_swapping_sample(self):
        """Criterion 8: swap one sample file, rerun, verdict follows."""
        target = os.path.join(self.tmp, 'slot.dat')
        with open(target, 'wb') as handle:
            handle.write(plain_json_bytes())
        first = analyze_file(target)
        self.assertEqual(first.kind, 'json')
        self.assertFalse(first.dangerous)

        with open(target, 'wb') as handle:
            handle.write(global_pickle_bytes())
        second = analyze_file(target)
        self.assertEqual(second.kind, 'pickle')
        self.assertTrue(second.dangerous)

        # and via the CLI on the whole directory
        out = os.path.join(self.tmp, 'report.json')
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            cli_main(['--samples', self.tmp, '--out', out])
        self.assertIn('dangerous=1', stdout.getvalue())


class TestSummaryLine(TempDirTestCase):
    def test_summary_line_format(self):
        paths = build_eight_samples(self.tmp)
        results = [(p, analyze_file(p)) for p in paths.values()]
        line = summary_line(build_report(results))
        self.assertIn('samples=8', line)
        self.assertIn('dangerous=5', line)
        self.assertIn('pickle:2', line)
        self.assertIn('java:1', line)
        self.assertIn('yaml:1', line)
        self.assertIn('json:1', line)


if __name__ == '__main__':
    unittest.main()
