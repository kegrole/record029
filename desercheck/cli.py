"""Command line entry: python -m desercheck.cli --samples DIR --out FILE."""

import argparse
import os
import sys

from .detector import analyze_file
from .report import build_report, summary_line, write_report


def iter_sample_files(samples_dir):
    """Yield sample file paths in deterministic (sorted) order."""
    for name in sorted(os.listdir(samples_dir)):
        path = os.path.join(samples_dir, name)
        if os.path.isfile(path):
            yield path


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='desercheck',
        description='Static detector for dangerous deserialization payloads '
                    '(pickle / Java serialization / YAML tags / JSON). '
                    'Never executes the samples.',
    )
    parser.add_argument('--samples', required=True,
                        help='directory containing sample files')
    parser.add_argument('--out', required=True,
                        help='path of the JSON report to write')
    args = parser.parse_args(argv)

    if not os.path.isdir(args.samples):
        parser.error('samples directory not found: %s' % args.samples)

    results = [(path, analyze_file(path)) for path in iter_sample_files(args.samples)]
    report = build_report(results)
    write_report(report, args.out)
    print(summary_line(report))
    return 0


if __name__ == '__main__':
    sys.exit(main())
