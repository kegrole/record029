"""Report assembly: turn per-sample Findings into a JSON report."""

import json
import os


def build_report(results):
    """results: list of (path, Finding). Returns a JSON-serializable dict."""
    samples = []
    dangerous_kinds = {}
    dangerous_count = 0
    for path, finding in results:
        entry = {
            'sample': os.path.basename(str(path)),
            'path': str(path),
        }
        entry.update(finding.to_dict())
        samples.append(entry)
        if finding.dangerous:
            dangerous_count += 1
            dangerous_kinds[finding.kind] = dangerous_kinds.get(finding.kind, 0) + 1
    return {
        'summary': {
            'samples': len(samples),
            'dangerous': dangerous_count,
            'safe': len(samples) - dangerous_count,
            'dangerous_kinds': dangerous_kinds,
        },
        'samples': samples,
    }


def write_report(report, out_path):
    """Write the report JSON, creating the output directory if needed."""
    directory = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(directory, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write('\n')


def summary_line(report):
    """One-line stdout summary: counts + dangerous kind distribution."""
    summary = report['summary']
    kinds = summary['dangerous_kinds']
    dist = ','.join('%s:%d' % (kind, kinds[kind]) for kind in sorted(kinds)) or 'none'
    return 'samples=%d dangerous=%d safe=%d dangerous_kinds=%s' % (
        summary['samples'], summary['dangerous'], summary['safe'], dist)
