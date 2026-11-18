#!/usr/bin/env python3
"""Attach captured mock configuration and atomically package exactly one run."""
import argparse
import json
import os
from pathlib import Path
import tarfile
import tempfile


def finalize(root, outdir, stats):
    if Path(outdir).name != outdir or outdir in ('', '.', '..'):
        raise ValueError('outdir must be a single directory name')
    matches = list(root.glob('**/' + outdir + '/run-config.jsonl'))
    if len(matches) != 1:
        raise ValueError(f'expected one run-config.jsonl, found {len(matches)}')
    config = matches[0]
    captured = json.loads(stats.read_text())
    effective = captured['effective_config']
    if not isinstance(effective, dict) or not effective:
        raise ValueError('mock effective_config is missing or empty')
    rows = [json.loads(line) for line in config.read_text().splitlines() if line.strip()]
    if not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError('run configuration contains no valid records')
    for row in rows:
        row['mock_gateway'] = effective
    temporary = config.with_suffix(config.suffix + '.mock-tmp')
    temporary.write_text(''.join(json.dumps(row, sort_keys=True) + '\n' for row in rows))
    os.replace(temporary, config)
    (config.parent / 'mock-stats.json').write_text(json.dumps(captured, sort_keys=True) + '\n')
    destination = root / (outdir + '.tar.gz')
    fd, temporary_archive = tempfile.mkstemp(prefix=outdir + '.', suffix='.partial', dir=root)
    os.close(fd)
    try:
        with tarfile.open(temporary_archive, 'w:gz') as archive:
            archive.add(config.parent, arcname=outdir)
        os.replace(temporary_archive, destination)
    finally:
        Path(temporary_archive).unlink(missing_ok=True)
    return destination


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('root', type=Path)
    parser.add_argument('outdir')
    parser.add_argument('stats', type=Path)
    args = parser.parse_args()
    try:
        print(finalize(args.root, args.outdir, args.stats))
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        parser.exit(2, f'mock archive finalization failed: {error}\n')
