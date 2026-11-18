#!/usr/bin/env python3
"""Validate archive identity against the coordinate supplied by the launcher."""
import json
import re
import sys
import tarfile

POLICIES = {'q1a1': ('direct-service', False), 'q1b1': ('no-reflow', False),
            'q1c1': ('reflow', False), 'q1d1': ('reflow', True)}

def main(path, target, arm):
    if arm not in POLICIES:
        raise ValueError('unknown arm')
    with tarfile.open(path, 'r:gz') as archive:
        members = [m for m in archive.getmembers() if m.isfile() and m.name.endswith('/run-config.jsonl')]
        if len(members) != 1:
            raise ValueError('expected one run-config')
        config = json.loads(archive.extractfile(members[0]).readline())
    policy, retain = POLICIES[arm]
    if config.get('target') != target or config.get('q1_policy') != policy or config.get('code_retain') is not retain:
        raise ValueError('target or arm policy mismatch')
    if config.get('threshold_resolved') != 1:
        raise ValueError('threshold mismatch')
    cid = config.get('campaign_id')
    if not isinstance(cid, str) or not re.fullmatch(r'[A-Za-z0-9_.-]+', cid):
        raise ValueError('invalid campaign_id')
    print(cid)

if __name__ == '__main__':
    try:
        main(*sys.argv[1:])
    except (ValueError, TypeError, OSError, tarfile.TarError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
