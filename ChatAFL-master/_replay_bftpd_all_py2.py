from __future__ import print_function

import csv
import os
import tarfile
import tempfile
import subprocess
import time
import sys

RESULTS_DIR = '/host_results'
OUT_NAME = os.environ.get('OUT_NAME', 'replayability_full_report.csv')
OUT_CSV = os.path.join(RESULTS_DIR, OUT_NAME)
REPORT_FIELDS = ['tar', 'fuzzer', 'run', 'sample', 'replay_rc', 'server_rc', 'reproduced', 'note']
SERVER_CMD = ['/home/ubuntu/experiments/bftpd/bftpd', '-D', '-c', '/home/ubuntu/experiments/basic.conf']
REPLAYER = '/home/ubuntu/aflnet/aflnet-replay'
REPLAY_WAIT_SECONDS = 8
SERVER_WAIT_SECONDS = 3
SHARD_INDEX = int(os.environ.get('SHARD_INDEX', '-1'))
SHARD_COUNT = int(os.environ.get('SHARD_COUNT', '1'))


def parse_archive_name(name):
    if name.endswith('.tar.gz'):
        base = name[:-7]
    elif name.endswith('.tar'):
        base = name[:-4]
    else:
        base = name
    if not base.startswith('out-'):
        return None, None
    parts = base.split('-')
    if len(parts) < 3:
        return None, None
    fuzzer = '-'.join(parts[2:-1]) if len(parts) > 3 else parts[2]
    run = parts[-1] if parts[-1].isdigit() else None
    return fuzzer, run


def is_crash_member(member):
    return member.isfile() and '/replayable-crashes/' in member.name and os.path.basename(member.name).startswith('id')


def load_existing_report():
    if not os.path.exists(OUT_CSV):
        return [], set()

    with open(OUT_CSV, 'r') as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    completed = set()
    for row in rows:
        tar_name = row.get('tar')
        sample = row.get('sample')
        if tar_name and sample:
            completed.add((tar_name, sample))
    return rows, completed


def write_row(handle, row):
    writer = csv.DictWriter(handle, fieldnames=REPORT_FIELDS)
    writer.writerow(row)
    handle.flush()
    os.fsync(handle.fileno())


def wait_for_process(proc, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc = proc.poll()
        if rc is not None:
            return rc
        time.sleep(0.2)
    return None


def replay_one(case_bytes):
    tmp_fd, case_path = tempfile.mkstemp(prefix='bftpd-case-', suffix='.bin')
    try:
        os.write(tmp_fd, case_bytes)
        os.close(tmp_fd)
    except Exception:
        try:
            os.close(tmp_fd)
        except Exception:
            pass
        try:
            os.unlink(case_path)
        except OSError:
            pass
        raise

    srv = subprocess.Popen(SERVER_CMD, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rep_rc = None
    srv_rc = None
    note = ''
    try:
        time.sleep(0.5)
        rep = subprocess.Popen([REPLAYER, case_path, 'FTP', '21', '1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        rep_rc = wait_for_process(rep, REPLAY_WAIT_SECONDS)
        if rep_rc is None:
            note = 'replay_timeout'
            rep.kill()
            rep_rc = rep.wait()

        srv_rc = wait_for_process(srv, SERVER_WAIT_SECONDS)
        if srv_rc is None:
            note = note or 'server_timeout'
    finally:
        if srv.poll() is None:
            try:
                srv.terminate()
                srv_rc = wait_for_process(srv, 2)
            except Exception:
                pass
        if srv.poll() is None:
            try:
                srv.kill()
                srv_rc = srv.wait()
            except Exception:
                pass
        try:
            os.unlink(case_path)
        except OSError:
            pass

    reproduced = srv_rc is not None and srv_rc != 0
    return rep_rc, srv_rc, reproduced, note


def main():
    tar_paths = sorted([
        os.path.join(RESULTS_DIR, name)
        for name in os.listdir(RESULTS_DIR)
        if name.startswith('out-') and name.endswith('.tar.gz')
    ])
    if SHARD_COUNT > 1 and SHARD_INDEX >= 0:
        tar_paths = [path for index, path in enumerate(tar_paths) if index % SHARD_COUNT == SHARD_INDEX]

    rows, completed = load_existing_report()
    seen = len(rows)
    reproduced = 0
    unreproduced = 0
    failed = 0
    for row in rows:
        reproduced_value = str(row.get('reproduced', '')).lower()
        note_value = str(row.get('note', ''))
        if reproduced_value == 'true':
            reproduced += 1
        elif reproduced_value == 'false':
            unreproduced += 1
        if note_value.startswith('exception:'):
            failed += 1

    csv_exists = os.path.exists(OUT_CSV) and os.path.getsize(OUT_CSV) > 0
    out_handle = open(OUT_CSV, 'a')
    try:
        if not csv_exists:
            writer = csv.DictWriter(out_handle, fieldnames=REPORT_FIELDS)
            writer.writeheader()
            out_handle.flush()
            os.fsync(out_handle.fileno())

        for tar_path in tar_paths:
            fuzzer, run = parse_archive_name(os.path.basename(tar_path))
            if not fuzzer:
                continue

            with tarfile.open(tar_path, 'r:gz') as tf:
                members = [member for member in tf.getmembers() if is_crash_member(member)]
                members.sort(key=lambda member: member.name)
                for member in members:
                    key = (os.path.basename(tar_path), os.path.basename(member.name))
                    if key in completed:
                        continue

                    seen += 1
                    case_bytes = tf.extractfile(member).read()
                    try:
                        rep_rc, srv_rc, ok, note = replay_one(case_bytes)
                    except Exception as exc:
                        rep_rc, srv_rc, ok = None, None, False
                        note = 'exception:%s:%s' % (type(exc).__name__, exc)
                        failed += 1
                    else:
                        if ok:
                            reproduced += 1
                        else:
                            unreproduced += 1

                    row = {
                        'tar': os.path.basename(tar_path),
                        'fuzzer': fuzzer,
                        'run': run,
                        'sample': os.path.basename(member.name),
                        'replay_rc': rep_rc,
                        'server_rc': srv_rc,
                        'reproduced': ok,
                        'note': note,
                    }
                    rows.append(row)
                    completed.add(key)
                    write_row(out_handle, row)

                    if seen % 25 == 0:
                        print('PROGRESS %d samples | reproduced=%d unreproduced=%d failed=%d' % (seen, reproduced, unreproduced, failed))
                        sys.stdout.flush()
    finally:
        out_handle.close()

    total = seen
    print('=== FINAL SUMMARY ===')
    print('TOTAL=%d' % total)
    print('REPRODUCED=%d' % reproduced)
    print('UNREPRODUCED=%d' % unreproduced)
    print('FAILED=%d' % failed)
    if total:
        print('REPRO_RATE=%.4f' % (float(reproduced) / float(total)))
        print('UNREPRO_RATE=%.4f' % (float(unreproduced) / float(total)))
    print('OUTPUT=%s' % OUT_CSV)


if __name__ == '__main__':
    main()
