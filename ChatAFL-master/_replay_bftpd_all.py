import csv
import os
import tarfile
import tempfile
import subprocess
import time
from pathlib import Path
from typing import Optional, Tuple

RESULTS_DIR = Path('/host_results')
OUT_CSV = RESULTS_DIR / 'replayability_full_report.csv'
REPORT_FIELDS = ['tar', 'fuzzer', 'run', 'sample', 'replay_rc', 'server_rc', 'reproduced', 'note']

# Use the same replay contract as the benchmark's crash_script:
# aflnet-replay <testcase> FTP 21 1
# server: /home/ubuntu/experiments/bftpd/bftpd -D -c /home/ubuntu/experiments/basic.conf
SERVER_CMD = ['/home/ubuntu/experiments/bftpd/bftpd', '-D', '-c', '/home/ubuntu/experiments/basic.conf']
REPLAYER = '/home/ubuntu/aflnet/aflnet-replay'


def parse_archive_name(name: str):
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


def is_crash_member(member: tarfile.TarInfo) -> bool:
    return member.isfile() and '/replayable-crashes/' in member.name and os.path.basename(member.name).startswith('id')


def load_existing_report() -> Tuple[list, set]:
    if not OUT_CSV.exists():
        return [], set()

    with OUT_CSV.open(newline='') as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    completed = {(row['tar'], row['sample']) for row in rows if row.get('tar') and row.get('sample')}
    return rows, completed


def write_row(handle, row: dict) -> None:
    writer = csv.DictWriter(handle, fieldnames=REPORT_FIELDS)
    writer.writerow(row)
    handle.flush()
    os.fsync(handle.fileno())


def replay_one(case_bytes: bytes) -> Tuple[Optional[int], Optional[int], bool, str]:
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(case_bytes)
        case_path = tmp.name

    srv = subprocess.Popen(SERVER_CMD, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rep_rc = None
    srv_rc = None
    note = ''
    try:
        time.sleep(0.5)
        try:
            rep = subprocess.run([REPLAYER, case_path, 'FTP', '21', '1'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            rep_rc = rep.returncode
        except subprocess.TimeoutExpired:
            note = 'replay_timeout'

        # Wait for the server to exit on its own after the replay.
        try:
            srv_rc = srv.wait(timeout=4)
        except subprocess.TimeoutExpired:
            srv_rc = None
            note = note or 'server_timeout'
    finally:
        if srv.poll() is None:
            srv.terminate()
            try:
                srv_rc = srv.wait(timeout=2)
            except subprocess.TimeoutExpired:
                srv.kill()
                srv_rc = srv.wait(timeout=2)
        try:
            os.unlink(case_path)
        except OSError:
            pass

    # For this harness, non-zero exit of the server process means the replay triggered an abnormal termination.
    reproduced = (srv_rc is not None and srv_rc != 0)
    return rep_rc, srv_rc, reproduced, note


def main() -> None:
    tar_paths = sorted(RESULTS_DIR.glob('out-*.tar.gz'))
    rows, completed = load_existing_report()
    seen = len(rows)
    reproduced = sum(1 for row in rows if str(row.get('reproduced', '')).lower() == 'true')
    unreproduced = sum(1 for row in rows if str(row.get('reproduced', '')).lower() == 'false')
    failed = sum(1 for row in rows if str(row.get('note', '')).startswith('exception:'))

    OUT_CSV.parent.mkdir(parents=True, exist_ok=True)
    csv_exists = OUT_CSV.exists() and OUT_CSV.stat().st_size > 0

    with OUT_CSV.open('a', newline='') as out_handle:
        if not csv_exists:
            writer = csv.DictWriter(out_handle, fieldnames=REPORT_FIELDS)
            writer.writeheader()
            out_handle.flush()
            os.fsync(out_handle.fileno())

        for tar_path in tar_paths:
            fuzzer, run = parse_archive_name(tar_path.name)
            if not fuzzer:
                continue

            with tarfile.open(tar_path, 'r:gz') as tf:
                members = [m for m in tf.getmembers() if is_crash_member(m)]
                members.sort(key=lambda m: m.name)
                for member in members:
                    key = (tar_path.name, os.path.basename(member.name))
                    if key in completed:
                        continue

                    seen += 1
                    case_bytes = tf.extractfile(member).read()
                    try:
                        rep_rc, srv_rc, ok, note = replay_one(case_bytes)
                    except Exception as exc:
                        rep_rc, srv_rc, ok, note = None, None, False, f'exception:{type(exc).__name__}:{exc}'
                        failed += 1
                    else:
                        if ok:
                            reproduced += 1
                        else:
                            unreproduced += 1

                    row = {
                        'tar': tar_path.name,
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

                    # Progress ping every 25 newly processed samples.
                    if seen % 25 == 0:
                        print(f'PROGRESS {seen} samples | reproduced={reproduced} unreproduced={unreproduced} failed={failed}', flush=True)

    total = seen
    print('=== FINAL SUMMARY ===')
    print(f'TOTAL={total}')
    print(f'REPRODUCED={reproduced}')
    print(f'UNREPRODUCED={unreproduced}')
    print(f'FAILED={failed}')
    if total:
        print(f'REPRO_RATE={reproduced/total:.4f}')
        print(f'UNREPRO_RATE={unreproduced/total:.4f}')
    print(f'OUTPUT={OUT_CSV}')


if __name__ == '__main__':
    main()
