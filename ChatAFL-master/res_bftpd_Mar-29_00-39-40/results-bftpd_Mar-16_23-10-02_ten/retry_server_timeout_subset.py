from __future__ import print_function

import csv
import os
import tarfile
import tempfile
import subprocess
import time

RESULTS_DIR = '/host_results'
INPUT_CSV = os.environ.get('INPUT_CSV', os.path.join(RESULTS_DIR, 'retry_server_timeout_50.csv'))
OUT_CSV = os.environ.get('OUT_CSV', os.path.join(RESULTS_DIR, 'retry_50_results.csv'))
REPORT_FIELDS = ['tar', 'fuzzer', 'run', 'sample', 'replay_rc', 'server_rc', 'reproduced', 'note']

SERVER_CMD = ['/home/ubuntu/experiments/bftpd/bftpd', '-D', '-c', '/home/ubuntu/experiments/basic.conf']
REPLAYER = '/home/ubuntu/aflnet/aflnet-replay'

try:
    REPLAY_WAIT_SECONDS = int(os.environ.get('REPLAY_WAIT_SECONDS', '30'))
    SERVER_WAIT_SECONDS = int(os.environ.get('SERVER_WAIT_SECONDS', '10'))
except Exception:
    REPLAY_WAIT_SECONDS = 30
    SERVER_WAIT_SECONDS = 10


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
            try:
                rep.kill()
            except Exception:
                pass
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
    if not os.path.exists(INPUT_CSV):
        print('INPUT CSV not found:', INPUT_CSV)
        return

    to_run = []
    with open(INPUT_CSV) as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            to_run.append(row)

    out_exists = os.path.exists(OUT_CSV) and os.path.getsize(OUT_CSV) > 0
    processed = set()
    if out_exists:
        with open(OUT_CSV) as oh:
            r = csv.DictReader(oh)
            for rr in r:
                processed.add((rr.get('tar'), rr.get('sample')))

    out_handle = open(OUT_CSV, 'a')
    try:
        if not out_exists:
            writer = csv.DictWriter(out_handle, fieldnames=REPORT_FIELDS)
            writer.writeheader()
            out_handle.flush()
            os.fsync(out_handle.fileno())

        for idx, row in enumerate(to_run):
            tar_name = row['tar']
            sample = row['sample']
            if (tar_name, sample) in processed:
                print('SKIP already processed', tar_name, sample)
                continue
            tar_path = os.path.join(RESULTS_DIR, tar_name)
            print('PROCESSING', idx+1, 'of', len(to_run), tar_name, sample)
            try:
                with tarfile.open(tar_path, 'r:gz') as tf:
                    members = [m for m in tf.getmembers() if os.path.basename(m.name) == sample]
                    if not members:
                        out_row = dict(zip(REPORT_FIELDS, [tar_name, row.get('fuzzer'), row.get('run'), sample, None, None, False, 'missing_in_tar']))
                        csv.DictWriter(out_handle, fieldnames=REPORT_FIELDS).writerow(out_row)
                        out_handle.flush()
                        continue
                    member = members[0]
                    case_bytes = tf.extractfile(member).read()
                    rep_rc, srv_rc, ok, note = replay_one(case_bytes)
            except Exception as exc:
                rep_rc, srv_rc, ok = None, None, False
                note = 'exception:%s' % (exc,)

            out_row = {
                'tar': tar_name,
                'fuzzer': row.get('fuzzer'),
                'run': row.get('run'),
                'sample': sample,
                'replay_rc': rep_rc,
                'server_rc': srv_rc,
                'reproduced': ok,
                'note': note,
            }
            csv.DictWriter(out_handle, fieldnames=REPORT_FIELDS).writerow(out_row)
            out_handle.flush()
            os.fsync(out_handle.fileno())
    finally:
        out_handle.close()

    print('DONE. OUTPUT=', OUT_CSV)


if __name__ == '__main__':
    main()
