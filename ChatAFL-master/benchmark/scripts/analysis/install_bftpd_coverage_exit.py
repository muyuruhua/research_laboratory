#!/usr/bin/env python3
"""Install an auditable SIGPIPE normal-exit policy in a BFTPD gcov tree only.

The coverage subject already replaces fork/data-channel behavior. A closed peer
can terminate it with SIGPIPE before libgcov writes any counters. Route only that
signal to an async-safe flag and leave the command loop through normal cleanup.
No crash signal is hidden
and no libgcov routine is called directly from a signal handler.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

MARKER = "COVERAGE_REPLAY_SIGPIPE_NORMAL_EXIT_V2"
CHROOT_MARKER = "COVERAGE_REPLAY_CHROOT_GCOV_PREFIX_V1"
BUILD_MARKER = "COVERAGE_REPLAY_REPRODUCIBLE_BUILD_V1"
BUILD_SEED = "loopfuzz-bftpd-coverage-v1"
SOURCE_DATE_EPOCH = "1"
CHROOT_FUNCTION = '''
/* COVERAGE_REPLAY_CHROOT_GCOV_PREFIX_V1: measurement build only.
 * GCOV_PREFIX already names the jail in the parent namespace.  After a
 * successful chroot, compiled-in object paths resolve inside that jail;
 * retaining the prefix would write to a second, nested jail instead.
 * Use this for regular, anonymous and FILE_AUTH logins alike. */
static int coverage_replay_chroot(const char *path)
{
    int result = chroot(path);
    if (result == 0 && unsetenv("GCOV_PREFIX") != 0) {
        perror("COVERAGE_REPLAY_CHROOT_GCOV_PREFIX_V1");
        exit(2);
    }
    return result;
}

'''
FUNCTION = '''
/* COVERAGE_REPLAY_SIGPIPE_NORMAL_EXIT_V2: measurement build only.
 * Request normal cleanup at the next command-loop boundary.
 * Only signal/write/flag run in the handler; libgcov dumps via atexit.
 * The trace fd was opened before
 * chroot/setuid; protocol fd 2 is never used for this diagnostic. */
static int coverage_replay_exit_fd = -1;
static volatile sig_atomic_t coverage_replay_broken_peer = 0;
static void coverage_replay_sigpipe(int signum)
{
    static const char message[] = "COVERAGE_REPLAY_SIGPIPE_NORMAL_EXIT_V2\\n";
    signal(SIGPIPE, SIG_IGN);
    if (coverage_replay_exit_fd >= 0)
        (void) write(coverage_replay_exit_fd, message, sizeof(message) - 1);
    coverage_replay_broken_peer = 1;
}

'''
ARM = '''
        /* COVERAGE_REPLAY_SIGPIPE_NORMAL_EXIT_V2 */
        {
            const char *trace = getenv("COVERAGE_V4_EXIT_TRACE");
            if (trace && trace[0]) {
                coverage_replay_exit_fd = open(trace, O_WRONLY | O_CREAT | O_APPEND, 0600);
                if (coverage_replay_exit_fd < 0) {
                    perror("coverage exit trace");
                    exit(2);
                }
                signal(SIGPIPE, coverage_replay_sigpipe);
            }
        }
'''

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def patch_chroot(text):
    """Cover every login chroot; reject an unknown source instead of guessing."""
    if CHROOT_MARKER in text:
        if len(re.findall(r"\bcoverage_replay_chroot\s*\(", text)) != 5:
            raise ValueError("partial bftpd coverage chroot policy")
        return text
    anchor = "char *mygetpwuid(int uid, FILE * file, char *name)"
    if text.count(anchor) != 1 or len(re.findall(r"\bchroot\s*\(", text)) != 4:
        raise ValueError("unexpected bftpd login.c chroot layout")
    text = re.sub(r"\bchroot\s*\(", "coverage_replay_chroot(", text)
    return text.replace(anchor, CHROOT_FUNCTION + anchor)


def install(root, rebuild=True):
    root = root.resolve()
    if root.name != "bftpd-gcov" or not list(root.glob("*.gcno")):
        raise ValueError("refusing non-instrumented/non-bftpd-gcov tree")
    path = root / "main.c"
    before = sha(path)
    text = path.read_text()
    if MARKER not in text:
        anchor = "void handler_sigalrm(int signum)"
        arm_anchor = "atexit(end_child);"
        if text.count(anchor) != 1 or text.count(arm_anchor) != 1:
            raise ValueError("unexpected bftpd main.c; patch anchors are not unique")
        loop_anchor = "while (fgets(str, MAXCMD, stdin))"
        if text.count(loop_anchor) != 1:
            raise ValueError("unexpected command loop; refusing partial patch")
        text = text.replace(anchor, FUNCTION + anchor).replace(arm_anchor, arm_anchor + ARM)
        text = text.replace(loop_anchor, "while (!coverage_replay_broken_peer && fgets(str, MAXCMD, stdin))")
        path.write_text(text)
    login = root / "login.c"
    login_before = sha(login)
    login.write_text(patch_chroot(login.read_text()))
    makefile = root / "Makefile"
    make_text = makefile.read_text()
    if BUILD_MARKER not in make_text:
        makefile.write_text(make_text + "\n# " + BUILD_MARKER + "\n" +
                            "CFLAGS += -frandom-seed=" + BUILD_SEED + "\n")
    if rebuild:
        env = os.environ.copy()
        env["SOURCE_DATE_EPOCH"] = SOURCE_DATE_EPOCH
        # Rebuild every object, so inherited image gcno stamps cannot leave
        # different per-arm measurement identities.  GCC's fixed random seed
        # pins gcno stamps as well as compiler-generated symbol randomness.
        subprocess.run(["make", "-B", "-j2"], cwd=root, env=env, check=True)
    binary = root / "bftpd"
    if rebuild and any(marker.encode() not in binary.read_bytes()
                       for marker in (MARKER, CHROOT_MARKER)):
        raise ValueError("build does not contain the exit/chroot policy markers")
    result = dict(policy=MARKER, source_before_sha256=before, source_sha256=sha(path),
                  chroot_policy=CHROOT_MARKER, login_before_sha256=login_before,
                  login_sha256=sha(login),
                  reproducible_build=dict(source_date_epoch=SOURCE_DATE_EPOCH,
                                          random_seed=BUILD_SEED, forced_all_objects=True),
                  binary_sha256=sha(binary), rebuilt=rebuild,
                  scope="coverage build only; does not modify the fuzz target")
    (root / "coverage-exit-policy.json").write_text(json.dumps(result, indent=2) + "\n")
    return result

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--no-build", action="store_true")
    args = parser.parse_args()
    print(json.dumps(install(args.root, not args.no_build), sort_keys=True))

if __name__ == "__main__":
    main()
