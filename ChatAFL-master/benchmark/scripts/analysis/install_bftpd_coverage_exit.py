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
DATA_CHANNEL_MARKER = "COVERAGE_REPLAY_DATA_CHANNEL_CONTROL_FD_V1"
DATA_CHANNEL_OWNERSHIP_MARKER = "COVERAGE_REPLAY_DATA_CHANNEL_DUP_FD_OWNERSHIP_V1"
PASSIVE_FD_OWNERSHIP_MARKER = "COVERAGE_REPLAY_PASSIVE_TO_ACTIVE_FD_OWNERSHIP_V1"
DATA_SOCKET_LIFECYCLE_MARKER = "COVERAGE_REPLAY_DATA_SOCKET_LIFECYCLE_V1"
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


def _active_dataconn_block(text):
    """Return the active-mode dataconn branch and its replacement bounds.

    The gcov patch intentionally disables the real active data connection, but
    leaves the socket creation and bind in place.  A subsequent data write
    therefore targets an unconnected socket and raises SIGPIPE.  Keep this
    source-layout check strict: silently patching a different BFTPD revision
    would invalidate the replay evidence.
    """
    function_start = text.find("int dataconn()")
    function_end = text.find("void init_userinfo", function_start + 1)
    if (function_start < 0 or function_end < 0 or
            text.count("int dataconn()") != 1):
        raise ValueError("unexpected bftpd commands.c dataconn layout")
    pasv_start = text.find("\tif (pasv) {", function_start, function_end)
    active_start = text.find("\t} else {", pasv_start + 1, function_end)
    reply_start = text.find(
        '\n\tcontrol_printf(SL_SUCCESS, "150 %s data connection established.",',
        active_start, function_end)
    if min(pasv_start, active_start, reply_start) < 0:
        raise ValueError("unexpected bftpd commands.c dataconn branch layout")
    if text.find("\t} else {", active_start + 1, function_end) >= 0:
        raise ValueError("ambiguous bftpd commands.c active dataconn branch")
    return active_start, reply_start, text[active_start:reply_start]


GZIP_FD_HELPER = '''
/* COVERAGE_REPLAY_DATA_CHANNEL_DUP_FD_OWNERSHIP_V1: measurement build only.
 * Keep gzclose() from closing either the control stream (fd 2) or the data
 * channel descriptor owned by command cleanup. */
static const char coverage_replay_data_channel_fd_ownership[] __attribute__((used)) =
    "COVERAGE_REPLAY_DATA_CHANNEL_DUP_FD_OWNERSHIP_V1";
#ifdef HAVE_ZLIB_H
static gzFile coverage_replay_gzdopen(int fd, const char *mode)
{
    int owned_fd = dup(fd);
    gzFile stream;
    if (owned_fd < 0)
        return NULL;
    stream = gzdopen(owned_fd, mode);
    if (stream == NULL)
        close(owned_fd);
    return stream;
}
#endif

'''


def patch_gzip_fd_ownership(text):
    """Give each zlib stream a descriptor separate from command cleanup."""
    if DATA_CHANNEL_OWNERSHIP_MARKER in text:
        wrapped_call = 'coverage_replay_gzdopen(sock, "wb")'
        unwrapped_text = text.replace(wrapped_call, "")
        if (text.count(DATA_CHANNEL_OWNERSHIP_MARKER) != 2 or
                text.count(wrapped_call) != 2 or
                'gzdopen(sock, "wb")' in unwrapped_text):
            raise ValueError("partial bftpd gzip data-channel fd ownership policy")
        return text
    if text.count('gzdopen(sock, "wb")') != 2:
        raise ValueError("unexpected bftpd compressed-output gzdopen layout")
    text = text.replace('gzdopen(sock, "wb")',
                        'coverage_replay_gzdopen(sock, "wb")')
    anchor = "int dataconn()"
    if text.count(anchor) != 1:
        raise ValueError("unexpected bftpd commands.c dataconn layout")
    return text.replace(anchor, GZIP_FD_HELPER + anchor)


def patch_passive_fd_ownership(text):
    """Close the passive listener, never the unspecialized data socket.

    Before dataconn runs, the global sock is zero. PASV followed by PORT or
    EPRT used to close fd 0, terminating the control read loop without 221.
    """
    dataconn = text.find("int dataconn()")
    port = text.find("void command_port(char *params)")
    pasv = text.find("void command_pasv(char *foo)")
    if min(dataconn, port, pasv) < 0 or not dataconn < port < pasv:
        raise ValueError("unexpected bftpd passive/data command layout")
    data_block = text[dataconn:port]
    command_block = text[port:pasv]
    old_close = "if (sock != 2) close(sock);"
    new_close = "if (pasvsock >= 0) { close(pasvsock); pasvsock = -1; }"
    if PASSIVE_FD_OWNERSHIP_MARKER in text:
        if (text.count(PASSIVE_FD_OWNERSHIP_MARKER) != 1 or
                old_close in command_block or command_block.count(new_close) != 2 or
                "close(pasvsock);\n        pasvsock = -1;\n        prepare_sock(sock);" not in data_block):
            raise ValueError("partial bftpd passive fd ownership policy")
        return text
    old_data = "close(pasvsock);\n        prepare_sock(sock);"
    if data_block.count(old_data) != 1 or command_block.count(old_close) != 2:
        raise ValueError("unexpected bftpd passive fd closure layout")
    data_block = data_block.replace(old_data,
                                    "close(pasvsock);\n        pasvsock = -1;\n"
                                    "        prepare_sock(sock);")
    command_block = command_block.replace(old_close, new_close)
    marker = ("/* Measurement-only passive listener ownership. */\n"
              "static const char coverage_replay_passive_fd_policy[] __attribute__((used)) =\n"
              '    "' + PASSIVE_FD_OWNERSHIP_MARKER + '";\n')
    return text[:dataconn] + data_block + marker + command_block + text[pasv:]


def patch_data_socket_lifecycle(text):
    """Keep uninitialized or already-closed data fds away from control fd 0."""
    guarded_close = "if (sock >= 0 && sock != 2) { close(sock); sock = -1; }"
    old_close = re.compile(r"if\s*\(sock\s*!=\s*2\)\s*close\(sock\);")
    if DATA_SOCKET_LIFECYCLE_MARKER in text:
        if (text.count(DATA_SOCKET_LIFECYCLE_MARKER) != 1 or
                text.count("int sock = -1;") != 1 or
                text.count(guarded_close) != 9 or old_close.search(text)):
            raise ValueError("partial bftpd data socket lifecycle policy")
        return text
    if text.count("int sock;") != 1 or len(old_close.findall(text)) != 9:
        raise ValueError("unexpected bftpd data socket lifecycle layout")
    marker = ("/* Measurement-only data socket lifecycle. */\n"
              "static const char coverage_replay_data_socket_lifecycle[] __attribute__((used)) =\n"
              '    "' + DATA_SOCKET_LIFECYCLE_MARKER + '";\n')
    text = text.replace("int sock;", "int sock = -1;\n" + marker)
    return old_close.sub(guarded_close, text)


def patch_data_channel(text):
    """Use an owned duplicate of control fd 2 for coverage data writes."""
    replacement = (
        "\t} else {\n"
        "\t\tstatic const char coverage_replay_data_channel_policy[] __attribute__((used)) =\n"
        "\t\t    \"" + DATA_CHANNEL_MARKER + "\";\n"
        "\t\t/* active data-channel policy: measurement build only.\n"
        "\t\t * Active-mode data uses the replay control stream, matching\n"
        "\t\t * the coverage subject's passive-mode data-channel policy.\n"
        "\t\t * Own a duplicate so data-stream cleanup never closes fd 2. */\n"
        "\t\tsock = dup(2);\n"
        "\t\tif (sock < 0) {\n"
        "\t\t\tcontrol_printf(SL_FAILURE,\n"
        "\t\t\t              \"425-Unable to duplicate coverage data channel.\\r\\n425 %s.\",\n"
        "\t\t\t              strerror(errno));\n"
        "\t\t\treturn 1;\n"
        "\t\t}\n"
        "\t}\n")

    if DATA_CHANNEL_MARKER in text:
        if text.count(DATA_CHANNEL_MARKER) != 1:
            raise ValueError("partial bftpd active data-channel policy")
        active_start, reply_start, block = _active_dataconn_block(text)
        expected = replacement.rstrip("\n")
        if block.rstrip("\n") != expected:
            # Upgrade the exact V1 implementation that assigned sock = 2.
            legacy = expected.replace(
                "\t\t * Own a duplicate so data-stream cleanup never closes fd 2. */\n"
                "\t\tsock = dup(2);\n"
                "\t\tif (sock < 0) {\n"
                "\t\t\tcontrol_printf(SL_FAILURE,\n"
                "\t\t\t              \"425-Unable to duplicate coverage data channel.\\r\\n425 %s.\",\n"
                "\t\t\t              strerror(errno));\n"
                "\t\t\treturn 1;\n"
                "\t\t}\n",
                "\t\t * the coverage subject's passive-mode data-channel policy. */\n"
                "\t\tsock = 2;\n")
            if block.rstrip("\n") != legacy:
                raise ValueError("partial bftpd active data-channel policy")
            text = text[:active_start] + replacement + text[reply_start:]
    else:
        active_start, reply_start, block = _active_dataconn_block(text)
        # Require the gcov source shape before changing it. In particular,
        # reject the native build where active connect() is still enabled.
        required = (
            "\t\tsock = socket(AF_INET, SOCK_STREAM, 0);",
            "\t\tif (bind(sock, (struct sockaddr *) &local, sizeof(local)) < 0) {",
            "\t\tif (0) {//connect(sock, (struct sockaddr *) &sa, sizeof(sa)) == -1) {")
        if any(block.count(anchor) != 1 for anchor in required):
            raise ValueError("unexpected bftpd active dataconn branch; refusing partial patch")
        text = text[:active_start] + replacement + text[reply_start:]

    return patch_data_socket_lifecycle(
        patch_passive_fd_ownership(patch_gzip_fd_ownership(text)))


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
    commands = root / "commands.c"
    if not commands.is_file():
        raise ValueError("bftpd-gcov tree lacks commands.c")
    commands_before = sha(commands)
    commands.write_text(patch_data_channel(commands.read_text()))
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
                       for marker in (MARKER, CHROOT_MARKER, DATA_CHANNEL_MARKER,
                                      DATA_CHANNEL_OWNERSHIP_MARKER,
                                      PASSIVE_FD_OWNERSHIP_MARKER,
                                      DATA_SOCKET_LIFECYCLE_MARKER)):
        raise ValueError("build does not contain the exit/chroot policy markers")
    result = dict(policy=MARKER, source_before_sha256=before, source_sha256=sha(path),
                  chroot_policy=CHROOT_MARKER, login_before_sha256=login_before,
                  login_sha256=sha(login),
                  data_channel_policy=DATA_CHANNEL_MARKER,
                  data_channel_fd_ownership=DATA_CHANNEL_OWNERSHIP_MARKER,
                  passive_fd_ownership=PASSIVE_FD_OWNERSHIP_MARKER,
                  data_socket_lifecycle=DATA_SOCKET_LIFECYCLE_MARKER,
                  commands_before_sha256=commands_before,
                  commands_sha256=sha(commands),
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
