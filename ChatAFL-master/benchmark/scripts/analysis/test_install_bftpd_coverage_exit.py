"""Coverage-only BFTPD build policy regression checks."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest import mock

import install_bftpd_coverage_exit as installer
import coverage_v4 as coverage


class InstallerTests(unittest.TestCase):
    def login_fixture(self):
        return ("char *mygetpwuid(int uid, FILE * file, char *name) { return 0; }\n" +
                "int login(void) { return chroot(initial) || chroot(regular) || "
                "chroot(anonymous) || chroot(file_auth); }\n")

    def commands_fixture(self):
        return ("int sock;\n"
                "int dataconn()\n"
                "{\n"
                "\tstruct sockaddr foo;\n"
                "\tstruct sockaddr_in local;\n"
                "\tif (pasv) {\n"
                "\t\tsock = 2;//accept(pasvsock, 0, 0);\n"
                "        close(pasvsock);\n"
                "        prepare_sock(sock);\n"
                "\t} else {\n"
                "\t\tsock = socket(AF_INET, SOCK_STREAM, 0);\n"
                "\t\tif (!strcasecmp(config_getoption(\"DATAPORT20\"), \"yes\")) {\n"
                "\t\t\tlocal.sin_port = htons(20);\n"
                "\t\t}\n"
                "\t\tif (bind(sock, (struct sockaddr *) &local, sizeof(local)) < 0) {\n"
                "\t\t\treturn 1;\n"
                "\t\t}\n"
                "\t\tsa.sin_family = AF_INET;\n"
                "\t\tif (0) {//connect(sock, (struct sockaddr *) &sa, sizeof(sa)) == -1) {\n"
                "\t\t\treturn 1;\n"
                "\t\t}\n"
                "\t}\n"
                "\tcontrol_printf(SL_SUCCESS, \"150 %s data connection established.\",\n"
                "\t               xfertype == TYPE_BINARY ? \"BINARY\" : \"ASCII\");\n"
                "\treturn 0;\n"
                "}\n"
                "void command_port(char *params) {\n"
                "  if (pasv) {\n"
                "    if (sock != 2) close(sock);\n"
                "    pasv = 0;\n"
                "  }\n"
                "}\n"
                "void command_eprt(char *params) {\n"
                "    if (pasv) {\n"
                "        if (sock != 2) close(sock);\n"
                "        pasv = 0;\n"
                "    }\n"
                "}\n"
                "void command_pasv(char *foo) {}\n"
                "void command_retr() {\n"
                "\tgzfile = gzdopen(sock, \"wb\");\n"
                "\tgzfile = gzdopen(sock, \"wb\");\n"
                "}\n\n" +
                "if (sock != 2) close(sock);\n" * 9 +
                "void init_userinfo() {}\n")

    def test_active_data_channel_uses_owned_control_fd_and_is_strict(self):
        patched = installer.patch_data_channel(self.commands_fixture())
        self.assertEqual(patched.count(installer.DATA_CHANNEL_MARKER), 1)
        self.assertIn("\n\t\tsock = dup(2);\n", patched)
        self.assertIn("if (sock < 0)", patched)
        self.assertNotIn("socket(AF_INET, SOCK_STREAM, 0)", patched)
        self.assertEqual(patched.count(installer.DATA_CHANNEL_OWNERSHIP_MARKER), 2)
        self.assertIn("int owned_fd = dup(fd);", patched)
        self.assertIn("stream = gzdopen(owned_fd, mode);", patched)
        self.assertIn("if (stream == NULL)\n        close(owned_fd);", patched)
        self.assertEqual(patched.count('coverage_replay_gzdopen(sock, "wb")'), 2)
        self.assertEqual(patched.count(installer.PASSIVE_FD_OWNERSHIP_MARKER), 1)
        self.assertEqual(patched.count("if (pasvsock >= 0) { close(pasvsock); pasvsock = -1; }"), 2)
        self.assertIn("close(pasvsock);\n        pasvsock = -1;\n"
                      "        prepare_sock(sock);", patched)
        self.assertIn("int sock = -1;", patched)
        self.assertEqual(patched.count(installer.DATA_SOCKET_LIFECYCLE_MARKER), 1)
        self.assertEqual(patched.count(
            "if (sock >= 0 && sock != 2) { close(sock); sock = -1; }"), 9)
        self.assertEqual(installer.patch_data_channel(patched), patched)
        with self.assertRaisesRegex(ValueError, "active dataconn"):
            installer.patch_data_channel(self.commands_fixture().replace(
                "if (0) {//connect", "if (connect"))

    def test_partial_gzip_fd_ownership_policy_fails_closed(self):
        patched = installer.patch_data_channel(self.commands_fixture())
        partially_reverted = patched.replace(
            'coverage_replay_gzdopen(sock, "wb")', 'gzdopen(sock, "wb")', 1)
        with self.assertRaisesRegex(ValueError, "partial"):
            installer.patch_data_channel(partially_reverted)

        missing_call = patched.replace(
            'coverage_replay_gzdopen(sock, "wb")', "gzdopen(NULL, \"wb\")", 1)
        with self.assertRaisesRegex(ValueError, "partial"):
            installer.patch_data_channel(missing_call)

    def test_partial_passive_fd_policy_fails_closed(self):
        patched = installer.patch_data_channel(self.commands_fixture())
        broken = patched.replace(
            "if (pasvsock >= 0) { close(pasvsock); pasvsock = -1; }",
            "if (sock != 2) close(sock);", 1)
        with self.assertRaisesRegex(ValueError, "partial bftpd passive"):
            installer.patch_data_channel(broken)

    def test_partial_data_socket_lifecycle_fails_closed(self):
        patched = installer.patch_data_channel(self.commands_fixture())
        broken = patched.replace("int sock = -1;", "int sock;", 1)
        with self.assertRaisesRegex(ValueError, "partial bftpd data socket"):
            installer.patch_data_channel(broken)

    def test_legacy_control_fd_policy_is_upgraded(self):
        patched = installer.patch_data_channel(self.commands_fixture())
        legacy = patched.replace("sock = dup(2);", "sock = 2;")
        legacy = legacy.replace(
            "\t\t * Own a duplicate so data-stream cleanup never closes fd 2. */\n"
            "\t\tsock = 2;\n"
            "\t\tif (sock < 0) {\n"
            "\t\t\tcontrol_printf(SL_FAILURE,\n"
            "\t\t\t              \"425-Unable to duplicate coverage data channel.\\r\\n425 %s.\",\n"
            "\t\t\t              strerror(errno));\n"
            "\t\t\treturn 1;\n"
            "\t\t}\n",
            "\t\t * the coverage subject's passive-mode data-channel policy. */\n"
            "\t\tsock = 2;\n")
        upgraded = installer.patch_data_channel(legacy)
        self.assertIn("sock = dup(2);", upgraded)
        self.assertEqual(installer.patch_data_channel(upgraded), upgraded)

    def test_all_four_chroot_paths_and_idempotence(self):
        result = installer.patch_chroot(self.login_fixture())
        self.assertEqual(result.count("coverage_replay_chroot("), 5)
        self.assertIn('result == 0 && unsetenv("GCOV_PREFIX")', result)
        self.assertEqual(installer.patch_chroot(result), result)

    def test_unknown_or_partial_chroot_layout_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "chroot layout"):
            installer.patch_chroot(self.login_fixture().replace("chroot(file_auth)", "0"))
        patched = installer.patch_chroot(self.login_fixture())
        with self.assertRaisesRegex(ValueError, "partial"):
            installer.patch_chroot(patched.replace("coverage_replay_chroot(file_auth)", "chroot(file_auth)"))

    def test_installer_rebuilds_all_objects_with_pinned_seed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "bftpd-gcov"
            root.mkdir()
            (root / "main.gcno").write_bytes(b"fixture")
            (root / "main.c").write_text(installer.MARKER)
            (root / "login.c").write_text(self.login_fixture())
            (root / "commands.c").write_text(self.commands_fixture())
            (root / "Makefile").write_text("CFLAGS=-fprofile-arcs -ftest-coverage\n")
            (root / "bftpd").write_text(installer.MARKER + installer.CHROOT_MARKER +
                                         installer.DATA_CHANNEL_MARKER +
                                         installer.DATA_CHANNEL_OWNERSHIP_MARKER +
                                         installer.PASSIVE_FD_OWNERSHIP_MARKER +
                                         installer.DATA_SOCKET_LIFECYCLE_MARKER)
            with mock.patch.object(installer.subprocess, "run") as build:
                installer.install(root)
                installer.install(root)
            self.assertEqual((root / "Makefile").read_text().count(installer.BUILD_MARKER), 1)
            self.assertIn("-frandom-seed=" + installer.BUILD_SEED, (root / "Makefile").read_text())
            policy = json.loads((root / "coverage-exit-policy.json").read_text())
            self.assertEqual(policy["data_channel_policy"], installer.DATA_CHANNEL_MARKER)
            self.assertEqual(policy["data_channel_fd_ownership"],
                             installer.DATA_CHANNEL_OWNERSHIP_MARKER)
            self.assertEqual(policy["passive_fd_ownership"],
                             installer.PASSIVE_FD_OWNERSHIP_MARKER)
            self.assertEqual(policy["data_socket_lifecycle"],
                             installer.DATA_SOCKET_LIFECYCLE_MARKER)
            self.assertEqual(build.call_args.args[0], ["make", "-B", "-j2"])
            self.assertEqual(build.call_args.kwargs["env"]["SOURCE_DATE_EPOCH"], "1")
            self.assertTrue(coverage.bftpd_exit_policy(root)["verified"])
            (root / "bftpd").write_text((root / "bftpd").read_text().replace(
                installer.DATA_CHANNEL_OWNERSHIP_MARKER, "missing-fd-ownership"))
            with self.assertRaisesRegex(coverage.CoverageError, "data-channel"):
                coverage.bftpd_exit_policy(root)
            (root / "bftpd").write_text(installer.MARKER + installer.CHROOT_MARKER +
                                         installer.DATA_CHANNEL_MARKER +
                                         installer.DATA_CHANNEL_OWNERSHIP_MARKER +
                                         installer.PASSIVE_FD_OWNERSHIP_MARKER +
                                         installer.DATA_SOCKET_LIFECYCLE_MARKER)
            (root / "login.c").write_text("/* legacy login without chroot policy */")
            with self.assertRaisesRegex(coverage.CoverageError, "chroot policy"):
                coverage.bftpd_exit_policy(root)

    def test_bftpd_replay_forwards_file_auth_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "file-auth.conf"
            config.write_text('global { FILE_AUTH="/tmp/fixture-auth" }\n')
            with mock.patch.dict(coverage.os.environ, {"COVERAGE_V4_TARGET_CONFIG": str(config)}):
                # This test checks command construction; the strict replayer
                # capability check is exercised by coverage-v4 integration
                # tests and should not depend on a machine-specific install.
                with mock.patch.object(coverage, "loopfuzz_replayer",
                                        return_value="/tmp/aflnet-replay"):
                    _, server = coverage.replay_commands("bftpd", "input", 21, 1,
                                                         Path(temporary), Path(temporary))
            self.assertEqual(server[-2:], ["-c", str(config)])


if __name__ == "__main__":
    unittest.main()
