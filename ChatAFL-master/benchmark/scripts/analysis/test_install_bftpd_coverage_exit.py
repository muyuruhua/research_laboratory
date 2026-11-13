"""Coverage-only BFTPD build policy regression checks."""
from pathlib import Path
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
            (root / "Makefile").write_text("CFLAGS=-fprofile-arcs -ftest-coverage\n")
            (root / "bftpd").write_text(installer.MARKER + installer.CHROOT_MARKER)
            with mock.patch.object(installer.subprocess, "run") as build:
                installer.install(root)
                installer.install(root)
            self.assertEqual((root / "Makefile").read_text().count(installer.BUILD_MARKER), 1)
            self.assertIn("-frandom-seed=" + installer.BUILD_SEED, (root / "Makefile").read_text())
            self.assertEqual(build.call_args.args[0], ["make", "-B", "-j2"])
            self.assertEqual(build.call_args.kwargs["env"]["SOURCE_DATE_EPOCH"], "1")
            self.assertTrue(coverage.bftpd_exit_policy(root)["verified"])
            (root / "login.c").write_text("/* legacy login without chroot policy */")
            with self.assertRaisesRegex(coverage.CoverageError, "chroot policy"):
                coverage.bftpd_exit_policy(root)

    def test_bftpd_replay_forwards_file_auth_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary) / "file-auth.conf"
            config.write_text('global { FILE_AUTH="/tmp/fixture-auth" }\n')
            with mock.patch.dict(coverage.os.environ, {"COVERAGE_V4_TARGET_CONFIG": str(config)}):
                _, server = coverage.replay_commands("bftpd", "input", 21, 1,
                                                     Path(temporary), Path(temporary))
            self.assertEqual(server[-2:], ["-c", str(config)])


if __name__ == "__main__":
    unittest.main()
