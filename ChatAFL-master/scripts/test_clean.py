import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CleanScriptTests(unittest.TestCase):
    def run_clean(self, running=False, ps_fails=False):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            docker = directory / "docker"
            log = directory / "docker.log"
            docker.write_text("""#!/bin/bash
printf '%s\\n' "$*" >> "$DOCKER_LOG"
case "$1" in
  info) exit 0 ;;
  ps)
    if [[ "$*" == *'ancestor=bftpd:latest'* ]]; then
      if [[ "$MOCK_PS_FAIL" == 1 ]]; then
        exit 1
      fi
      if [[ "$*" == *'--all'* ]]; then
        echo stopped-bftpd
      elif [[ "$MOCK_RUNNING" == 1 ]]; then
        echo active-bftpd
      fi
    fi
    ;;
  rm|rmi) exit 0 ;;
  *) exit 2 ;;
esac
""")
            docker.chmod(0o755)
            env = os.environ.copy()
            env.update(PATH=f"{directory}:{env['PATH']}", DOCKER_LOG=str(log),
                       MOCK_RUNNING="1" if running else "0",
                       MOCK_PS_FAIL="1" if ps_fails else "0")
            result = subprocess.run(["bash", str(ROOT / "clean.sh")], cwd=ROOT,
                                    env=env, text=True, capture_output=True)
            return result, log.read_text().splitlines()

    def test_running_container_prevents_all_deletion(self):
        result, commands = self.run_clean(running=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("active-bftpd", result.stderr)
        self.assertFalse(any(cmd.startswith(("rm ", "rmi ", "stop ")) for cmd in commands))

    def test_stopped_container_can_be_removed(self):
        result, commands = self.run_clean(running=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("rm stopped-bftpd", commands)
        self.assertIn("rmi bftpd:latest", commands)
        self.assertFalse(any(cmd.startswith("stop ") for cmd in commands))

    def test_docker_query_failure_prevents_all_deletion(self):
        result, commands = self.run_clean(ps_fails=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Cannot check running containers", result.stderr)
        self.assertFalse(any(cmd.startswith(("rm ", "rmi ", "stop ")) for cmd in commands))


if __name__ == "__main__":
    unittest.main()
