import base64
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / "llm_mock_v5.py"
REPO_ROOT = Path(__file__).resolve().parents[2]


def load_mock(target, protocol="HTTP"):
    # Import-time settings are globals in llm_mock_v5, so change the process
    # environment only for the duration of module loading and restore it after.
    names = ("MOCK_PROTOCOL", "MOCK_TARGET", "MOCK_LATENCY")
    previous = {name: os.environ.get(name) for name in names}
    if protocol is None:
        os.environ.pop("MOCK_PROTOCOL", None)
    else:
        os.environ["MOCK_PROTOCOL"] = protocol
    if target:
        os.environ["MOCK_TARGET"] = target
    else:
        os.environ.pop("MOCK_TARGET", None)
    os.environ["MOCK_LATENCY"] = "0"
    spec = importlib.util.spec_from_file_location(f"llm_mock_{target.replace('-', '_')}", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
    return module


class ForkedDaapdHttpProfileTest(unittest.TestCase):
    def test_forked_daapd_uses_http_attribution_and_api_templates(self):
        mock = load_mock("forked-daapd")
        self.assertEqual(mock.detect_proto("forked-daapd DAAP HTTP/1.1"), "HTTP")
        self.assertEqual(mock._is_forked_daapd_http(), True)
        templates = mock.reply_for("list all message templates", count_reply_class=False)
        self.assertIn("GET /api/config", templates)
        self.assertIn("POST /api/queue/items/add", templates)
        self.assertIn("PUT /api/player/", templates)
        self.assertNotIn("/login", templates)
        self.assertNotIn("/databases", templates)

    def test_unpinned_forked_daapd_and_http_wire_syntax_stay_http(self):
        mock = load_mock("forked-daapd", protocol=None)
        self.assertEqual(mock.MOCK_PROTOCOL, "")
        self.assertEqual(mock.detect_proto("forked-daapd DAAP protocol"), "HTTP")

        mock = load_mock("", protocol=None)
        self.assertEqual(mock.detect_proto("DAAP HTTP/1.1 request"), "HTTP")

    def test_forked_daapd_wire_protocol_is_http_across_launch_and_replay(self):
        # The directory/feature name is DAAP, while the AFLNet wire parser is
        # HTTP. Lock the actual LoopFuzz launch argv and its parser contract.
        launcher = (REPO_ROOT / "benchmark/scripts/execution/profuzzbench_exec_all_dev.sh").read_text()
        launch_lines = [line for line in launcher.splitlines()
                        if "profuzzbench_exec_common_dev.sh forked-daapd" in line
                        and " loopfuzz " in line]
        self.assertEqual(len(launch_lines), 1)
        option_match = re.search(r'\s"([^"]+)"\s+\$TIMEOUT\s+\$SKIPCOUNT', launch_lines[0])
        self.assertIsNotNone(option_match, launch_lines[0])
        options = shlex.split(option_match.group(1))
        protocol_args = [options[i + 1] for i, option in enumerate(options[:-1])
                         if option == "-P"]
        self.assertEqual(protocol_args, ["HTTP"])

        target_run = (REPO_ROOT / "benchmark/subjects/DAAP/forked-daapd/run.sh").read_text()
        self.assertIn("-o $OUTDIR -N tcp://127.0.0.1/3689 $OPTIONS", target_run)
        parser = (REPO_ROOT / "LoopFuzz/afl-fuzz.c").read_text()
        http_case = re.search(
            r'else if \(!strcmp\(optarg, "HTTP"\)\)\s*\{([^}]+)\}',
            parser,
        )
        self.assertIsNotNone(http_case)
        self.assertIn("extract_requests_http", http_case.group(1))
        self.assertIn("protocol_name = ck_strdup(optarg);", parser)
        self.assertIn('"protocol_name"', parser)
        self.assertIn('"orig_cmdline"', parser)

        common_runner = (REPO_ROOT / "benchmark/scripts/execution/profuzzbench_exec_common_dev.sh").read_text()
        self.assertRegex(common_runner, r"forked-daapd\)\s+_target_mock_protocol=HTTP")
        self.assertIn('"${MOCK_PROTOCOL}" != "${_target_mock_protocol}"', common_runner)
        self.assertIn('_mock_target="${DOCIMAGE}"', common_runner)
        self.assertIn('"${_requested_mock_target}" != "${_mock_target}"', common_runner)
        self.assertIn("CHATAFL_TARGET_NAME=%s conflicts with target image %s", common_runner)

    def test_forked_daapd_rejects_daap_mock_pin(self):
        common_runner = (REPO_ROOT / "benchmark/scripts/execution/profuzzbench_exec_common_dev.sh").read_text()
        self.assertRegex(common_runner, r"forked-daapd\)\s+_target_mock_protocol=HTTP")
        self.assertIn('"${MOCK_PROTOCOL}" != "${_target_mock_protocol}"', common_runner)
        self.assertIn("conflicts with target %s (expected %s)", common_runner)

    def test_mock_protocol_mapping_matches_all_nine_wire_protocols(self):
        # Target directory names are not always wire protocol names: DAAP's
        # directory contains a target launched and monitored as HTTP. Keep the
        # mock's bank selection aligned with the actual -P argument for every
        # protocol target in this experiment matrix.
        expected = {
            "lightftp": "FTP",
            "bftpd": "FTP",
            "proftpd": "FTP",
            "pure-ftpd": "FTP",
            "exim": "SMTP",
            "live555": "RTSP",
            "kamailio": "SIP",
            "forked-daapd": "HTTP",
            "lighttpd1": "HTTP",
        }
        launcher = (REPO_ROOT / "benchmark/scripts/execution/profuzzbench_exec_all_dev.sh").read_text()
        common_runner = (REPO_ROOT / "benchmark/scripts/execution/profuzzbench_exec_common_dev.sh").read_text()

        shell_mapping = {}
        for target_group, protocol in re.findall(
            r"^\s*([a-z0-9|.-]+)\)\s+_target_mock_protocol=([A-Z]+)\s*;;",
            common_runner,
            re.MULTILINE,
        ):
            for target in target_group.split("|"):
                shell_mapping[target] = protocol

        self.assertEqual({target: shell_mapping.get(target) for target in expected}, expected)
        for target, expected_protocol in expected.items():
            launch_lines = [
                line for line in launcher.splitlines()
                if f"profuzzbench_exec_common_dev.sh {target} " in line
                and " loopfuzz " in line
            ]
            self.assertEqual(len(launch_lines), 1, (target, launch_lines))
            option_match = re.search(r'\s"([^"]+)"\s+\$TIMEOUT\s+\$SKIPCOUNT', launch_lines[0])
            self.assertIsNotNone(option_match, launch_lines[0])
            options = shlex.split(option_match.group(1))
            protocol_args = [
                options[i + 1] for i, option in enumerate(options[:-1])
                if option == "-P"
            ]
            self.assertEqual(protocol_args, [expected_protocol], target)

    def test_forked_daapd_replies_stay_on_corpus_backed_api_routes(self):
        mock = load_mock("forked-daapd")
        prompt = (
            "Analyze the HTTP protocol. Communication History:\n"
            "GET /api/config HTTP/1.1\nHost: 127.0.0.1:3689\n\n"
            "GET /api/player HTTP/1.1\nHost: 127.0.0.1:3689\n\n"
            "ONLY valid JSON suggested_request"
        )
        for request_id in range(1, 81):
            reply = json.loads(mock.reply_for(prompt, request_id=request_id))
            request = reply.get("suggested_request")
            if request is None:
                for action in reply.get("actions", []):
                    for operation in action.get("ops", []):
                        if "data" in operation:
                            request = base64.b64decode(operation["data"]).decode()
                            break
            self.assertIsNotNone(request, reply)
            self.assertRegex(request, r"(?m)^(GET|POST|PUT|DELETE) /(api/|artwork/)")
            self.assertNotIn("/login", request)
            self.assertNotIn("/databases", request)

    def test_other_http_target_keeps_generic_profile(self):
        mock = load_mock("lighttpd1")
        self.assertFalse(mock._is_forked_daapd_http())
        # Mock replies may validly use either the single-request or actions[]
        # schema, and the random category can select any generic HTTP method.
        # Check the wire profile rather than one seed/category-specific value.
        for request_id in range(1, 81):
            reply = mock.reply_for(
                "Return a JSON object with one suggested_request.", request_id=request_id,
                count_reply_class=False)
            parsed = json.loads(reply)
            requests = []
            if parsed.get("suggested_request"):
                requests.append(parsed["suggested_request"])
            for action in parsed.get("actions", []):
                for operation in action.get("ops", []):
                    if "data" in operation:
                        requests.append(base64.b64decode(operation["data"]).decode())
            self.assertTrue(requests, parsed)
            for request in requests:
                self.assertRegex(request, r"(?m)^[A-Z]{3,10} (\*|/)")
                self.assertNotIn("/api/", request)
        self.assertEqual(mock.detect_proto("plain HTTP request"), "HTTP")


if __name__ == "__main__":
    unittest.main()
