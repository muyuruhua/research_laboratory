#!/usr/bin/env python3
"""Exercise the real C API clients against a local HTTP server; no live key needed.

    python3 llm_api_regression.py
    python3 llm_api_regression.py --sanitize
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent
SANITIZE = "--sanitize" in sys.argv
if SANITIZE:
    sys.argv.remove("--sanitize")

HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include "chat-llm.h"
struct job { char *prompt; int success; };
static void *ask(void *arg) {
    struct job *j = arg;
    char *answer = chat_with_llm(j->prompt, "legacy-argument", 3, 0.7f);
    j->success = answer != NULL;
    if (answer) printf("ANSWER %s\n", answer);
    free(answer);
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    chat_llm_global_init();
    chat_llm_set_calls_log(getenv("TEST_LEDGER"));
    chat_llm_set_archive_dir(getenv("TEST_ARCHIVE"));
    int n = getenv("TEST_THREADS") ? atoi(getenv("TEST_THREADS")) : 1;
    if (n < 1 || n > 8) return 2;
    struct job jobs[8]; pthread_t threads[8];
    for (int i = 0; i < n; ++i) {
        jobs[i] = (struct job){argv[1], 0};
        if (n == 1) ask(&jobs[i]);
        else if (pthread_create(&threads[i], NULL, ask, &jobs[i])) return 2;
    }
    int successes = 0;
    for (int i = 0; i < n; ++i) {
        if (n != 1) pthread_join(threads[i], NULL);
        successes += jobs[i].success;
    }
    printf("RESULT %llu %llu %llu %llu\n", chat_llm_cum_calls(),
           chat_llm_cum_tokens(), llm_last_prompt_tokens, llm_last_completion_tokens);
    chat_llm_global_cleanup();
    return successes == n ? 0 : 1;
}
'''

GOOD = {
    "model": "served-model",
    "choices": [{"message": {"content": "\nRTSP answer"}}],
    "usage": {"prompt_tokens": 10, "completion_tokens": 4},
}
PROMPT = [{"role": "user", "content": 'RTSP "PLAY"\r\npath\\name\n中文'}]


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        with self.server.lock:
            self.server.requests.append((self.path, dict(self.headers), raw))
            reply = self.server.replies.pop(0) if len(self.server.replies) > 1 else self.server.replies[0]
        if reply is None:
            self.connection.shutdown(socket.SHUT_RDWR)
            self.connection.close()
            return
        status, body = reply
        body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class APIRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="loopfuzz-api-regression-")
        cls.build = Path(cls.temp.name)
        harness = cls.build / "client.c"
        harness.write_text(HARNESS)
        flags = ["-O1", "-g", "-ffunction-sections", "-fdata-sections", "-I", str(ROOT)]
        if SANITIZE:
            flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-no-pie"]
        libraries = ["-Wl,--gc-sections", "-lcurl", "-ljson-c", "-lpcre2-8", "-lpthread", "-lm"]
        subprocess.run(["gcc", *flags, "-Wno-unused-result", str(ROOT / "chat-llm.c"), str(harness),
                        "-o", str(cls.build / "chat-client"), *libraries], check=True)
        subprocess.run(["gcc", *flags, "-Wall", "-Wextra", "-Werror", str(ROOT / "testLLM.c"),
                        "-o", str(cls.build / "testLLM"), *libraries], check=True)
        subprocess.run(["gcc", *flags, "-Wno-unused-result", str(ROOT / "chat-llm.c"),
                        str(ROOT / "llm_preflight.c"), "-o", str(cls.build / "llm-preflight"),
                        *libraries], check=True)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.lock = threading.Lock()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()
        cls.temp.cleanup()

    def setUp(self):
        self.server.requests = []
        self.server.replies = [(200, GOOD)]

    def run_client(self, *, replies=None, prompt=None, env=None, program="chat-client"):
        if replies is not None:
            self.server.replies = replies
        proc_env = {k: v for k, v in os.environ.items()
                    if not k.startswith(("CHATAFL_", "TEST_"))
                    and k not in ("KEY", "LLM_MODEL") and "proxy" not in k.lower()}
        proc_env.update(KEY="local-dummy-key", LLM_MODEL="test-model",
                        CHATAFL_LLM_BASE=f"http://127.0.0.1:{self.server.server_port}/v1/chat/completions")
        if SANITIZE:
            proc_env.update(ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                            UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
        proc_env.update(env or {})
        with tempfile.TemporaryDirectory(dir=self.build) as work:
            proc_env.update(TEST_LEDGER=str(Path(work) / "calls.jsonl"), TEST_ARCHIVE=work)
            command = [str(self.build / program)]
            if program == "chat-client":
                command.append(json.dumps(PROMPT, ensure_ascii=False) if prompt is None else prompt)
            p = subprocess.run(command, env=proc_env, capture_output=True, text=True, timeout=30)
            self.assertNotIn("AddressSanitizer", p.stderr, p.stderr)
            self.assertNotIn("runtime error:", p.stderr, p.stderr)
            self.assertIn(p.returncode, (0, 1), p.stderr)
            ledger = Path(work) / "calls.jsonl"
            self.records = [json.loads(s) for s in ledger.read_text().splitlines()] if ledger.exists() else []
            self.archives = [json.loads(f.read_text()) for f in Path(work).glob("*.req")]
        self.stats = None
        for line in p.stdout.splitlines():
            if line.startswith("RESULT "):
                self.stats = tuple(map(int, line.split()[1:]))
        return p

    def test_serialization_and_ledger_escape(self):
        model = 'model"with\\escape\n中文'
        p = self.run_client(env={"LLM_MODEL": model})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("ANSWER RTSP answer", p.stdout)
        path, headers, raw = self.server.requests[0]
        body = json.loads(raw)
        self.assertEqual(path, "/v1/chat/completions")
        self.assertEqual(body["messages"], PROMPT)
        self.assertEqual(body["model"], model)
        self.assertNotIn("prompt", body)
        self.assertEqual(headers["Authorization"], "Bearer local-dummy-key")
        self.assertEqual(self.records[0]["model_requested"], model)
        self.assertEqual(self.archives[0], body)
        self.assertEqual(self.stats, (1, 14, 10, 4))

    def test_sampling_configuration(self):
        p = self.run_client(env={"CHATAFL_TOP_P": "0.8", "CHATAFL_MAX_TOKENS": "1234"})
        self.assertEqual(p.returncode, 0, p.stderr)
        body = json.loads(self.server.requests[0][2])
        self.assertEqual(body["max_tokens"], 1234)
        self.assertEqual(body["top_p"], 0.8)
        self.assertAlmostEqual(body["temperature"], 0.7, places=6)

    def test_permanent_http_errors_are_not_retried(self):
        for status in (400, 401, 403, 404, 422):
            with self.subTest(status=status):
                self.server.requests = []
                p = self.run_client(replies=[(status, {"error": {"message": "rejected"}})])
                self.assertEqual(p.returncode, 1)
                self.assertEqual(len(self.server.requests), 1)
                self.assertEqual(self.stats, (1, 0, 0, 0))
                self.assertIn(f"HTTP={status}", p.stderr)

    def test_rate_limit_retries_then_succeeds(self):
        p = self.run_client(replies=[(429, {"error": {"message": "busy"}}), (200, GOOD)])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(self.server.requests), 2)
        self.assertEqual([r["status"] for r in self.records], ["api-error", "ok"])
        self.assertEqual(self.stats, (2, 14, 10, 4))
        self.assertEqual(self.records[0]["model_served"], "")

    def test_retry_exhaustion(self):
        p = self.run_client(replies=[(503, {"error": {"message": "busy"}})])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(len(self.server.requests), 3)
        self.assertEqual(len(self.records), 3)
        self.assertEqual(self.stats, (3, 0, 0, 0))

    def test_transport_failure_retries(self):
        p = self.run_client(replies=[None, (200, GOOD)])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(self.server.requests), 2)
        self.assertEqual([r["status"] for r in self.records], ["transport-error", "ok"])

    def test_invalid_requests_are_rejected_before_network(self):
        for prompt in ('[{"role":"user","content":"bad "quote""}]', "{}", "[]", "null",
                       json.dumps(PROMPT) + " trailing"):
            with self.subTest(prompt=prompt):
                self.server.requests = []
                p = self.run_client(prompt=prompt)
                self.assertEqual(p.returncode, 1)
                self.assertEqual(len(self.server.requests), 0)
                self.assertEqual(self.stats, (0, 0, 0, 0))

    def test_invalid_json_responses(self):
        for body in (b"", b"<html>upstream failure</html>", b"[]", b"null", b"{} trailing"):
            with self.subTest(body=body):
                self.server.requests = []
                p = self.run_client(replies=[(200, body)])
                self.assertEqual(p.returncode, 1)
                self.assertEqual(len(self.server.requests), 1)
                self.assertEqual(self.records[0]["status"], "invalid-response")

    def test_invalid_response_shapes(self):
        for body in ({"choices": {}}, {"choices": []}, {"choices": [None]},
                     {"choices": [{"message": []}]},
                     {"choices": [{"message": {"content": {"bad": "type"}}}]}):
            with self.subTest(body=body):
                self.server.requests = []
                p = self.run_client(replies=[(200, body)])
                self.assertEqual(p.returncode, 1)
                self.assertEqual(len(self.server.requests), 1)
                self.assertEqual(self.records[0]["status"], "empty-content")

    def test_empty_content_still_records_billed_usage(self):
        body = {**GOOD, "choices": [{"message": {"content": None}}]}
        p = self.run_client(replies=[(200, body)])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(self.stats, (1, 14, 10, 4))
        self.assertEqual(self.records[0]["completion_tokens"], 4)

    def test_invalid_usage_does_not_wrap_counters(self):
        body = {**GOOD, "usage": {"prompt_tokens": -1, "completion_tokens": "not-an-integer"}}
        p = self.run_client(replies=[(200, body)])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.stats, (1, 0, 0, 0))

    def test_api_error_in_200_response_is_not_retried(self):
        p = self.run_client(replies=[(200, {"error": {"message": "invalid request"}})])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(self.records[0]["status"], "api-error")

    def test_call_cap_applies_to_retries(self):
        p = self.run_client(replies=[(503, {"error": {"message": "busy"}})],
                            env={"CHATAFL_LLM_TOTAL_CALL_CAP": "1"})
        self.assertEqual(p.returncode, 1)
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(self.stats, (1, 0, 0, 0))
        self.assertEqual([r["status"] for r in self.records], ["api-error", "cap-refused"])

    def test_call_cap_applies_to_concurrent_workers(self):
        p = self.run_client(replies=[(503, {"error": {"message": "busy"}})],
                            env={"CHATAFL_LLM_TOTAL_CALL_CAP": "1", "TEST_THREADS": "4"})
        self.assertEqual(p.returncode, 1)
        self.assertEqual(len(self.server.requests), 1)
        self.assertEqual(self.stats[:2], (1, 0))

    def test_no_llm_and_empty_key_do_not_send(self):
        for env in ({"CHATAFL_NO_LLM": "1"}, {"KEY": ""}):
            with self.subTest(env=env):
                p = self.run_client(env=env)
                self.assertEqual(p.returncode, 1)
                self.assertEqual(len(self.server.requests), 0)
                self.assertEqual(self.stats, (0, 0, 0, 0))

    def test_long_key_is_not_truncated(self):
        key = "dummy-" + "x" * 400
        p = self.run_client(env={"KEY": key})
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(self.server.requests[0][1]["Authorization"], "Bearer " + key)

    def test_standalone_smoke_client(self):
        model = 'model"with\\escape'
        p = self.run_client(program="testLLM", env={"LLM_MODEL": model})
        self.assertEqual(p.returncode, 0, p.stderr)
        body = json.loads(self.server.requests[0][2])
        self.assertEqual(body["model"], model)
        self.assertIsInstance(body["messages"], list)
        self.assertIn("RTSP answer", p.stdout)

    def test_standalone_400_does_not_retry(self):
        p = self.run_client(program="testLLM", replies=[(400, {"error": {"message": "bad request"}})])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(len(self.server.requests), 1)

    def test_preflight_success_uses_campaign_config_without_dumping_secrets(self):
        key = "dummy-preflight-secret"
        p = self.run_client(program="llm-preflight", env={
            "KEY": key, "LLM_MODEL": "preflight-model", "CHATAFL_TOP_P": "0.8",
            "CHATAFL_MAX_TOKENS": "1234",
        })
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(self.server.requests), 1)
        path, headers, raw = self.server.requests[0]
        body = json.loads(raw)
        self.assertEqual(path, "/v1/chat/completions")
        self.assertEqual(headers["Authorization"], "Bearer " + key)
        self.assertEqual(body["model"], "preflight-model")
        self.assertEqual(body["max_tokens"], 1234)
        self.assertEqual(body["top_p"], 0.8)
        self.assertEqual(body["messages"], [{"role": "user", "content": "Reply OK."}])
        self.assertIn("[LLM preflight] PASS", p.stdout)
        self.assertIn(f"key_bytes={len(key)}", p.stdout)
        self.assertNotIn(key, p.stdout + p.stderr)
        self.assertNotIn("RTSP answer", p.stdout + p.stderr)

    def test_preflight_rejects_401_after_one_request(self):
        p = self.run_client(program="llm-preflight", replies=[
            (401, {"error": {"message": "Invalid token"}}), (200, GOOD),
        ])
        self.assertEqual(p.returncode, 1)
        self.assertEqual(len(self.server.requests), 1)
        self.assertIn("HTTP=401", p.stderr)
        self.assertIn("[LLM preflight] FAIL", p.stdout)
        self.assertNotIn("local-dummy-key", p.stdout + p.stderr)

    def test_preflight_disabled_skips_network(self):
        for setting in ("1", "yes"):
            with self.subTest(setting=setting):
                p = self.run_client(program="llm-preflight", env={"CHATAFL_NO_LLM": setting})
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(len(self.server.requests), 0)
                self.assertIn("[LLM preflight] SKIP", p.stdout)

    def test_launcher_stops_before_group_execution_when_preflight_fails(self):
        with tempfile.TemporaryDirectory(dir=self.build) as work:
            launch_root = Path(work)
            (launch_root / "run_ablation.sh").write_text(
                (ROOT.parent / "run_ablation.sh").read_text())
            (launch_root / "scripts").mkdir()
            (launch_root / "bin").mkdir()
            fixtures = {
                "scripts/check_llm.sh": '#!/bin/bash\nprintf checked > "$PREFLIGHT_SENTINEL"\nexit 1\n',
                "run_dev.sh": '#!/bin/bash\ndocker run\n',
                "bin/docker": '''#!/bin/bash
case "$1" in
  ps) exit 0 ;;
  run|exec|rm|stop) printf '%s\\n' "$1" >> "$LAUNCH_SENTINEL"; exit 99 ;;
  *) exit 99 ;;
esac
''',
                # Keep launcher resource checks independent of the test host.
                "bin/awk": "#!/bin/bash\nprintf '134217728\\n'\n",
                "bin/chown": "#!/bin/bash\nexit 0\n",
            }
            for relative, content in fixtures.items():
                fixture = launch_root / relative
                fixture.write_text(content)
                fixture.chmod(0o755)
            env = {k: v for k, v in os.environ.items()
                   if not k.startswith(("CHATAFL_", "TEST_")) and k != "SUDO_USER"}
            env.update(KEY="dummy-launcher-key", SKIPCOUNT="100", ABLATION_PARALLEL="1",
                       PATH=str(launch_root / "bin") + os.pathsep + os.defpath,
                       PREFLIGHT_SENTINEL=str(launch_root / "preflight.called"),
                       LAUNCH_SENTINEL=str(launch_root / "docker.mutated"))
            p = subprocess.run(["bash", str(launch_root / "run_ablation.sh"), "bftpd", "3", "95",
                                "-g", "wrapdirect8,wrapgate8,salvage8"], env=env,
                               capture_output=True, text=True, timeout=15)
            self.assertNotEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertTrue((launch_root / "preflight.called").exists(), p.stdout + p.stderr)
            self.assertFalse((launch_root / "docker.mutated").exists(), p.stdout + p.stderr)
            self.assertNotIn("[ABLATION] 已启动", p.stdout)
            self.assertIn("LLM 预检失败", p.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
