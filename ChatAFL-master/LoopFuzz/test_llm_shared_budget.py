#!/usr/bin/env python3
"""Actual C transport regressions using localhost only; no external gateway."""
import http.server
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parent
HARNESS = r'''
#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "chat-llm.c"
void *__real_mmap(void *, size_t, int, int, int, off_t);
void *__wrap_mmap(void *p, size_t n, int prot, int flags, int fd, off_t offset) {
    if (getenv("TEST_MMAP_FAIL")) { errno = ENOMEM; return MAP_FAILED; }
    return __real_mmap(p, n, prot, flags, fd, offset);
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    const char *delay = getenv("TEST_FSYNC_DELAY_MS");
    if (delay) usleep((useconds_t)strtoul(delay, NULL, 10) * 1000U);
    return __real_fsync(fd);
}
static char prompt[] = "[{\"role\":\"user\",\"content\":\"Reply OK.\"}]";
static void *calls(void *arg) {
    int count = (int)(intptr_t)arg;
    for (int i = 0; i < count; ++i) {
        char *answer = chat_with_llm(prompt, NULL, 1, 0.7f); free(answer);
    }
    return NULL;
}
int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "single";
    if (strcmp(mode, "missinginit")) chat_llm_global_init();
    const char *deadline = getenv("TEST_DEADLINE_MS");
    if (deadline) {
        long offset = strtol(deadline, NULL, 10);
        chat_llm_set_campaign_deadline(chat_llm_now_ms() + offset);
    }
    chat_llm_set_calls_log(getenv("TEST_CALLS_PATH"));
    chat_llm_set_archive_dir(getenv("TEST_ARCHIVE_PATH"));
    if (!strcmp(mode, "threads")) {
        pthread_t threads[8];
        for (int i=0; i<8; ++i) pthread_create(&threads[i], NULL, calls, (void *)(intptr_t)3);
        for (int i=0; i<8; ++i) pthread_join(threads[i], NULL);
    } else if (!strcmp(mode, "forks")) {
        for (int i=0; i<8; ++i) if (!fork()) { calls((void *)(intptr_t)3); _exit(0); }
        while (wait(NULL) > 0) {}
    } else if (!strcmp(mode, "killed")) {
        pid_t child=fork();
        if (!child) { calls((void *)(intptr_t)1); _exit(0); }
        while (!chat_llm_cum_calls()) usleep(1000);
        usleep(150000); kill(child, SIGKILL); waitpid(child, NULL, 0);
        calls((void *)(intptr_t)2);
    } else if (!strcmp(mode, "ownerdead")) {
        int ready[2]; pipe(ready); pid_t child=fork();
        if (!child) { close(ready[0]); if (!chat_llm_budget_lock()) _exit(2); write(ready[1], "x", 1); pause(); _exit(3); }
        close(ready[1]); char signal; if (read(ready[0], &signal, 1)!=1) return 4;
        kill(child, SIGKILL); waitpid(child, NULL, 0); calls((void *)(intptr_t)1);
    } else if (!strcmp(mode, "retry")) {
        char *answer=chat_with_llm(prompt, NULL, 5, 0.7f); free(answer);
    } else calls((void *)(intptr_t)2);
    printf("{\"calls\":%llu,\"tokens\":%llu}\n", chat_llm_cum_calls(), chat_llm_cum_tokens());
    chat_llm_global_cleanup(); return 0;
}
'''

class SharedBudgetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="llm-shared-budget-")
        build = Path(cls.build.name)
        (build / "harness.c").write_text(HARNESS)
        cls.binary = build / "harness"
        subprocess.run([os.environ.get("CC", "cc"), "-O1", "-g", "-ffunction-sections", "-fdata-sections",
                        "-Wno-unused-result", "-I", str(ROOT), str(build / "harness.c"), "-o", str(cls.binary),
                        "-Wl,--gc-sections", "-Wl,--wrap=mmap", "-Wl,--wrap=fsync", "-lcurl", "-ljson-c", "-lpcre2-8", "-lpthread", "-lm"], check=True)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def exercise(self, mode="single", cap=5, response="ok", extra=None):
        observed = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                observed.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                if response == "block": time.sleep(1)
                code = 503 if response == "retry" else 400 if response == "badrequest" else 200
                value = {"model": "served-local", "choices": [{"message": {"content": "OK"}}]}
                if response != "no-usage": value["usage"] = {"prompt_tokens": 3, "completion_tokens": 2}
                if code != 200: value = {"error": {"message": "local-test"}}
                data = b"not-json" if response == "invalid" else json.dumps(value).encode()
                self.send_response(code); self.send_header("Content-Length", str(len(data))); self.end_headers()
                try: self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError): pass
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            with tempfile.TemporaryDirectory(prefix="llm-shared-case-") as directory:
                path = Path(directory)
                env = dict(os.environ)
                for key in list(env):
                    if key.startswith("CHATAFL_") or key in ("KEY", "LLM_MODEL", "TEST_MMAP_FAIL"):
                        env.pop(key)
                env.update(KEY="local-stub-only", LLM_MODEL="local-requested", CHATAFL_MAX_TOKENS="16",
                           CHATAFL_LLM_BASE=f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
                           CHATAFL_LLM_TOTAL_CALL_CAP=str(cap), TEST_CALLS_PATH=str(path / "llm-calls.jsonl"),
                           TEST_ARCHIVE_PATH=str(path), NO_PROXY="127.0.0.1", no_proxy="127.0.0.1")
                if extra: env.update(extra)
                started = time.monotonic()
                result = subprocess.run([str(self.binary), mode], env=env, text=True, capture_output=True, timeout=20)
                self.last_elapsed = time.monotonic() - started
                self.assertEqual(result.returncode, 0, result.stderr)
                totals = json.loads(result.stdout.strip().splitlines()[-1])
                def rows(name):
                    p = path / name
                    return [json.loads(line) for line in p.read_text().splitlines()] if p.exists() else []
                completed = rows("llm-calls.jsonl")
                reserved = rows("llm-calls.jsonl.reservations.jsonl")
                ids = [r["request_id"] for r in completed]
                self.assertEqual(len(ids), len(set(ids)))
                for row in completed:
                    self.assertEqual(row["outbound_attempted"], row["status"] not in ("cap-refused", "deadline-before-dispatch"))
                    if row["status"] != "cap-refused":
                        self.assertTrue((path / (row["request_id"] + ".req")).is_file())
                        self.assertTrue((path / (row["request_id"] + ".resp")).is_file())
                self.assertTrue(all(item["max_tokens"] == 16 for item in observed))
                return observed, totals, completed, reserved
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_fork_descendants_share_one_hard_limit(self):
        observed, totals, completed, reserved = self.exercise("forks", cap=5)
        self.assertEqual((len(observed), totals["calls"], totals["tokens"], len(reserved)), (5, 5, 25, 5))
        self.assertEqual(len({r["reservation_id"] for r in reserved}), 5)
        self.assertEqual(sum(r["status"] == "ok" for r in completed), 5)

    def test_enrichment_threads_share_one_hard_limit(self):
        observed, totals, completed, reserved = self.exercise("threads", cap=5)
        self.assertEqual((len(observed), totals["calls"], len(reserved)), (5, 5, 5))
        self.assertEqual(sum(r["status"] == "ok" for r in completed), 5)

    def test_retries_consume_the_same_limit(self):
        observed, totals, completed, reserved = self.exercise("retry", cap=2, response="retry")
        self.assertEqual((len(observed), totals["calls"], len(reserved)), (2, 2, 2))
        self.assertEqual([r["status"] for r in completed], ["api-error", "api-error", "cap-refused"])

    def test_killed_inflight_reservation_is_not_refunded(self):
        observed, totals, completed, reserved = self.exercise("killed", cap=1, response="block")
        self.assertEqual((len(observed), totals["calls"], len(reserved)), (1, 1, 1))
        self.assertEqual(sum(r["status"] == "ok" for r in completed), 0)

    def test_dead_process_lock_owner_recovers(self):
        observed, totals, completed, _ = self.exercise("ownerdead", cap=1)
        self.assertEqual((len(observed), totals["calls"]), (1, 1))
        self.assertEqual(completed[0]["status"], "ok")

    def test_budget_setup_failure_sends_nothing(self):
        observed, totals, _, reserved = self.exercise(extra={"TEST_MMAP_FAIL": "1"})
        self.assertEqual((len(observed), totals["calls"], len(reserved)), (0, 0, 0))

    def test_missing_initialization_sends_nothing(self):
        observed, totals, _, reserved = self.exercise("missinginit")
        self.assertEqual((len(observed), totals["calls"], len(reserved)), (0, 0, 0))

    def test_default_success_and_usage_are_preserved(self):
        observed, totals, completed, _ = self.exercise()
        self.assertEqual((len(observed), totals["calls"], totals["tokens"]), (2, 2, 10))
        self.assertTrue(all(r["status"] == "ok" and r["usage_reported"] for r in completed))

    def test_omitted_usage_remains_explicitly_unknown(self):
        _, totals, completed, _ = self.exercise(response="no-usage")
        self.assertEqual(totals["tokens"], 0)
        self.assertTrue(all(not r["usage_reported"] for r in completed))

    def test_error_and_invalid_response_do_not_retry(self):
        for response, status in (("badrequest", "api-error"), ("invalid", "invalid-response")):
            with self.subTest(response=response):
                observed, _, completed, _ = self.exercise("retry", response=response)
                self.assertEqual(len(observed), 1)
                self.assertEqual(completed[0]["status"], status)

    def test_reported_token_threshold_stops_later_attempts(self):
        observed, totals, completed, _ = self.exercise(extra={"CHATAFL_TOKEN_CAP": "5"})
        self.assertEqual((len(observed), totals["tokens"]), (1, 5))
        self.assertEqual(completed[-1]["status"], "cap-refused")

    def test_expired_deadline_sends_and_reserves_nothing(self):
        for mode in ("retry", "threads", "forks"):
            with self.subTest(mode=mode):
                observed, totals, completed, reserved = self.exercise(mode, extra={"TEST_DEADLINE_MS": "-100"})
                self.assertEqual((len(observed), totals["calls"], len(completed), len(reserved)), (0, 0, 0, 0))

    def test_deadline_bounds_slow_inflight_without_retry(self):
        observed, totals, completed, reserved = self.exercise("retry", response="block", extra={"TEST_DEADLINE_MS": "200"})
        self.assertEqual((len(observed), totals["calls"], len(completed), len(reserved)), (1, 1, 1, 1))
        self.assertEqual(completed[0]["status"], "transport-error")
        self.assertFalse(completed[0]["usage_reported"])
        self.assertGreater(self.last_elapsed, 0.1)
        self.assertLess(self.last_elapsed, 0.8)

    def test_retry_backoff_cannot_cross_deadline(self):
        observed, totals, completed, reserved = self.exercise("retry", response="retry", extra={"TEST_DEADLINE_MS": "200"})
        self.assertEqual((len(observed), totals["calls"], len(completed), len(reserved)), (1, 1, 1, 1))
        self.assertEqual(completed[0]["status"], "api-error")
        self.assertFalse(completed[0]["usage_reported"])
        self.assertLess(self.last_elapsed, 0.8)

    def test_reservation_crossing_deadline_is_explicitly_unsent(self):
        observed, totals, completed, reserved = self.exercise("retry", extra={"TEST_DEADLINE_MS": "100", "TEST_FSYNC_DELAY_MS": "250"})
        self.assertEqual((len(observed), totals["calls"], len(completed), len(reserved)), (0, 1, 1, 1))
        row = completed[0]
        self.assertEqual(row["status"], "deadline-before-dispatch")
        self.assertFalse(row["outbound_attempted"])
        self.assertFalse(row["usage_reported"])
        self.assertFalse(row["retry"])
        self.assertEqual((row["prompt_tokens"], row["completion_tokens"], row["model_served"]), (0, 0, ""))

if __name__ == "__main__": unittest.main(verbosity=2)
