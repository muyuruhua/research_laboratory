"""Actual replay client checks against TCP peers and malformed framed files."""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
import unittest


BINARY = Path(os.environ.get("REPLAY_TEST_BINARY", Path(__file__).with_name("aflnet-replay"))).resolve()


def framed(*payloads):
    return b"".join(struct.pack("<I", len(payload)) + payload for payload in payloads)


class ReplayClientContract(unittest.TestCase):
    def invoke(self, root, data, port):
        packet, ledger = root / "input.raw", root / "frames.jsonl"
        packet.write_bytes(data)
        result = subprocess.run(
            [str(BINARY), str(packet), "FTP", str(port), "0", "50", "10000"],
            env={**os.environ, "LOOPFUZZ_REPLAY_LEDGER": str(ledger)},
            capture_output=True, timeout=5,
        )
        rows = [json.loads(line) for line in ledger.read_text().splitlines()]
        self.assertEqual(rows[-1]["event"], "session_end")
        return result, rows

    def conversation(self, mode):
        errors, received = [], []
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def peer():
            try:
                with listener:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(3)
                        connection.sendall(b"220 ready\r\n")
                        for index in range(2):
                            payload = b""
                            while len(payload) < 6:
                                chunk = connection.recv(6 - len(payload))
                                if not chunk:
                                    break
                                payload += chunk
                            if not payload:
                                break
                            received.append(payload)
                            if mode == "reset":
                                connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                                return
                            connection.sendall(b"200 OK\r\n")
                            if mode == "early-fin":
                                connection.shutdown(socket.SHUT_WR)
                                # Drain any forbidden sends after FIN, so their absence is tested.
                                extra = connection.recv(4096)
                                if extra:
                                    received.append(extra)
                                return
                        if mode == "final-fin":
                            connection.shutdown(socket.SHUT_WR)
                        else:
                            connection.recv(1)  # hold open until the client completes
            except BaseException as error:
                errors.append(repr(error))

        worker = threading.Thread(target=peer, daemon=True)
        worker.start()
        with tempfile.TemporaryDirectory() as directory:
            result, rows = self.invoke(Path(directory), framed(b"NOOP\r\n", b"QUIT\r\n"), port)
        worker.join(4)
        self.assertFalse(worker.is_alive(), "peer did not finish")
        self.assertEqual(errors, [])
        return result, rows, received

    def test_open_peer_complete(self):
        result, rows, received = self.conversation("open")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(rows[-1]["stop_reason"], "eof")
        self.assertEqual(received, [b"NOOP\r\n", b"QUIT\r\n"])

    def test_normal_fin_after_last_frame(self):
        result, rows, received = self.conversation("final-fin")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(rows[-1]["stop_reason"], "eof")
        self.assertTrue(rows[-1]["peer_closed"])
        self.assertEqual(len(received), 2)

    def test_early_fin_prevents_any_trailing_frame(self):
        result, rows, received = self.conversation("early-fin")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(rows[-1]["stop_reason"], "peer-closed-before-input-end")
        self.assertEqual(rows[-1]["frames_total"], 1)
        self.assertEqual(received, [b"NOOP\r\n"])

    def test_reset_still_fails(self):
        result, rows, received = self.conversation("reset")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(rows[-1]["stop_reason"], "client-recv-post-send-failed")
        self.assertEqual(rows[1]["post_recv_errno"], 104)
        self.assertEqual(received, [b"NOOP\r\n"])

    def assert_invalid_without_connect(self, data, reason):
        with socket.socket() as listener, tempfile.TemporaryDirectory() as directory:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(0.05)
            result, rows = self.invoke(Path(directory), data, listener.getsockname()[1])
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(rows[-1]["stop_reason"], reason)
            self.assertEqual(rows[-1]["frames_total"], 0)
            with self.assertRaises(socket.timeout):
                listener.accept()

    def test_partial_headers_rejected_before_any_frame_is_sent(self):
        for length in (1, 2, 3):
            with self.subTest(length=length):
                self.assert_invalid_without_connect(framed(b"NOOP\r\n") + b"\x01" * length, "truncated-frame-header")

    def test_partial_payload_never_sends_padding(self):
        self.assert_invalid_without_connect(struct.pack("<I", 9) + b"NOOP\r\n", "truncated-frame-payload")

    def test_missing_input_returns_error(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([str(BINARY), str(Path(directory) / "missing"), "FTP", "1", "0"], capture_output=True, timeout=2)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"Cannot open input", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
