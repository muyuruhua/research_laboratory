# Vulnerability Advisory Draft — forked-daapd / OwnTone Server
## Unauthenticated single-request remote Denial-of-Service via SMARTPL parser error-recovery deadlock

> Status: DRAFT for GitHub Security Advisory submission (private vulnerability reporting
> on `owntone/owntone-server`, formerly `ejurgensen/forked-daapd`).

### Summary

The SMARTPL query expression parser in forked-daapd/OwnTone Server (ANTLRv3 C runtime
based implementation, present in versions 27.0 through 28.3) enters a recursive
error-recovery state when fed a malformed search expression. The parser never returns,
the HTTP worker never produces a response, and the server's event loop becomes
permanently blocked. **A single unauthenticated HTTP GET request permanently disables
the server for all clients** (including new connections) until process restart.
The process stays alive (no crash), CPU falls idle, and all threads park in `epoll_wait`.

### Affected versions

- **Affected**: forked-daapd / OwnTone Server **27.0 – 28.3** (all releases using the
  ANTLR3 C runtime SMARTPL parser, `src/smartpl_query.c`).
- **Fixed**: **28.4** (2022-05-30) — upstream commit `[daap/rsp/smartpl] Drop ANTLR
  parsers` removed the ANTLRv3 runtime entirely and replaced it with a flex/bison
  parser whose fallback rule returns invalid characters as tokens and exits cleanly
  on syntax error. The fix was architectural; upstream was not aware of the DoS.
- **Not affected**: 28.4 and later (including current releases).

### Root cause

`src/smartpl_query.c:42` `parse_input()` → `SMARTPLLexerNew()` (libantlr3c-3.4).
A malformed expression containing a raw high-byte (`0x81`) inside a long token together
with bare `?` characters drives the ANTLR3 lexer into recursive error recovery.
The lexer emits a stream of `lexer error` diagnostics (38 in the minimal reproducer)
and never reaches EOF; the calling HTTP request handler blocks forever and the event
loop stops servicing any connection.

### Reproducer (exact bytes, single request)

```
printf 'GET /api/search?type=al?um&expression=time_added+aft\x81r+iiiiiiiiiiiiiiiiiiiiiiiiiilibrary<artirts?media_kind=music HTTP/1.1\r\n\r\n' | nc <host> 3689
```

Python equivalent:

```python
import socket
s = socket.create_connection(("<host>", 3689), timeout=3)
s.sendall(b"GET /api/search?type=al?um&expression=time_added+aft\x81r"
          b"+iiiiiiiiiiiiiiiiiiiiiiiiiilibrary<artirts?media_kind=music"
          b" HTTP/1.1\r\n\r\n")
```

### Verification evidence (fresh, 2026-09-20)

Environment: forked-daapd 27.2 (benchmark build, docker image `forked-daapd:latest`,
source tree unmodified apart from build instrumentation).

| Experiment | Result |
|---|---|
| Single-request wedge, 5 independent fresh-server rounds | **5/5** — process alive, new connections time out at t+2s **and** t+60s, `GET /api/config` unresponsive, server log shows exactly 38 `lexer error` lines each round |
| Full 48-message fuzzer seed (superset containing the request), 3 fresh rounds | **3/3** global wedge |
| Control (benign `GET /api/config` on fresh server) | Response `200` immediately, server healthy |
| Process state during wedge | alive; CPU ticks stop accumulating (0 between probes); all threads in `epoll_wait` (reply-loss deadlock, not a busy loop) |
| Recovery | none observed; permanent until process restart |

### Impact

Complete loss of availability for the media server via one unauthenticated request
on the DAAP/HTTP port (default 3689), reachable from any network client. Impact limited
to availability (no memory corruption; no confidentiality/integrity impact observed).

Suggested CVSS 3.1 vector: `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (7.5 High).
Suggested CWE: CWE-754 (Improper Check for Unusual or Exceptional Conditions);
secondary CWE-667 (Improper Locking).

### Credit

Discovered by LoopFuzz (LLM-assisted stateful protocol fuzzer, calibrated hang channel),
campaign batch `results-forked-daapd_Sep-10_04-19-34`, automated hot-replay triage and
manual root-cause analysis. Reported 2026-09.

### Notes for the maintainer

- No public report or CVE exists for this issue as of 2026-09 (checked NVD `owntone`
  9 CVEs / `forked-daapd` 0 results, GitHub issues search).
- Versions 27.0–28.3 are EOL; we are requesting a CVE for the affected range so that
  downstream distributors holding 28.3-era packages can reference it.
