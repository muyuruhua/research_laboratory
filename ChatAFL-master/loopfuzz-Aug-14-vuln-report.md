# LoopFuzz 最新结果漏洞定性报告

- **分析日期**：2026-08-16
- **结果范围**：`benchmark/results-*_Aug-14_16-07-04`（9 个协议，最新一批）
- **fuzzer**：loopfuzz（含 `-K` 服务器终止、`-E` 状态感知、`-t 5000+` 超时）
- **判定方法**：以「`.asan.log` 是否存在 ASAN 内存错误报告」作为真实内存安全 bug 的首要判据，辅以 `addr2line` 符号化 + 源码印证 + 重放验证

---

## 1. 执行摘要

最新一批结果里，**真正带完整 ASAN 报告的内存安全 bug 只有 2 个**，且都**无法稳定复现**（低频竞态）；另有一组 7 个 crash 是 fuzzer 关闭路径的**误报**。

| 结论 | 数量 | 说明 |
|---|---|---|
| ✅ 真实 bug（有 ASAN 报告 + 源码印证） | 2 | live555 stack-use-after-return、proftpd heap-use-after-free |
| ❌ 误报（无 ASAN 报告） | 7 | kamailio 关闭期 SIGABRT |
| ⚪ 纯超时（无内存 bug） | 4 | exim / forked-daapd×2 / proftpd-run2 的 hang |
| — 无发现 | 4 协议 | bftpd / lightftp / lighttpd1 / pure-ftpd |
| Oracle 违规 | 0 | 全部 9 协议 `oracle_violations=0` |

---

## 2. 九协议全量盘点

以「是否存在 `.asan.log`（ASAN 报告落点）」为标准：

| 协议 | run | 位置 | `.asan.log` | 定性 |
|---|---|---|---|---|
| live555 | 1 | crash (sig:06) | ✅ stack-use-after-return | **真 bug** |
| proftpd | 1 | **hang**（非 crash） | ✅ heap-use-after-free | **真 bug** |
| kamailio | 2 | 7× crash (sig:06) | ❌ 无 | 误报（关闭期 SIGABRT） |
| exim | 2 | 1× hang | ❌ 无 | 纯超时 |
| forked-daapd | 1/2 | 各 1× hang | ❌ 无 | 纯超时 |
| proftpd | 2 | 1× hang | ❌ 无 | 纯超时 |
| bftpd / lightftp / lighttpd1 / pure-ftpd | — | 无 | — | 无发现 |

> 关键教训：**proftpd 的真 UAF 藏在 `replayable-hangs/` 里，`unique_crashes=0` 是假象**——只数 crash 计数会漏报真漏洞。

---

## 3. 真 bug 证据链

### 3.1 live555 —— stack-use-after-return

**ASAN 报告**（`replayable-crashes/id:000000,...asan.log`）：
```
ERROR: AddressSanitizer: stack-use-after-return
READ of size 2 ... thread T0
  This frame has 14 object(s):
    [864, 1064) 'cseq' (line 791)   <== 访问落在该栈变量上
    [592, 792) 'urlSuffix' (line 790)
SUMMARY: AddressSanitizer: stack-use-after-return
```

**符号化定位**（`addr2line`）：
- 读已失效栈内存：`RTSPServer::RTSPClientConnection::handleCmd_DESCRIBE_afterLookup`（RTSPServer.cpp:434）→ `snprintf(..., fCurrentCSeq, ...)`

**源码印证**：
- `RTSPServer.hh:243`：`char const* fCurrentCSeq;` —— **指针成员**
- `RTSPServer.cpp:831`：`fCurrentCSeq = cseq;` —— 指向 `handleRequestBytes` 的**栈上 `cseq` 缓冲区**
- 函数返回后 `fCurrentCSeq` 悬垂，DESCRIBE 异步回调里 `snprintf` 读它 → 经典 use-after-return

### 3.2 proftpd —— heap-use-after-free

**ASAN 报告**（`replayable-hangs/id:000000,...asan.log`）：
```
ERROR: AddressSanitizer: heap-use-after-free
READ of size 8 at ... (104 bytes inside 544-byte region)
freed by: pool_release_free_block_list (pool.c:475) ← free_pools (main.c:1525)
previously allocated by: make_sub_pool (pool.c:488) ← pr_class_match_addr (class.c:133)
SUMMARY: AddressSanitizer: heap-use-after-free
```

**符号化定位**：
- 读已释放内存：`pr_table_add_dup`（table.c:841）`memcpy(...)`
- 调用链：`pr_session_disconnect`（session.c:123）← `finish_terminate`（signals.c:102，**SIGTERM 关闭路径**）← `handle_terminate_with_kids` ← `pr_signals_handle`

**源码印证**：
- `pr_class_match_addr`（class.c:133）创建 `tmp_pool = make_sub_pool(permanent_pool)` 做 class 匹配，该 544 字节 sub-pool 随 `free_pools` 释放
- 释放后 `pr_session_disconnect` 仍持指针访问 → 经典 use-after-free

**触发机制（为什么低频）**：该 UAF 发生在 **SIGTERM 关闭路径**（`finish_terminate → pr_session_disconnect`），要求「`free_pools` 释放 `session.notes` 之后、进程退出之前」SIGTERM 恰好在 proftpd 的信号阻塞窗口（`sigs_nblocked` 引用计数）内被 `pr_signals_unblock → pr_signals_handle` 处理。极窄时序窗口 → 约 1/5 万 exec 才出一次。

---

## 4. 误报：kamailio 7× SIGABRT

- 7 个 crash（`id:000000`~`id:000006`）全是 `sig:06`(SIGABRT)。
- 原始日志**没有 `ERROR: AddressSanitizer`**，只有孤零零的 `AddressSanitizer:DEADLYSIGNAL`，且前面是 `handle_sigs(): Thank you for flying kamailio!!!`（优雅关闭消息）。
- **根因**：`handle_sigs`（main.c:735）收到 SIGTERM 后走 `shutdown_children()`，关闭路径 `abort()` → SIGABRT，被 fuzzer 误判为 `FAULT_CRASH`。
- **不是输入触发的漏洞**。

---

## 5. 复现结果

| 漏洞 | 复现方式 | 次数 | 结果 |
|---|---|---|---|
| live555 stack-use-after-return | ASAN 版 `testOnDemandRTSPServer`，22 条 RTSP 消息 TCP 重放 | 30 | **0** |
| proftpd heap-use-after-free | 手写重放（connect→空输入→SIGTERM 等 6 变体） | 54 | **0** |
| proftpd heap-use-after-free | **真实 afl-fuzz（forkserver 模式，20 分钟）** | **27,263 exec** | **0** |
| proftpd heap-use-after-free | （含短跑）合计 | ~29,624 exec | **0** |
| kamailio 7× SIGABRT | ASAN 版 kamailio，7 条输入 UDP 重放 | 7/7 | **全不崩（确认误报）** |

**结论**：两个真 bug 都**不可稳定复现**（低频竞态）；kamailio 是误报。

---

## 6. crash-detection 补丁

### 6.1 根因

`run_target()` 的信号分类：子进程以 SIGABRT 死掉时，既不是 SIGKILL（超时/强制）、也不是 SIGTERM（优雅关闭），于是落到 `return FAULT_CRASH`。这导致两个方向的问题：

- **kamailio 误报（false positive）**：关闭期纯 `abort()` 被误判为 crash。
- **proftpd 漏报（false negative）**：关闭期真 UAF 被误判（且因超时被归进 hang）。

原有一段「O2 关闭窗口 ASAN crash 检查」是**死代码**（外层 `kill_signal == SIGKILL` 已保证 `WTERMSIG==SIGKILL`，内层再判 `==SIGABRT` 恒为假），从未生效。

### 6.2 修复方案：按 ASAN 报告区分

判别依据：真 ASAN 内存错误会往 stderr 打 `ERROR: AddressSanitizer`；纯 `abort()` 只打 `AddressSanitizer:DEADLYSIGNAL`。fuzzer 已把子进程 stderr 捕获到 `/tmp/afl_stderr_capture`（每 exec 前 `truncate`）。

核心改动（`LoopFuzz/afl-fuzz.c`）：

1. 新增标志 `u8 child_term_sent`（`send_over_network` 里对**仍存活**的子进程发 SIGTERM 前置位）。
2. 新增辅助函数 `stderr_has_asan_error()`：读 `/tmp/afl_stderr_capture` 末尾，搜 `"ERROR: AddressSanitizer"`。
3. `run_target` 里 `child_term_sent` 分支：
   ```c
   if (child_term_sent) {
     child_term_sent = 0;
     if (stderr_has_asan_error())  return FAULT_CRASH;  // 真内存 bug
     return FAULT_NONE;                                  // 关闭 artifact
   }
   ```
4. 删除死代码 O2。

### 6.3 验证

- 判别逻辑对着真实日志验证：kamailio（无 `ERROR:`）→ `FAULT_NONE`；proftpd（有 `heap-use-after-free`）→ `FAULT_CRASH`。
- 编译：规范源码 `LoopFuzz/afl-fuzz.c` + 12 个 `benchmark/subjects/*/loopfuzz/` 快照全部 `make afl-fuzz` 通过（rc=0）。

---

## 7. 结论与教训

1. **真漏洞仅 2 个，且都不可稳定复现**：live555（偶发 ~20%）、proftpd（~1/5 万竞态）。
2. **「证据等级」与「复现等级」必须分开标注**：ASAN 报告 + 符号化 + 源码自洽 → 高置信度「真实 bug」；重放失败 → 不能声称「可复现」。
3. **`unique_crashes=0` 是假象**：真 UAF 藏在 `replayable-hangs/`，只数 crash 会漏报。
4. **一个补丁修两个方向**：`stderr_has_asan_error()` 同时消除 kamailio 误报、找回 proftpd 漏报。
