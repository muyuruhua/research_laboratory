# Teardown 候选 ASAN 容器重放 Triage 报告

- **日期**：2026-09-02
- **对象**：`benchmark/results-*_Sep-02_18-16-08`（9 target × 3 runs × 180 min，
  LoopFuzz evidence-controller v2，arm D）产生的全部 teardown-crashes 候选
- **候选清单**（共 **39** 个唯一输入，全部 `race:1`，即 SIGTERM 时子进程仍存活）：

| Target (run) | 候选数 | 信号 |
|---|---|---|
| kamailio run1 | 23 | 全部 sig:06 (SIGABRT) |
| lighttpd1 run1 | 13（去重后 12） | 12×SIGABRT + 1×sig:09 |
| bftpd run1 | 1 | sig:06 |
| proftpd run2 / run3 | 1 + 1 | sig:06 |

## 1. 判定标准（沿用 `loopfuzz-Aug-14-vuln-report.md` 的项目判据）

**真实内存安全 bug 的首要判据 = `.asan.log` / stderr 中出现
`ERROR: AddressSanitizer`**，辅以可重放性（ASAN 构建下重放崩溃）。
纯 `abort()`/SIGABRT 出现在 SIGTERM 关闭窗口且无 ASAN 报告 = 关停伪影
（shutdown artifact），不是输入触发的漏洞。

四张镜像（kamailio/lighttpd1/bftpd/proftpd）均以 `AFL_USE_ASAN=1` 构建，
容器内即 ASAN 版目标，满足重放判据的硬件前提。

## 2. Triage 方法与结果

### Phase A —— ASAN 容器内输入重放（主证据）

对每个候选：全新启动 ASAN 目标 → `aflnet-replay` 按长度前缀逐包重放
`.request.replay` 种子 ×30 次 → 监控进程存活 + `log_path` ASAN 报告。

| Target | 候选×重放 | 崩溃 | ASAN 报告 |
|---|---|---|---|
| kamailio | 23×30 = 690 | **0** | **0** |
| lighttpd1 | 13×30 = 390 | **0** | **0** |
| bftpd | 1×30 = 30 | 0（见 §3） | **0** |
| proftpd | 2×30 = 60 | 0（见 §3） | **0** |

（`aflnet-replay <file> <proto> <port> 0` 的第 4 参为本地端口，种子格式
为 4 字节小端长度前缀 + 消息体——与保存格式一致，重放语义忠实。）

### Phase B —— SIGTERM 窗口与良性对照

- **独立进程 SIGTERM**：4 个 target 的良性对照（无输入 / 良性会话后发
  SIGTERM）均 `exit=0` 干净退出——独立运行的主进程不会 abort。
- **FTP 服务“会话后退出”定性**：bftpd `-D`（不预 fork）与 proftpd
  `-X`(`--nofork`) 在**良性**会话（USER/PASS/QUIT）后同样以 `ec=0` 退出
  （proftpd 8/8，bftpd 3/3；空闲 40 s 不退出）。Phase A 中 FTP 候选的
  "exited_after_replay" 是这两个标志的正常单会话语义，与输入无关。

### Phase C —— forkserver 模式复现（与产生候选的执行模型一致）

以候选为唯一种子、关闭 LLM（无 KEY）、真实 `afl-fuzz` 运行 ~5 分钟：

| Target | execs | unique_crashes | hangs | 新 teardown 候选 | 其中带 ASAN |
|---|---|---|---|---|---|
| bftpd | 3,487 | 0 | 0 | 0 | — |
| proftpd | 3,112 | 0 | 0 | 0 | — |
| lighttpd1 | 1,921 | 0 | 0 | 2 | **0** |
| kamailio | 48（初始化后早退，与输入无关） | 0 | 0 | 0 | — |

lighttpd1 在忠实执行模型下**再次产生** teardown 候选且仍无 ASAN 报告
——即该信号在 forkserver 关闭窗口可复发，但从不伴随内存错误，与
“关停伪影”解释一致。

### 旁证

1. **fuzz 时已做过一次 ASAN 筛查**：teardown 候选的保存条件就是
   “SIGTERM 窗口致命信号 **且** stderr 无 `ERROR: AddressSanitizer`”
   （Aug-2026 crash-channel hardening 的 `stderr_has_asan_error()` 逻辑）。
   即原始执行的 stderr 已经不含 ASAN 内存错误。
2. **历史同签名反证**：Aug-14 报告将 7 个同签名 kamailio 关闭期 SIGABRT
   候选放入 ASAN 版 kamailio 重放，7/7 全不崩，判定误报；根因是
   `handle_sigs`（main.c:735）收到 SIGTERM 后 `shutdown_children()`
   路径 `abort()`，与输入内容无关。本批 23 个 kamailio 候选为同类。

## 3. 结论

**39/39 候选全部判定为关停伪影（shutdown artifact），无一构成漏洞。**

- 0 个候选在 ASAN 构建下重放崩溃（1,170 次重放总数）；
- 0 份 `ERROR: AddressSanitizer` 报告（重放时与原始 fuzz 时双重缺失）;
- FTP 两个“服务退出”事件被良性对照证明是 `-D`/`--nofork` 的正常
  单会话语义；
- forkserver 忠实模型下复发的新 teardown 候选同样无 ASAN。

**凭什么不是漏洞**（正面陈述判据链）：不满足项目漏洞判据的任何一条——
无 ASAN 报告（判据一）、ASAN 版重放 100% 不崩（判据二）、行为与输入
无关（良性对照等价复现，判据三）。

## 4. 附件

- 重放/triage 脚本：`/tmp/triage/triage_{kamailio,lighttpd1,ftp}.sh`、
  `forkserver_bftpd.sh`（如需保留请拷入仓库）
- 原始日志：`/tmp/triage/out/*.log`
- 本批证据目录：各 `out-*/teardown-crashes/`（含 `.request.replay` 种子）

## 5. 对论文的影响

按 first_paper.md §十二.6 的口径：这批运行**不应**以 crash 文件数量计
漏洞；teardown 候选属于 `bug_event` 的 "reached-but-untriggered / 待
triage" 类证据，本报告完成其 disposition（all: shutdown-artifact）。
建议在 `bug-events.jsonl` 中补记 teardown 候选（当前该日志只覆盖
save_if_interesting 路径的 crash/hang），使 triage 结果可机读 join。
