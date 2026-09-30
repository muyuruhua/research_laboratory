# 漏洞 crash 全量重放报告（2026-09-30，第 1 步）

## 执行内容

对 `(newest)vulnerability` 下全部战役 crash/hang 工件做全量重放，不新跑任何 fuzzing 战役。

## ProFTPD / O-PFTP-01（CVE-2023-51713）——oracle 对差分重放（核心）

- 输入：2 个 LoopFuzz 24h 战役 run（Sep-25，arm=loopfuzz-gated-fixed）的 replayable-crashes 全量 233（121+112）+ teardown-crashes 9，共 242；每个输入在 o-pftp-01:vuln 与 o-pftp-01:patched 各重放一次（aflnet-replay，FTP/21，ASAN 镜像对，base 61e621e743346，patched 仅差上游修复 97bbe68363cc）。
- 判定：合并 stdout+stderr 中的 ASAN heap-buffer-overflow 且帧为 make_ftp_cmd（oracle 谓词）。注意 proftpd 为 per-connection fork：子进程崩溃、主进程存活，存活不构成否证；ASAN 报告走 stdout。
- **结果：vuln 172/242 触发（172 个全部为 make_ftp_cmd 帧，无任何其他签名；战役内 172/233：run1 83/121、run2 89/112；teardown 0/9）；patched 0/242 无 ASAN 激活。**
- 61/233 战役内输入未独立复现（原因未定位：可能需要战役会话状态；战役侧 .asan.log 旁车每 run 仅 1 份含 ASAN 记录，旁车不可靠，oracle 对重放为权威判定）。
- 证据：`cve-benchmark/oracles/O-PFTP-01/results/full_crash_replay_20260930/`（双侧 chunk.tsv、differential_results.tsv、SUMMARY.md、脚本）。

## live555（CVE-2026-38998）——单侧重放

- 输入：88 个 crash（3+85）× live555:latest 战役镜像（该构建无 ASAN），30s 超时。
- **结果：82/88 终止服务器（退出码 1），6/88 存活。**
- 边界：无 vuln/patched 对、无 ASAN → 不能归因到 heap-UAF；仅为战役构建复现率。
- 证据：`(newest)vulnerability/replay_analysis_20260930/`。

## forked-daapd / SMARTPL

无需重跑：战役全部 5 个 hang 已于 2026-09-20 全量重放为 0/5（论文措辞由"five sampled"改为"all five recorded"）。

## Kamailio / O-KAM-01（CVE-2026-39863）——全队列条目谓词普查（补充轮）

纠正：kamailio 为逻辑漏洞（有符号溢出的负值产物），证据口径本就是队列条目的谓词重放；战役 0 crash 不代表无工件——队列里有满足前置条件的条目。

- 输入：2 个 LoopFuzz 战役 run（Sep-27，TCP 形态，453/1506 分钟，队列 1997/2557 条）中全部含 Content-Length ≥ 2^31 的条目，共 253（r1 77、r2 176）。论文原"195 entries"为当时快照。
- 方法：每条独立起服务，o-kam-01:vuln / :patched 双侧重放（TCP 5060 整文件流式发送，SIP 按 Content-Length 分帧）；阳/阴性对照先通过（vuln 命中 −10，patched 打守卫日志）。注：aflnet-replay 的 SIP 为 UDP，不能用于此谓词，故用自写 TCP 发送器。
- **结果：vuln 102/253 产生负值产物（r1 36/77、r2 66/176；−2147483648×58、−1×42、−954437177×2）；patched 0/253 负值行，193/253 打出上游 large-value 守卫。** 151/253 未触发（前置满足但无产物，报文次序/解析路径未定位）。
- 证据：`cve-benchmark/oracles/O-KAM-01/results/full_queue_replay_20260930/`。
- 论文更新：tab:cve 控制证据格、tab:cveresults 整行、Kamailio 案例段、"全量重放"段（扩展为三项：ProFTPD、LIVE555、Kamailio）。


## 论文更新（main.revised.tex，已重编译 23 页、0 溢出）

- tab:cveresults：ProFTPD 行改为全量重放口径（172/233 触发、patched 0/242）；live555 行补 82/88 复现；SMARTPL 行改为"全部 5 个"。
- 正文：新增全量重放协议与结果段（含 61 个不可复现与 teardown 0/9 的如实说明）；ProFTPD 案例段升级为"已验证版本对的差分重放证据"。

## 口径边界（不可声称的内容）

- 重放对象是 crash 工件，不是 campaign recall：无 time-to-trigger、无 arm 级发现概率、无成本口径。
- ProFTPD 的 172/233 是"LoopFuzz 两次战役产生的 crash 工件中可独立复现且命中 CVE 谓词的比例"，不是"CVE 被发现概率"。
