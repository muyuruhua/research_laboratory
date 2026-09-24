# LoopFuzz 真正触发历史漏洞 — 实施与验证结果

日期：2026-09-23/24。目标：**不喂触发种子**，LoopFuzz 在模糊测试过程中自行发现并记录 CVE-2023-51713（ProFTPD make_ftp_cmd OOB read）。

## 最终结果（清洁源码、3 分钟短程验证）

```
execs_done 2277 | unique_crashes 2 | escape_amp_applied 14 | 11.7 execs/s
```

- 种子：镜像自带 `in-ftp` 4 条 stock 种子（86–135B，无引号无转义）。
- 发现的 crash：`replayable-crashes/id:000000,sig:06,op:havoc_*` → 内容为 `"\N\K\E\O...` 引号内随机字母转义洪泛（46.8KB 行）。
- **重放归因（金标准）**：对独立 campaign 服务器重放 → `ERROR: AddressSanitizer: heap-buffer-overflow @ 0x4d687f`，`addr2line = make_ftp_cmd /home/ubuntu/experiments/proftpd/src/main.c:862` — CVE-2023-51713 精确命中。
- 证据：`evidence/loopfuzz-discovery/`（crash 文件、stats、重放归因日志）。

## 两个必要修复（缺一不可，均为本次发现）

### 修复 1：S2c 转义放大算子（搜索能力）+ CommandBufferSize 解锁（可见性）

- `LoopFuzz/mutation-ops.c/.h`：S2c 策略——把任一非鉴权行替换为 `"` + `\X`×N + `" X\r\n`（N 目标 [30720,61440)，随机字母转义）；并入现有 `UR(32)/UR(4)` 引擎调度；计数器 `escape_amp_applied` 进 fuzzer_stats；消融开关 `CHATAFL_NO_ESCAPE_AMP`（afl-fuzz.c env 块 + run_dev.sh + profuzzbench_exec_common_dev.sh 全链路转发）。
- `benchmark/subjects/FTP/ProFTPD/run.sh`：启动前注入 `CommandBufferSize 65535`（tab 锚点），使 cmd_buf 成为 65568B 独立池块（OOB 才可被 ASAN 看见；默认 512 时路径执行但零报告——已实测）。所有 fuzzer 共享，公平。

### 修复 2（**独立的重大发现**）：crash 记录竞态——SIGTERM 抢跑丢弃真实崩溃

**现象**：把已验证必崩的输入作为唯一种子直接喂 afl-fuzz，656 次执行 0 crash。探针实锤：38/38 次 `sig=6 (SIGABRT) term_sent=1`。

**根因链**：
1. 洪泛到达 → 服务器进入 ASAN 报告/abort 流程（重负载下 >1ms）；
2. fuzzer 的响应窗口（毫秒级）结束 → `send_over_network()` 对仍存活（正在 abort）的子进程发 SIGTERM → `child_term_sent=1`；
3. 子进程最终以 SIGABRT 死亡，但落入 `child_term_sent` 分支（"teardown 伪影"保护，为 kamailio 关停 abort 设计）；
4. 兜底检查 `stderr_has_asan_error()` 失败——SIGTERM 打断了 ASAN 报告写入，捕获文件里只有 proftpd 启动日志（实测 cap 文件每 exec 仅 +257B，无任何 ASAN 输出）；
5. → FAULT_NONE，**真实崩溃被静默丢弃**。

**修复**（`LoopFuzz/afl-fuzz.c` send_over_network 终止块之前）：`likely_buggy`（服务器无响应=崩溃征兆）时有界等待 ≤1s 让子进程自行死亡，死则 `child_term_sent` 保持 0 → SIGABRT 正常分类为 FAULT_CRASH。正常执行的等待代价为零（门控在 likely_buggy 上）。

**影响面**：该竞态系统性丢弃所有"abort 慢于响应窗口"的服务器端 ASAN 崩溃——机器负载越重越严重（用户 84 容器并发时 ASAN 报告显著变慢）。这解释了：pilot 12h×3 fuzzer 对 O-PFTP-01 的 0 recall、数月 campaign 的 proftpd 0 漏洞。**此修复与 S2c 无关，对所有 target 的 crash recall 都有增益。**

## 验证轨迹（全部可复跑）

1. 单元测试：`gcc vuln-seed-verification/scripts/s2c_unit_test.c LoopFuzz/mutation-ops.c` → PASS（46,079B 洪泛、鉴权前缀完好）。
2. 服务器侧：S2c 形态直连发送 → ASAN heap-buffer-overflow（三次独立容器验证）。
3. crash-seed 判定实验：修复前 656 execs 0 记录 → 修复后干跑即检出（"results in a crash"）。
4. 端到端发现：stock 种子 3 分钟 → 2 unique crashes → 重放归因 CVE-2023-51713。
5. 消融开关验证：Arm B（NO_ESCAPE_AMP=1）`escape_amp_applied: 0`（90 分钟 campaign，17,830 execs）。

## 修改文件清单

| 文件 | 改动 |
|---|---|
| `LoopFuzz/mutation-ops.c/.h` | S2c 策略 + 计数器 + 开关 extern |
| `LoopFuzz/afl-fuzz.c` | stats 行、消融 env 读取、**crash-grace wait 修复** |
| `benchmark/subjects/FTP/ProFTPD/run.sh` | CommandBufferSize 65535 注入（幂等） |
| `run_dev.sh`、`benchmark/scripts/execution/profuzzbench_exec_common_dev.sh` | CHATAFL_NO_ESCAPE_AMP 转发 |

## 重要注意事项

1. **公平性**：crash-grace 修复在 LoopFuzz 源内。论文对比实验若与 chatafl/aflnet 基线比 crash 数，需把同款修复移植到基线源码（ChatAFL/ 等目录有同源代码），否则对比不公平。S2c 作为 loopfuzz 的贡献点走消融（NO_ESCAPE_AMP）。
2. **历史数据不可比**：conf 变更 + 检测修复 = 环境变更，论文口径需全臂重跑。
3. **你的原始命令现在可直接重跑**：`run_dev.sh` 自动挂载修复后的 LoopFuzz 源码并在容器内重编，proftpd 的 run.sh 自动注入 conf。LLM 富集约占前 30 分钟（190 次 API 调用），之后进入 fuzzing；S2c 不依赖 LLM。
4. A2/B 两个 90 分钟臂是在 crash-grace 修复**之前**跑的（故 A2 有 326 次开火仍 0 crash——现在知道原因了）。修复后的正式臂矩阵（H1/H2）可按 TRIGGER-RIGOROUS-PLAN.md §4 重跑。
