# LoopFuzz Evidence Controller v2 — 论文对齐改造说明

对应论文：*When Protocol States Mislead: Evidence-Gated Admission and Online
Feedback Calibration for LLM-Assisted Stateful Fuzzing*（`C_two_papers/first_paper.md`）。

本次改造把 LoopFuzz 从「LLM + 若干启发式」升级为**证据校准控制器**：
LLM 只产生假设（hypothesis generator），候选必须在真实目标上执行
（execute-before-promote）拿到证据后，才能进入长期（durable）队列；
response-derived state 的效用由在线后验校准，而非固定信任。

---

## 1. 论文要求 → 实现映射

| 论文章节 | 要求 | 实现 |
|---|---|---|
| §三.3 | 拆分 G_code / G_state | `admission_evaluate()`：`g_code_pass`（bitmap/native/favored 证据）与 `g_state_pass`（IPSM node/state edge）**分开判定、分开记录**；日志字段 `g_code_pass` / `g_state_pass` |
| §四 | 两级队列 | `admission_provisional_queue_candidate()` / `provisional_account_after_fuzz()` / `provisional_expire()`；预算默认 **64 次 descendant 变异** 或 **30 s TTL**，先到为准 |
| §五 | Beta-Bernoulli 后验 + Thompson | `evidence-cal.c`（纯逻辑、可单测）：`θ_s ~ Beta(1,1)`，discounted 更新 `α←1+γ(α−1)+r`，γ=0.995；调度 `Score(s)=Frontier(s)·[ε+(1−ε)θ̃_s]`，ε=0.1 |
| §五.1 | episode 定义 | 主循环一次 (choose_state → choose_seed → fuzz_one) = 一个 episode；reward=该 episode 内是否发现**新 code edge**（`code_gain_events`，与 IPSM novelty 完全独立） |
| §七 | 5-arm 因果设计 | A=aflnet, B=chatafl（已有）；**C**=`CHATAFL_NO_ADMISSION=1`（direct）；**D**=默认（gated+fixed policy）；**E**=`CHATAFL_CALIBRATION=1`（gated+calibrated）。D↔E 仅差调度项 |
| §九 | LLM 配置可审计 | `chat_llm_apply_sampling_env()`：`CHATAFL_TOP_P`（默认1.0）、`CHATAFL_MAX_TOKENS`（默认4096）统一生效并写入 run-config |
| §十 | 六类 append-only 日志 | 见下表 |
| §十一 | 机制指标 | `evidence_report.py`：Precision@H、Brier、ECE、reliability bins、disposition 分布、conversion rate |

## 2. 六类事件日志（out_dir 下，JSON Lines，schema_version=2）

| 文件 | 内容关键字段 |
|---|---|
| `run-config.jsonl` | `phase(start/end)`, `arm`, `model/top_p/max_tokens/call_cap`, `cal_gamma/epsilon`, `provisional_*`, `fuzzer_commit`, `rng_seed`, `termination_reason` |
| `candidate-events.jsonl` | `candidate_id`, `prompt_id/prompt_hash/raw_reply_hash`, `input/output_tokens`, `source_state`, `requested_target_state` |
| `admission-events.jsonl` | `trial_id→candidate_id`, P/U/R reason codes, **g_code/g_state 分列**, `disposition`(reject/provisional/durable), pre/post IPSM nodes & state edges & code branches |
| `provisional-events.jsonl` | `kind(admit/convert/expire)`, `budget_left`, `descendant_execs/code_gain`, `conversion_time_ms`, `reason` |
| `state-episodes.jsonl` | `alpha_before/beta_before/posterior_mean_before/sampled_theta`（**全部 pre-update，无信息泄漏**）, `mutations`, `new_code_edges`, `new_state_edges`, `reward`, `alpha_after/beta_after` |
| `bug-events.jsonl` | crash/hang 的 `oracle_id`(信号签名), artifact, target_state |

术语约定（论文 §三）：日志与文档中 **code edge/branch** = 程序覆盖反馈；
**IPSM/state edge** = 响应状态机转移。绝不单独写 "edge"。

## 3. 运行方式

### 全效果（= 论文 arm D：gated-fixed）

```bash
export KEY="sk-..." && export SKIPCOUNT=100
sudo -E ./run_dev.sh 3 180 exim,live555,kamailio,lighttpd1,pure-ftpd,forked-daapd,lightftp,bftpd,proftpd loopfuzz
```

### 消融（含论文 5-arm 对照组）

```bash
# 现有组照常工作：
sudo -E ./run_ablation.sh bftpd 1 1580 -g full,wo_hypothesis,wo_refinement,wo_frontier,wo_adaptive,wo_admission

# 论文因果 arm 组（新增）：
#   direct=C  gated_fixed|full=D  calibrated=E
sudo -E ./run_ablation.sh bftpd 1 1580 -g direct,gated_fixed,calibrated
# γ 敏感性（0.99 / 0.995默认 / 1.0，论文 §五.3 冻结后仅此三档）：
sudo -E ./run_ablation.sh bftpd 1 1580 -g calibrated,cal_gamma099,cal_gamma100
```

### 环境变量

| 变量 | 默认 | 含义 |
|---|---|---|
| `CHATAFL_CALIBRATION` | 0（arm D） | 1=arm E：Thompson 后验调度替换固定 p_s<0.005 penalty |
| `CHATAFL_CAL_GAMMA` | 0.995 | 折扣因子 γ（pilot 后冻结） |
| `CHATAFL_CAL_EPSILON` | 0.1 | 最低探索权重 ε |
| `CHATAFL_PROVISIONAL_BUDGET` | 64 | provisional descendant 变异预算 |
| `CHATAFL_PROVISIONAL_TTL_MS` | 30000 | provisional 墙钟 TTL |
| `CHATAFL_PROVISIONAL_MAX_LIVE` | 64 | 并发存活 provisional 上限（FIFO 驱逐） |
| `CHATAFL_NO_ADMISSION` | 0 | 1=arm C（parseable→durable 直接入队，反事实对照） |
| `CHATAFL_ADMISSION_LOG` | 1 | 0=关闭 admission JSONL（门控仍生效） |
| `CHATAFL_EVENT_LOG` | 1 | 0=关闭全部 JSONL 事件日志 |
| `CHATAFL_TOP_P` / `CHATAFL_MAX_TOKENS` | 1.0 / 4096 | LLM 采样配置（所有调用统一） |

### 离线指标

```bash
./evidence_report.py benchmark/out-bftpd-loopfuzz/
# 或机器可读：
./evidence_report.py --json OUT_DIR
```

## 4. 与旧行为的兼容性

- **run_dev.sh 全效果**：旧行为是「P 合法即执行，原生覆盖决定入队」；
  新默认在**完全相同的执行路径**上增加了两级 admission：无 code 收益但
  有 IPSM 新颖性的候选进 provisional（此前直接丢弃）；其余不变。
- **wo_admission 消融组**：语义不变（parseable→durable 强制入队），
  现在同时就是论文 arm C。
- **其余消融组**（wo_hypothesis/wo_refinement/wo_frontier/wo_adaptive/
  wo_state_prompt/fixed*）：不受影响；wo_frontier 在 arm E 下同时关闭
  frontier 项与校准项的作用面（校准因子仍在，但 Frontier(s)=base）。
- **arm E 下 Fix-19 固定 penalty 被替换**（不是叠加）——这是 D vs E
  单变量对照的必要条件。

## 5. 单元测试

```bash
cd LoopFuzz && make evidence_selftest && ./evidence_selftest
# 覆盖：discounted 后验算术、非平稳衰减、裁决表（A/B/C 三情形与
# U/R fail 优先级）、Beta(1,1) 与 Beta(9,1) 采样统计、分数组合、
# ε 探索下限、确定性重放。
```
