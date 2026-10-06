# LoopFuzz Evidence Controller v2 — 论文对齐改造说明

对应论文：*When Protocol States Mislead: Evidence-Gated Admission and Online
Feedback Calibration for LLM-Assisted Stateful Fuzzing*（`C_two_papers/first_paper.md`）。

本次改造把 LoopFuzz 从「LLM + 若干启发式」升级为**证据校准控制器**：
LLM 只产生假设（hypothesis generator），候选必须在真实目标上执行
（execute-before-promote）拿到证据后，才能进入长期（durable）队列；
response-derived state 的效用由在线后验校准，而非固定信任。

---

## 0. v3 保真度修复（2026-10-05，first-batch，schema_version=3）

针对专家 P0-1/P0-2/P0-4 的实现层修复，重跑 C/D/E 前必须先部署：

1. **真正的 execute-before-promote（P0-1）**：LLM 候选 trial 期间设置
   `admission_trial_mode`，`save_if_interesting()` 对 trial 只做**非破坏性
   novelty 探测**（scratch 副本上调 `has_new_bits`），不入队、不消耗
   virgin map。评估顺序固定为 P → isolated trial → U/R → 独立 G_code/G_state
   → decision。**decision 事件（`admission_decision`）先于任何队列插入写盘**，
   durable 只有 `P∧U∧R∧G_code` 才由 `admission_promote_durable()` 显式入队
   （此时才把 trial bitmap 应用到真实 virgin map）。arm C 保持 legacy 直通路径
   （它就是反事实对照），trial mode 仅对门控 arm（D/E）启用。
2. **G_state 与 retention 解耦（P0-1）**：新增**观察台账**（observed-state /
   observed-transition 两个 khash 集合），每次 trial 的响应状态序列先登记；
   新颖性 = 不在 IPSM ∪ 台账。旧实现里 IPSM 只在入队后更新，导致
   `¬G_code∧G_state` 结构性不可能、provisional 恒为 0 —— 已消除。
   admission 事件新增字段：`trial_hnb`（0/1/2，2=新 edge）、
   `obs_new_states`、`obs_new_transitions`。
3. **provisional 预算逐 descendant 前置检查（P0-1）**：`common_fuzz_stuff()`
   顶部 per-exec 钩子在实际执行**之前**检查并原子扣减 `prov_budget_left`
   （TTL 同检），预算耗尽即中止该 entry 的继续变异；账本不变量：
   `descendant_execs ≤ budget`。`provisional_account_after_fuzz()` 只负责
   生命周期收尾（convert/expire），不再事后扣减。停机时存活 provisional
   记 `censor`（保留文件与证据），与 expire 区分。
4. **arm 身份时序修复（P0-2）**：全部 arm 生效的环境变量解析抽取为
   `evidence_env_parse()`，在 `run_config_log("start")` **之前**执行 ——
   修复了 Sep-2026 tarball 中 start 事件系统性把 arm 标成 gated-fixed +
   默认 γ 的 bug（end 事件才是真值）。
5. **reward 口径纯净（P0-4）**：`code_save_events`（任意覆盖 save，含
   hit-count-only）与 `code_gain_events`（**仅新 edge，hnb==2**）分离；
   episode reward 与 provisional 转化只看新 edge。durable promotion 记
   `admission_gain_events`，绝不混入 episode reward。
6. **固定 episode 能量（P0-4）**：`CHATAFL_EPISODE_ENERGY`（默认 512，
   0=关闭）限定每个 state-selection episode 的 havoc/splice 阶段执行数，
   deterministic 阶段不算能量（一次性阶段，保持谱系）。episode 事件新增
   `completed` / `posterior_updated` / `episode_energy_cap` / `energy_used` /
   `energy_exhausted`。
7. **episode 完成度门控（P0-4）**：零变异 episode（无 seed 状态的空选）与
   被 stop 中断的 episode 只记录（`reward=-1` 或 `posterior_updated=false`），
   **不更新后验**；LLM trial 的执行/收益通过 `cal_episode_rebase_after_trial()`
   从当期 episode 的 mutations/reward 中剔除（trial 归 candidate 账）。

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

所有命令在 `ChatAFL-master/` 目录下执行。目标列表固定为 9 个：
`exim,live555,kamailio,lighttpd1,pure-ftpd,forked-daapd,lightftp,bftpd,proftpd`

### 论文 5-arm 完整矩阵（§七）

#### Arm A — aflnet 基线（无 LLM，无 admission）

```bash
export KEY="sk-..." && export SKIPCOUNT=100
sudo -E ./run_dev.sh 3 180 exim,live555,kamailio,lighttpd1,pure-ftpd,forked-daapd,lightftp,bftpd,proftpd aflnet
```

| 每目标跑几次 | 一次多久 | 总 run 数 |
|---|---|---|
| 3 次 | 180 min（3h） | 9 × 3 = 27 |

#### Arm B — chatafl 基线（LLM，无 admission）

```bash
export KEY="sk-..." && export SKIPCOUNT=100
sudo -E ./run_dev.sh 3 180 exim,live555,kamailio,lighttpd1,pure-ftpd,forked-daapd,lightftp,bftpd,proftpd chatafl
```

| 每目标跑几次 | 一次多久 | 总 run 数 |
|---|---|---|
| 3 次 | 180 min（3h） | 9 × 3 = 27 |

#### Arm D — loopfuzz gated-fixed（默认，证据门控 + 固定 state policy）

```bash
export KEY="sk-..." && export SKIPCOUNT=100
sudo -E ./run_dev.sh 3 180 exim,live555,kamailio,lighttpd1,pure-ftpd,forked-daapd,lightftp,bftpd,proftpd loopfuzz
```

| 每目标跑几次 | 一次多久 | 总 run 数 |
|---|---|---|
| 3 次 | 180 min（3h） | 9 × 3 = 27 |

#### Arm C + E — 论文因果对照组（9 目标逐个跑）

```bash
export KEY="sk-..." && export SKIPCOUNT=100

# 9 目标逐个执行（direct=C  gated_fixed=D  calibrated=E，每组 1 容器 × 1580 min）：
for T in exim live555 kamailio lighttpd1 pure-ftpd forked-daapd lightftp bftpd proftpd; do
  sudo -E ./run_ablation.sh $T 1 1580 -g direct,gated_fixed,calibrated
done
```

| 每目标跑几次 | 一次多久 | 总 run 数 |
|---|---|---|
| 每组 1 次，共 3 组（C/D/E） | 1580 min（~26.3h） | 9 目标 × 3 组 × 1 = 27 |

#### γ 敏感性（9 目标逐个跑）

```bash
export KEY="sk-..." && export SKIPCOUNT=100

# γ 三档（0.995 默认 / 0.99 / 1.0，论文 §五.3）：
for T in exim live555 kamailio lighttpd1 pure-ftpd forked-daapd lightftp bftpd proftpd; do
  sudo -E ./run_ablation.sh $T 1 1580 -g calibrated,cal_gamma099,cal_gamma100
done
```

| 每目标跑几次 | 一次多久 | 总 run 数 |
|---|---|---|
| 每组 1 次，共 3 组 | 1580 min（~26.3h） | 9 目标 × 3 组 × 1 = 27 |

### 补充消融（论文不直接要求，可作 appendix）

```bash
# 单变量消融矩阵（6 组）——以 bftpd 为例，可换其他目标：
sudo -E ./run_ablation.sh bftpd 1 1580 -g full,wo_hypothesis,wo_refinement,wo_frontier,wo_adaptive,wo_admission
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
| `CHATAFL_EPISODE_ENERGY` | 512 | 每 episode havoc 阶段固定执行预算（v3，0=关闭） |

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
