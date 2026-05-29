# ChatAFL-Opt 消融实验指南

本指南基于当前 `ChatAFL-Opt` 的实现，定义消融矩阵设计、运行方式和结果解读。

> 代码核对状态（2026-05）：已按当前 `ChatAFL-Opt/afl-fuzz.c`、`run_ablation.sh`、
> `monitor.sh`、`benchmark/scripts/execution/profuzzbench_exec_common*.sh` 的真实行为校对。

---

## 一、消融矩阵

### 设计原则

**严格单变量消融**：消融矩阵中每组与 `full` 仅差一个开关。任意两组之间的性能差异可直接归因于该单一策略的净贡献，消除多变量混淆。

### 7 组定义

| 组名 | 关闭的策略 | 环境变量 |
|------|-----------|---------|
| **wo_all** | 全部四个需求 | `CHATAFL_HYPOTHESIS=0`, `NO_REFINEMENT=1`, `NO_FRONTIER=1`, `NO_ADAPTIVE=1`, `NO_STATE_PROMPT=1`, `THRESHOLD=512` |
| **full** | （无，全开） | （不设任何 `NO_*` 标志） |
| **wo_hypothesis** | 需求1+2+3 | `CHATAFL_HYPOTHESIS=0` |
| **wo_refinement** | 需求3 CEGAR | `NO_REFINEMENT=1` |
| **wo_frontier** | 需求4 稀有状态优先 | `NO_FRONTIER=1` |
| **wo_adaptive** | 需求4 自适应阈值 | `NO_ADAPTIVE=1`, `THRESHOLD=512` |
| **wo_state_prompt** | 需求4 状态感知 prompt | `NO_STATE_PROMPT=1` |

### 各组回答的问题

```
wo_all ────────────────────────────────────────────────────→ full
  │                                                             │
  │   差值 = 四个需求的总贡献                                       │
  │                                                             │
  ├── wo_hypothesis  →  full − wo_hypothesis  = 需求1+2+3 的净贡献
  ├── wo_refinement  →  full − wo_refinement  = 需求3 CEGAR 的净贡献
  ├── wo_frontier    →  full − wo_frontier    = 需求4 frontier 的净贡献
  ├── wo_adaptive    →  full − wo_adaptive    = 需求4 自适应的净贡献
  └── wo_state_prompt→  full − wo_state_prompt= 需求4 state prompt 的净贡献
```

| 组 | 作用 | 度量目标 |
|----|------|---------|
| **wo_all** | 下界锚点 | 退化到 ChatAFL + 固定阈值 512 的基线性能 |
| **full** | 上界锚点 | 四个需求全开的完整 ChatAFL-Opt 性能 |
| **wo_hypothesis** | 需求1+2+3 消融 | LLM 生成 grammar → 验证 → CEGAR 修正，整体是正向贡献还是拖累？ |
| **wo_refinement** | 需求3 消融 | 反例回喂 LLM 局部修补语法，修对了还是修歪了？ |
| **wo_frontier** | 需求4 消融 | 优先探索出度 0-1 的未饱和状态，能否加速状态空间覆盖？ |
| **wo_adaptive** | 需求4 消融 | 根据 edges 增长率动态调整 plateau 触发频率，比固定 512 好吗？ |
| **wo_state_prompt** | 需求4 消融 | 给 LLM 注入 IPSM 拓扑信息，生成的建议更精准吗？ |

### 阅读规则

```
full − wo_xxx > 0  →  该策略有正向贡献，保留
full − wo_xxx ≈ 0  →  该策略无明显效果，可裁剪
full − wo_xxx < 0  →  该策略存在负交互，需调整协调机制
```

---

## 二、消融开关详解

### 环境变量一览

| 变量 | 作用 |
|------|------|
| `CHATAFL_HYPOTHESIS=0` | 关闭整个语法假设系统（需求1+2+3）。`=1`（默认）时启用 |
| `CHATAFL_NO_REFINEMENT=1` | 关闭 Tier-2 反例驱动修正。Tier-1 采样验证仍运行 |
| `CHATAFL_NO_FRONTIER=1` | 关闭 frontier bonus（低出度状态 2×~4× 能量加成）+ error penalty（错误响应扣分） |
| `CHATAFL_NO_ADAPTIVE=1` | 关闭自适应 plateau 阈值，锁定为固定值 |
| `CHATAFL_NO_STATE_PROMPT=1` | 关闭状态感知 prompt，退化到 ChatAFL 原始简单 prompt |
| `CHATAFL_ABLATION_THRESHOLD=N` | 当 `NO_ADAPTIVE=1` 时指定固定阈值。建议显式设置 |

### 开关依赖关系

```
CHATAFL_HYPOTHESIS=0
  └── 隐式关闭 CEGAR（无 hypothesis 则无对象可 refine）

CHATAFL_NO_REFINEMENT=1 需要 CHATAFL_HYPOTHESIS=1 才有效
  └── 否则 periodic_hypothesis_refinement() 入口即返回
  └── run_ablation.sh / run_dev.sh 链路自动注入 HYPOTHESIS=1

CHATAFL_NO_ADAPTIVE=1 建议配合 CHATAFL_ABLATION_THRESHOLD=512
  └── 默认固定值 200 触发频率是 ChatAFL 基线 512 的 2.56×
  └── 显式设置 THRESHOLD=512 才能与 ChatAFL 对齐
```

### 验证开关生效

```bash
docker logs <容器ID> 2>&1 | grep "ABLATION\|hypothesis"
```

期望日志：

| 开关 | 期望日志 |
|------|---------|
| `HYPOTHESIS=0` | `hypothesis mode disabled` |
| `NO_REFINEMENT` | `ABLATION: Tier-2 hypothesis refinement DISABLED` |
| `NO_FRONTIER` | `ABLATION: Frontier bonus + error penalty DISABLED` |
| `NO_ADAPTIVE=1 THR=512` | `ABLATION: Adaptive plateau threshold DISABLED (fixed=512)` |
| `NO_STATE_PROMPT` | `ABLATION: State-aware rich prompt + actions[] DISABLED` |

---

## 三、运行方式

### 环境准备

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
export KEY="sk-..."
export SKIPCOUNT=40
```

`KEY` 是 LLM API key，`SKIPCOUNT` 是覆盖率统计间隔。`run_ablation.sh` 调用 `run_dev.sh`，使用本地 `ChatAFL-Opt/` 代码并在容器内重新编译。

### 预设模式

```bash
# 默认 core 预设（7 组单变量消融）
sudo -E ./run_ablation.sh live555 5 1470

# 阈值子实验（5 组）
sudo -E ./run_ablation.sh live555 5 1470 threshold

# 完整消融矩阵（core + threshold = 12 组）
sudo -E ./run_ablation.sh live555 5 1470 appendix

# 旧 bundled 7 组（仅历史复现）
sudo -E ./run_ablation.sh live555 5 1470 legacy
```

### 自定义消融组（`--groups`）

指定一个或多个消融组运行，跳过预设。参数值与 `monitor.sh` Ablation 列完全等价。

```bash
# 单组
sudo -E ./run_ablation.sh bftpd 3 240 --groups full

# 多组（逗号分隔）
sudo -E ./run_ablation.sh bftpd 3 240 --groups full,wo_adaptive,wo_all

# 短参数 -g
sudo -E ./run_ablation.sh live555 5 1470 -g wo_refinement,wo_frontier
```

**`--groups` 枚举值：**

```
wo_all, wo_hypothesis, full, wo_refinement, wo_frontier,
wo_adaptive, wo_state_prompt, adaptive_full,
fixed150, fixed200, fixed300, fixed512
```

### 参数说明

```bash
sudo -E ./run_ablation.sh [TARGET] [RUNS] [TIMEOUT_MIN] [PRESET] [--groups name1,name2,...]
```

| 参数 | 含义 | 默认值 |
|------|------|--------|
| `TARGET` | 目标协议实现 | `live555` |
| `RUNS` | 每组重复次数 | `5` |
| `TIMEOUT_MIN` | 每组运行分钟数 | `1470` |
| `PRESET` | 实验预设 | `core` |
| `--groups` | 自定义消融组，覆盖 PRESET | — |

---

## 四、预设详情

### `core` 预设（7 组，默认）

严格单变量消融矩阵。每组与 `full` 仅差一个开关。

| 组名 | 环境变量 |
|------|---------|
| `wo_all` | `HYPOTHESIS=0`, `NO_REFINEMENT=1`, `NO_FRONTIER=1`, `NO_ADAPTIVE=1`, `NO_STATE_PROMPT=1`, `THRESHOLD=512` |
| `full` | 无 |
| `wo_hypothesis` | `HYPOTHESIS=0` |
| `wo_refinement` | `NO_REFINEMENT=1` |
| `wo_frontier` | `NO_FRONTIER=1` |
| `wo_adaptive` | `NO_ADAPTIVE=1`, `THRESHOLD=512` |
| `wo_state_prompt` | `NO_STATE_PROMPT=1` |

### `threshold` 预设（5 组）

阈值子实验，研究 adaptive vs 固定阈值的差异。

| 组名 | 环境变量 |
|------|---------|
| `adaptive_full` | 无（等价于 `full`） |
| `fixed150_full` | `NO_ADAPTIVE=1`, `THRESHOLD=150` |
| `fixed200_full` | `NO_ADAPTIVE=1`, `THRESHOLD=200` |
| `fixed300_full` | `NO_ADAPTIVE=1`, `THRESHOLD=300` |
| `fixed512_full` | `NO_ADAPTIVE=1`, `THRESHOLD=512`（等价于 `wo_adaptive`） |

### `appendix` 预设（12 组）

= `core`（7 组）+ `threshold`（5 组），完整消融矩阵。

### `legacy` 预设（7 组）

旧 bundled 设计，仅用于历史结果对齐和复现。

- `full_opt`, `wo_refinement`, `wo_frontier`, `wo_adaptive_100`, `wo_adaptive_512`, `wo_state_prompt`, `wo_all`

**不建议**将 `legacy` 结果作为主消融证据。其中 `wo_adaptive_100` 的阈值 100 不与当前 adaptive 算法实际落点对应。

---

## 五、监控与结果

### monitor.sh

实时监控消融实验进度。Ablation 列标签与 `run_ablation.sh` 组名完全等价。

```bash
# 监控所有容器
./monitor.sh

# 只监控特定协议
./monitor.sh bftpd

# 单次采集
./monitor.sh -1
```

`monitor.sh` 通过读取容器内 `/proc/1/environ` 的 `CHATAFL_*` 变量来判定消融标签，与 `run_ablation.sh` 设置的值一致。

### 结果目录

每组写入独立目录：

```text
ablation/results-<target>_ablation_<label>_<timestamp>/
```

例如：

```text
ablation/results-bftpd_ablation_full_20260528T120000/
ablation/results-bftpd_ablation_wo_adaptive_20260528T120000/
ablation/results-bftpd_ablation_wo_all_20260528T120000/
```

### 推荐报告的指标

| 指标 | 来源 | 说明 |
|------|------|------|
| `bitmap_cvg` | fuzzer_stats | 边覆盖率 |
| `paths_total` | fuzzer_stats | 路径总数 |
| `execs_done` | fuzzer_stats | 总执行次数 |
| IPSM nodes / edges | ipsm.dot | 状态空间探索 |
| `unique_crashes` | fuzzer_stats | 唯一崩溃数 |
| `oracle_unique_violations` | fuzzer_stats | 语义漏洞发现数 |
| `llm_total_calls` | fuzzer_stats | LLM 总调用次数 |
| prompt / completion tokens | fuzzer_stats | LLM token 消耗 |

**关键归一化**：因 Docker CPU 争抢导致 Exec/s 差异可超过 3×，必须用 per-1000-execs 归一化指标（paths/1K、edges/1K、crashes/1K）来消除吞吐量差异。

### 判定语言

| 结论 | 条件 |
|------|------|
| **Supported** | 多数目标上 full 优于消融组，且无系统性成本膨胀 |
| **Mixed** | 部分目标提升、部分下降，或成本明显变差 |
| **Not supported** | 未能在多数目标上优于 full |

---

## 六、手动单组运行

不走 `run_ablation.sh` 时，手动运行单组的标准流程：

### 通用模板

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master

# 1) 清空所有消融环境变量
unset CHATAFL_HYPOTHESIS \
      CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
      CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
      CHATAFL_ABLATION_THRESHOLD

# 2) 设置当前组需要的变量
# export CHATAFL_NO_xxx=1
# export CHATAFL_ABLATION_THRESHOLD=xxx

# 3) 运行
sudo -E ./run_dev.sh <RUNS> <TIMEOUT_MIN> <TARGET> chatafl-opt

# 4) 跑完后清理
unset CHATAFL_HYPOTHESIS \
      CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
      CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
      CHATAFL_ABLATION_THRESHOLD
```

### 各组运行命令

**full（全效果）：**

```bash
unset CHATAFL_HYPOTHESIS CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
      CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT CHATAFL_ABLATION_THRESHOLD
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

**wo_all（全关闭基线）：**

```bash
export CHATAFL_HYPOTHESIS=0
export CHATAFL_NO_REFINEMENT=1
export CHATAFL_NO_FRONTIER=1
export CHATAFL_NO_ADAPTIVE=1
export CHATAFL_NO_STATE_PROMPT=1
export CHATAFL_ABLATION_THRESHOLD=512
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

**wo_hypothesis：**

```bash
export CHATAFL_HYPOTHESIS=0
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

**wo_refinement：**

```bash
export CHATAFL_NO_REFINEMENT=1
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

**wo_frontier：**

```bash
export CHATAFL_NO_FRONTIER=1
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

**wo_adaptive：**

```bash
export CHATAFL_NO_ADAPTIVE=1
export CHATAFL_ABLATION_THRESHOLD=512
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

**wo_state_prompt：**

```bash
export CHATAFL_NO_STATE_PROMPT=1
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

---

## 七、环境变量数据流

```
run_ablation.sh (export CHATAFL_*=...)
  → run_dev.sh (透传)
    → profuzzbench_exec_common_dev.sh (构建 ABLATION_FLAGS)
      → docker run -e CHATAFL_*=...
        → /proc/1/environ (容器内)
          → afl-fuzz.c getenv() (C 代码读取)
```

关键节点：

| 环节 | 文件 | 行为 |
|------|------|------|
| 消融组定义 | `run_ablation.sh` | 每组独立子 shell，先 `unset` 再 `export` |
| 环境透传 | `run_dev.sh` | 显式列出所有 `CHATAFL_*` 变量 |
| Docker 注入 | `profuzzbench_exec_common*.sh` | 硬编码 `-e CHATAFL_HYPOTHESIS=1`，ABLATION_FLAGS 追加开关 |
| C 代码读取 | `afl-fuzz.c` | `getenv()` 检查每个变量，设置对应的 `ablation_no_*` 标志 |

Docker `-e` 遵循 last-value-wins：`wo_all` 组导出 `CHATAFL_HYPOTHESIS=0`，出现在硬编码的 `CHATAFL_HYPOTHESIS=1` 之后，覆盖为 0。其余组不导出此变量，Docker 硬编码的 1 生效。

---

## 八、污染防控

### 什么会污染 full

任何残留的 `CHATAFL_NO_*` 或 `CHATAFL_ABLATION_THRESHOLD` 环境变量都会改变 full 行为：

```bash
# 错误：残留变量污染 full
export CHATAFL_NO_ADAPTIVE=1
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt   # 实际跑的是 wo_adaptive！
```

### 为什么 run_ablation.sh 不会污染

每个消融组在**独立子 shell** 中运行，启动前 `unset` 全部变量，结束后子 shell 退出，变量不会写回父 shell。组与组之间完全隔离。

### 安全复原

```bash
unset CHATAFL_HYPOTHESIS \
      CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
      CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
      CHATAFL_ABLATION_THRESHOLD

# 确认已清空
env | grep '^CHATAFL_' || echo "环境已干净"
```

---

## 九、已知限制

1. `wo_frontier` 同时关闭 frontier bonus 和 error penalty，不能拆分因果
2. `wo_state_prompt` 同时关闭 `state_ctx` 和 `actions[]` 路径，不能拆分因果
3. 需求2（Verifier）无独立开关——可解析性检查、Oracle、IPSM 状态跟踪与主循环耦合
4. fork 隔离、bounded execution、并行 enrichment、dedup ring 始终开启，无对应消融开关
5. 因此当前最严谨表述为："当前 shipped 行为下，某个 bundled policy 是否显示净效应"，而非"该模块的独立因果贡献已被严格证明"
6. `run_dev.sh` 独立运行等价于 `full` 组（无任何 `NO_*` 标志，`HYPOTHESIS=1`），通过 Docker 注入

### 如要实现真正正交消融

需新增开关：

- `CHATAFL_NO_FRONTIER_BONUS`（仅关 frontier bonus）
- `CHATAFL_NO_ERROR_PENALTY`（仅关 error penalty）
- `CHATAFL_NO_STATE_CTX`（仅关 state_ctx）
- `CHATAFL_NO_ACTIONS`（仅关 actions[]）
- `CHATAFL_NO_VERIFIER`（关验证器 pipeline）

这些开关实现之前，本文档与 `run_ablation.sh` 的 7 组 core 预设是当前最严谨、最可落地的版本。
