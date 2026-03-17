# ChatAFL-Opt 消融实验使用指南（按当前代码结构设计）

本指南基于**当前实现本身**来设计消融，不依赖旧结果是否好看。

> 代码核对状态（2026-03）：本文档已按当前 `ChatAFL-Opt/afl-fuzz.c`、`run_ablation.sh`、
> `benchmark/scripts/execution/profuzzbench_exec_common*.sh` 的真实行为重新校对。
> 其中最重要的更新有三点：
> 1. `CHATAFL_NO_ADAPTIVE=1` 的默认固定阈值现在是 `UNINTERESTING_THRESHOLD=200`，
>    只有显式设置 `CHATAFL_ABLATION_THRESHOLD` 才会变成 `150/300/512/...`；
> 2. `CHATAFL_NO_REFINEMENT=1` 若没有 `CHATAFL_HYPOTHESIS=1` 会退化为 no-op，但
>    `run_ablation.sh` / `run_dev.sh` 的容器链路当前会自动为 `chatafl-opt` 注入该变量；
> 3. `legacy` 预设中的 `wo_adaptive_100` 现已在脚本中显式导出
>    `CHATAFL_ABLATION_THRESHOLD=100`，因此它再次表示真正的 fixed-100 历史复现实验，
>    但仍只建议用于旧结果对齐，不建议进入当前主表。

目标只有两个：

1. 让实验问题与当前代码结构严格对应；
2. 在**不改功能逻辑**的前提下，把 `run_ablation.sh` 变成更合理的实验编排器。

---

## 一、先给结论：当前代码下最合理的设计

如果只看当前代码，而**不参考先前旧结果**，最合理的设计不是“固定 512 当唯一主锚点”，也不是“旧 bundled 7 组直接继续跑”。

更合理的做法是把实验分成两层：

### 层 A：主消融表 —— 解释当前 shipped 策略的组成

主表应该以**当前实际 shipped 行为**作为基线，即：

- `adaptive_full`

然后只回答当前代码中真正存在的 3 个策略 bundle 是否有净效应：

- `wo_refinement`
- `wo_frontier`
- `wo_state_prompt`

再补 2 个阈值对照，检验 adaptive 本身是否成立：

- `fixed200_full`
- `fixed512_full`

也就是说，当前最合理的主矩阵应当是 **6 组**，而不是旧的 7 组 bundled 表。

### 层 B：阈值子实验 —— 单独研究 plateau 触发策略

adaptive 在当前代码里只会把阈值调到：

- `150`
- `200`
- `300`

所以阈值子实验应该围绕这些**当前真实会出现的值**来做，而不是继续把 `100` 当主选项。

因此阈值子实验应为：

- `adaptive_full`
- `fixed150_full`
- `fixed200_full`
- `fixed300_full`
- `fixed512_full`

其中：

- `150/200/300` 对应当前 adaptive 的真实三档；
- `512` 是外部参考锚点，用于与 ChatAFL 传统触发频率对齐。

---

## 二、为什么当前代码就应该这样设计

原因不是旧结果，而是**代码耦合关系**本身。

### 1）`adaptive` 是触发频率策略，不是普通局部开关

当前 plateau handler 中：

- `adaptive` 直接决定多久进入一次 plateau 逻辑；
- plateau 逻辑内部又会触发：
  - lazy hypothesis init
  - Tier-2 refinement
  - rich state prompt / simple prompt
  - actions[] 执行路径
  - LLM 调用计数与 token 成本

所以 `adaptive` 不是“和 refinement/frontier/state_prompt 平级的局部开关”，而是**上层调度策略**。

这意味着：

- 主表里必须把 `adaptive` 当作一个单独问题来比较；
- 不能再把它和其他 bundle 完全混在一起解释；
- 但也不应该先验地把某个固定阈值直接设成唯一主基线。

### 2）`NO_FRONTIER` 与 `NO_STATE_PROMPT` 仍然是 bundled ablation

当前代码里：

- `CHATAFL_NO_FRONTIER=1` 同时关掉：
  - frontier out-degree bonus
  - error/productivity penalty
- `CHATAFL_NO_STATE_PROMPT=1` 同时关掉：
  - `state_ctx`
  - rich prompt 模板
  - `actions[]` 路径

因此主表最多只能回答：

- “这个 bundle 在当前 shipped 策略下是否有净效果？”

不能回答：

- “frontier bonus 单独贡献多少”
- “error penalty 单独贡献多少”
- “state_ctx 和 actions[] 谁更重要”

### 3）`NO_REFINEMENT` 是有效开关，但它依赖 plateau 触发

当前脚本链路会自动为 `chatafl-opt` 容器注入 `CHATAFL_HYPOTHESIS=1`，所以 `NO_REFINEMENT` 在 `run_ablation.sh` 下是有效的。

更具体地说，当前 `afl-fuzz.c` 在读取 `CHATAFL_NO_REFINEMENT=1` 时会打印
`ABLATION: Tier-2 hypothesis refinement DISABLED`；若没有 `CHATAFL_HYPOTHESIS=1`，还会明确打印
warning 说明该消融没有效果。因此：

- 通过 `run_ablation.sh` / `run_dev.sh` 跑 `chatafl-opt`，该开关是有效的；
- 手工直接起容器或绕开脚本时，必须自己确认 `CHATAFL_HYPOTHESIS=1` 已注入。

但 refinement 只在 plateau handler 内被调用，因此其效果天然受触发策略影响。

这也是为什么：

- 主表里可以比较 `adaptive_full` vs `wo_refinement`；
- 但如果要进一步研究 refinement 是否对某个静态阈值更敏感，那应当作为**后续补充实验**，而不是默认主表。

---

## 三、当前代码里真实存在的消融开关

截至当前实现，`ChatAFL-Opt/afl-fuzz.c` 真正支持的开关只有这些：

| 环境变量 | 当前实际作用 | 解释边界 |
|---|---|---|
| `CHATAFL_NO_REFINEMENT=1` | 关闭 Tier-2 `periodic_hypothesis_refinement()` | **Tier-1 sampled validation 仍运行**；且必须有 `CHATAFL_HYPOTHESIS=1` 才不是空操作 |
| `CHATAFL_NO_FRONTIER=1` | 同时关闭 frontier bonus 与 error/productivity penalty | 这是一个 **bundled** 开关，不是单一机制 |
| `CHATAFL_NO_ADAPTIVE=1` | 关闭 adaptive plateau threshold | 固定阈值默认为 `200`（即 `UNINTERESTING_THRESHOLD`），也可由 `CHATAFL_ABLATION_THRESHOLD` 显式覆盖 |
| `CHATAFL_NO_STATE_PROMPT=1` | 关闭 `state_ctx` 与 `actions[]` 路径，回退原始 prompt | 这同样是 **bundled** 开关 |
| `CHATAFL_ABLATION_THRESHOLD=<N>` | 在 `NO_ADAPTIVE=1` 时指定固定阈值 | 建议总是显式写出，避免“默认 200”造成误读 |

### 重要事实

- `profuzzbench_exec_common_dev.sh` 与 `profuzzbench_exec_common.sh` 已自动为 `chatafl-opt` 容器注入 `CHATAFL_HYPOTHESIS=1`；
- `run_ablation.sh` 每组都在独立子 shell 中先 `unset` 再 `export` 当前组变量，因此组与组之间不会串环境；
- `benchmark/scripts/execution/profuzzbench_exec_common*.sh` 会把 `CHATAFL_NO_*` 与 `CHATAFL_ABLATION_THRESHOLD` 原样透传进容器；
- 因此当前脚本里做 `NO_REFINEMENT` 对比是有效的；
- 但 `frontier` 和 `state prompt` 仍然是 bundled ablation，**当前代码无法分离**：
  - `frontier bonus` vs `error penalty`
  - `state_ctx` vs `actions[]`

---

## 四、当前推荐的主消融矩阵：`core` 预设

`run_ablation.sh` 默认执行 `core` 预设。这个预设不依赖旧结果，而是直接对齐当前代码的 4 类可观察策略：

1. 当前 shipped 行为；
2. refinement bundle；
3. frontier bundle；
4. state-prompt bundle；
5. adaptive 触发策略的两个关键静态对照。

### `core` 预设的 6 组

| 组名 | 环境变量 | 解释目标 |
|---|---|---|
| `adaptive_full` | 无 | 当前 shipped 行为，主基线 |
| `wo_refinement` | `NO_REFINEMENT=1` | 当前 adaptive 策略下，Tier-2 refinement 是否有净效果 |
| `wo_frontier` | `NO_FRONTIER=1` | 当前 adaptive 策略下，frontier bundle 是否有净效果 |
| `wo_state_prompt` | `NO_STATE_PROMPT=1` | 当前 adaptive 策略下，state-prompt bundle 是否有净效果 |
| `fixed200_full` | `NO_ADAPTIVE=1`, `THR=200` | adaptive 相对于 Opt 默认静态频率是否有净效果 |
| `fixed512_full` | `NO_ADAPTIVE=1`, `THR=512` | adaptive 相对于 ChatAFL 对齐频率是否有净效果 |

### 为什么主表不默认带 `wo_all`

`wo_all` 在当前代码下会同时改变多个 policy bundle，但：

- 仍保留 fork 隔离、bounded execution、并行 enrichment、dedup ring；
- 仍然不是 ChatAFL；
- 也无法作为严格因果分解依据。

因此更合理的做法是：

- **主表不用 `wo_all`**；
- 如果确实需要整体 sanity check，再放到 appendix 预设里单独跑。

### 当前论文里主表怎么解释

推荐主表口径：

- `adaptive_full` 是当前系统；
- `wo_refinement` / `wo_frontier` / `wo_state_prompt` 是对当前系统做的三组 bundled perturbation；
- `fixed200_full` / `fixed512_full` 用来回答 adaptive 触发策略是否成立。

这样最贴近当前代码语义，也最不容易过度解释。

---

## 五、辅助预设

### 1）`threshold` 预设：阈值子实验

用于单独回答“当前 adaptive 三挡策略是否优于静态阈值”的问题。

包含 5 组：

| 组名 | 环境变量 |
|---|---|
| `adaptive_full` | 无 |
| `fixed150_full` | `NO_ADAPTIVE=1`, `THR=150` |
| `fixed200_full` | `NO_ADAPTIVE=1`, `THR=200` |
| `fixed300_full` | `NO_ADAPTIVE=1`, `THR=300` |
| `fixed512_full` | `NO_ADAPTIVE=1`, `THR=512` |

这 5 组的好处是：

- `150/200/300` 全都来自当前 adaptive 真实会落到的阈值；
- `512` 保留为外部参考锚点；
- 不再把当前代码里不会自动出现的 `100` 当主实验一部分。

### 2）`appendix` 预设：补充 sanity-check

如果你仍希望保留“全关 policy bundle”的粗粒度检查，可使用 `appendix`：

- `adaptive_full`
- `wo_refinement`
- `wo_frontier`
- `wo_state_prompt`
- `fixed200_full`
- `fixed512_full`
- `wo_all`

这里的 `wo_all` 只建议放 appendix，不建议进主表。

### 3）`legacy` 预设：旧 bundled 7 组复现

包含旧脚本那 7 组：

- `full_opt`
- `wo_refinement`
- `wo_frontier`
- `wo_adaptive_100`（显式固定 100，仅用于历史复现）
- `wo_adaptive_512`
- `wo_state_prompt`
- `wo_all`

该预设保留的唯一目的：

- 与旧结果目录命名保持兼容；
- 复现旧论文表格；
- 与历史归档直接对齐。

注意：虽然 `wo_adaptive_100` 现在已经通过 `CHATAFL_ABLATION_THRESHOLD=100` 恢复为真正的 fixed-100 组，
它仍然只服务于历史 bundled 7 组复现。由于 100 不是当前 adaptive controller 会自然落到的阈值，
也不是当前 shipped 主矩阵的一部分，因此不建议再把它当作主论文中的默认 adaptive 对照。

**不建议**再把 `legacy` 结果当作主消融证据。

---

## 六、推荐的报告口径

### 强结论目标集

当前只建议对以下目标做强结论：

- `exim`
- `live555`
- `mosquitto`
- `pure-ftpd`

原因：这 4 个目标历史上有完整、平衡的消融 runs。

### 弱证据 / appendix only

- `kamailio`：补齐到每组 5 seeds 之前，只做弱证据；
- `forked-daapd`：现有消融归档缺失，不能写强结论。

### 每组至少报告的指标

- `l_abs`, `b_abs`
- `IPSM nodes`, `IPSM edges`
- `paths_total`
- `llm_total_calls`
- prompt / completion tokens
- `unique_crashes`, `unique_hangs`
- 若可用，再加 `forced_kills`

### 建议的判定语言

- **Supported**：多数目标 coverage 提升且没有系统性成本膨胀；
- **Mixed**：部分目标提升、部分目标下降，或成本明显变差；
- **Not supported**：未能在多数目标上优于主锚点。

---

## 七、运行方式

以下命令都在 `ChatAFL-master` 根目录执行。

### 先准备环境

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
export KEY="sk-..."
export SKIPCOUNT=40
```

说明：

- `KEY` 是当前 LLM 调用所需的 API key；
- `SKIPCOUNT` 是覆盖率统计间隔；
- `run_ablation.sh` 默认调用 `run_dev.sh`，因此会使用当前本地 `ChatAFL-Opt/` 代码并在容器内重新编译；
- `profuzzbench_exec_common_dev.sh` / `profuzzbench_exec_common.sh` 会自动为 `chatafl-opt` 容器注入 `CHATAFL_HYPOTHESIS=1`，因此 `wo_refinement` 在脚本路径下是有效的。

### 默认：运行新的 `core` 预设

```bash
sudo -E ./run_ablation.sh live555 5 1470
```

等价于：

```bash
sudo -E ./run_ablation.sh live555 5 1470 core
```

### 运行阈值子实验

```bash
sudo -E ./run_ablation.sh live555 5 1470 threshold
```

### 运行 appendix sanity-check

```bash
sudo -E ./run_ablation.sh live555 5 1470 appendix
```

### 复现旧 bundled 7 组

```bash
sudo -E ./run_ablation.sh live555 5 1470 legacy
```

### 结果目录命名

每组都写入：

```text
benchmark/results-<target>_ablation_<label>/
```

例如：

```text
benchmark/results-live555_ablation_adaptive_full/
benchmark/results-live555_ablation_wo_frontier/
benchmark/results-live555_ablation_fixed512_full/
```

### 参数说明

```bash
sudo -E ./run_ablation.sh [TARGET] [RUNS] [TIMEOUT_MIN] [PRESET]
```

含义如下：

- `TARGET`：目标协议实现，例如 `live555`、`exim`、`mosquitto`、`pure-ftpd`
- `RUNS`：每组重复次数，例如 `5`
- `TIMEOUT_MIN`：每组 campaign 运行分钟数，例如 `1470`
- `PRESET`：实验预设，可选 `core` / `threshold` / `appendix` / `legacy`

例如：

```bash
# 对 mosquitto 跑默认主矩阵，每组 5 次、24.5 小时
sudo -E ./run_ablation.sh mosquitto 5 1470 core

# 对 exim 跑阈值子实验
sudo -E ./run_ablation.sh exim 5 1470 threshold

# 对 pure-ftpd 跑 appendix 版本（含 wo_all）
sudo -E ./run_ablation.sh pure-ftpd 5 1470 appendix
```

### 手动单组运行某个 ablation 的标准模板

如果你不想走 `run_ablation.sh`，而是要手动只跑某一组，推荐固定按下面这个流程来，避免环境残留把 full 或别的组污染掉。

#### 通用模板

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master

# 1) 先清空所有 ablation 环境变量
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD ABLATION_PRESET

# 2) 只设置当前这一个实验组需要的变量
# export CHATAFL_NO_...=1
# export CHATAFL_ABLATION_THRESHOLD=...

# 3) 运行单组
sudo -E ./run_dev.sh <RUNS> <TIMEOUT_MIN> <TARGET> chatafl-opt

# 4) 跑完后再次清理，避免污染后续 full / 其他实验
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD ABLATION_PRESET
```

#### 手动跑 full（无消融）

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD ABLATION_PRESET

sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

#### 手动跑 `wo_refinement`

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD ABLATION_PRESET

export CHATAFL_NO_REFINEMENT=1
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt

unset CHATAFL_NO_REFINEMENT
```

#### 手动跑 `wo_frontier`

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD ABLATION_PRESET

export CHATAFL_NO_FRONTIER=1
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt

unset CHATAFL_NO_FRONTIER
```

#### 手动跑 `wo_state_prompt`

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD ABLATION_PRESET

export CHATAFL_NO_STATE_PROMPT=1
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt

unset CHATAFL_NO_STATE_PROMPT
```

#### 手动跑 `fixed200_full`

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD ABLATION_PRESET

export CHATAFL_NO_ADAPTIVE=1
export CHATAFL_ABLATION_THRESHOLD=200
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt

unset CHATAFL_NO_ADAPTIVE CHATAFL_ABLATION_THRESHOLD
```

#### 手动跑 `fixed512_full`

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD ABLATION_PRESET

export CHATAFL_NO_ADAPTIVE=1
export CHATAFL_ABLATION_THRESHOLD=512
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt

unset CHATAFL_NO_ADAPTIVE CHATAFL_ABLATION_THRESHOLD
```

#### 手动跑 `wo_all`（只建议 appendix / 粗粒度 sanity-check）

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD ABLATION_PRESET

export CHATAFL_NO_REFINEMENT=1
export CHATAFL_NO_FRONTIER=1
export CHATAFL_NO_ADAPTIVE=1
export CHATAFL_NO_STATE_PROMPT=1
export CHATAFL_ABLATION_THRESHOLD=512
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt

unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD
```

#### 手动运行时的两个原则

1. **先 `unset`，再 `export` 当前组需要的变量。**
2. **跑完后再次 `unset`。**

只要遵守这两条，手动跑单组一般不会污染后续 full 结果。

---

## 八、哪些情况会污染 full 结果？怎么安全复原环境？

### 什么叫“污染 full 结果”

只要你的 full 运行意图是“按默认 LoopFuzz 行为跑”，那么**任何 ablation 环境变量残留**都会污染 full 结果。

会污染 full 的变量只有这几类：

- `CHATAFL_NO_REFINEMENT`
- `CHATAFL_NO_FRONTIER`
- `CHATAFL_NO_ADAPTIVE`
- `CHATAFL_NO_STATE_PROMPT`
- `CHATAFL_ABLATION_THRESHOLD`

它们一旦被 `export`，再执行：

- `sudo -E ./run_dev.sh ...`
- `sudo -E ./run.sh ...`

就会把 ablation 配置继续带进容器，从而不再是 full 行为。

### 哪些情况最容易误污染

最常见的是这几种：

1. 你在当前 shell 里手动执行过：

```bash
export CHATAFL_NO_ADAPTIVE=1
export CHATAFL_ABLATION_THRESHOLD=512
```

然后忘了 `unset`，直接继续跑 full。

2. 你为了单独调试某组，手动执行过：

```bash
export CHATAFL_NO_REFINEMENT=1
sudo -E ./run_dev.sh ...
```

然后下一次还在同一个 shell 里跑 full。

3. 你在 root shell / sudo 保留环境下做过手动实验，没有清掉环境变量。

### 为什么 `run_ablation.sh` 本身不会污染其他组

因为 `run_ablation.sh` 里每个 ablation 组都在**独立子 shell**里运行，并且启动前都会先：

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD TIMESTAMP
```

然后再按需设置该组自己的变量。

所以：

- 组与组之间不会串；
- `run_ablation.sh` 结束后也不会把这些变量写回你当前父 shell。

换句话说，**真正容易污染 full 的不是 `run_ablation.sh`，而是你手工 `export` 后直接跑 `run_dev.sh` / `run.sh`。**

### 最安全的复原方式

如果你怀疑当前 shell 已经带了 ablation 变量，先执行：

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD ABLATION_PRESET
```

然后检查：

```bash
env | grep '^CHATAFL_' || true
```

如果没有输出，说明当前 shell 已经恢复到“无消融变量”状态。

### 最稳妥的 full 跑法

如果你要明确跑 full，而不是任何消融组，建议先清环境，再执行：

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER \
  CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT \
  CHATAFL_ABLATION_THRESHOLD ABLATION_PRESET

sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

如果你想进一步保险，最简单的方法是：

- 新开一个干净 shell；
- 只设置 `KEY` 和 `SKIPCOUNT`；
- 不设置任何 `CHATAFL_*` 消融变量；
- 再跑 full。

### 一句话原则

- **不设置 `CHATAFL_NO_*` / `CHATAFL_ABLATION_THRESHOLD`，就不会影响 full。**
- **开关存在本身不会影响 full，只有你把它们带入运行环境才会影响。**

---

## 九、验证是否生效

```bash
docker logs <容器ID> 2>&1 | grep "ABLATION\|hypothesis"
```

应看到类似日志：

| 开关 | 期望日志 |
|---|---|
| `NO_REFINEMENT` | `ABLATION: Tier-2 hypothesis refinement DISABLED` |
| `NO_FRONTIER` | `ABLATION: Frontier bonus + error penalty DISABLED` |
| `NO_ADAPTIVE=1 THR=512` | `ABLATION: Adaptive plateau threshold DISABLED (fixed=512 from CHATAFL_ABLATION_THRESHOLD)` |
| `NO_STATE_PROMPT` | `ABLATION: State-aware rich prompt + actions[] DISABLED (simple prompt mode)` |

如果你手工跑 `NO_REFINEMENT` 且忘了注入 `CHATAFL_HYPOTHESIS=1`，当前代码还会额外打印：

- `ABLATION: CHATAFL_NO_REFINEMENT set but CHATAFL_HYPOTHESIS not set — ablation has NO EFFECT`

这说明该次实验不应被当作有效 refinement 消融数据。

---

## 十、当前设计仍然有哪些限制

即使换成新的 `core` 预设，以下限制仍然成立：

1. `wo_frontier` 依然是 **frontier bonus + error penalty** 的联合关闭，不能拆因果；
2. `wo_state_prompt` 依然是 **state_ctx + actions[]** 的联合关闭，不能拆因果；
3. fork 隔离、bounded execution、并行 enrichment、dedup ring 仍然始终开启，没有对应开关；
4. 因此当前最严谨的表述应是：
  - “当前 shipped 行为下，某个 bundled policy 是否显示净效应”；
  - “adaptive 相对于若干静态阈值是否成立”；
  - 而不是“该模块的独立因果贡献已被严格证明”。

---

## 十一、如果以后要做到真正正交消融，需要新增什么开关

未来若要做更强的论文级因果分解，建议新增：

- `CHATAFL_NO_FRONTIER_BONUS`
- `CHATAFL_NO_ERROR_PENALTY`
- `CHATAFL_NO_STATE_CTX`
- `CHATAFL_NO_ACTIONS`

届时再做真正的 Stage-A / Stage-B 正交矩阵。

在这些开关实现之前，**本文件与 `run_ablation.sh` 的默认设计就是当前最严谨、最可落地的版本**。
