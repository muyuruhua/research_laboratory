# ChatAFL-Opt 消融实验使用指南

---

## 一、4 个消融开关：代码级精确描述

| 环境变量 | 实际控制的代码路径 | 不受该开关影响的路径 |
|---------|-----------------|-------------------|
| `CHATAFL_NO_REFINEMENT=1` | 跳过 `periodic_hypothesis_refinement()` (L7915)，即 Tier-2 LLM 精炼 | **Tier-1** `validate_hypothesis_sampled()` (L7228) **仍每 500 次 exec 运行**；`hypothesis_ctx` 仍初始化；反例仍被收集 |
| `CHATAFL_NO_FRONTIER=1` | `frontier_bonus` 恒为 1.0 (L1018)，同时关闭 `error_hint` 接受度惩罚 (L1040) | `error_hint` / `productivity` 字段仍被赋值、仍动态更新，只是不影响得分 |
| `CHATAFL_NO_ADAPTIVE=1` | 跳过 `edges_growth_rate` 三挡调整 (L7872)，阈值固定在 **100** | `edges_growth_rate` 仍每 60s 计算并打印；初始 `adaptive_plateau_threshold=UNINTERESTING_THRESHOLD=100` |
| `CHATAFL_NO_STATE_PROMPT=1` | 跳过 `state_ctx` JSON 构建 (L8029)；子进程用 `construct_prompt_stall_original()` (L8134)；禁用 `actions[]` 解析 (L8258) | dedup ring 仍 active；adaptive threshold 仍 active；fork 隔离 + 150s 超时仍 active |

**不设任何变量 = 完整 ChatAFL-Opt（所有优化开启）。**

---

## 二、已知的混淆项（Confounders）——必须在论文中说明

### ⚠️ 混淆项 1：`NO_ADAPTIVE` 固定值是 100，不是 ChatAFL 基线的 512

```c
// ChatAFL-Opt/config.h L76
#define UNINTERESTING_THRESHOLD  100  // Opt 的编译值

// ChatAFL/config.h L76
#define UNINTERESTING_THRESHOLD  512  // 基线的编译值
```

设置 `NO_ADAPTIVE=1` 后阈值固定在 **100**，比 ChatAFL 基线的 512 **触发频繁 5 倍**。因此 "w/o Adaptive" 测量的不是"去掉自适应后等同于基线触发频率"，而是"固定在最激进频率下去掉自适应"。

**论文写法**：在 "w/o Adaptive" 一行明确注明固定值为 100（并可以加一组 fixed=512 对比组与基线对齐）。

### ⚠️ 混淆项 2：`NO_REFINEMENT` 在没有 `CHATAFL_HYPOTHESIS` 时是**空操作**

```c
// L7904-7908
if (hypothesis_mode && !hypothesis_ctx) {
    init_grammar_hypothesis_system();  // hypothesis_mode=0 时跳过
}
// L7914
if (!ablation_no_refinement) {
    periodic_hypothesis_refinement();  // 内部 L5035: if (!hypothesis_mode...) return;
}
```

若运行时**未设置 `CHATAFL_HYPOTHESIS` 环境变量**，则 `hypothesis_mode=0`，`periodic_hypothesis_refinement()` 入口直接 return —— Full 配置与 w/o Refinement 配置行为**完全相同**，消融无效。

**结论**：`NO_REFINEMENT` 必须与 `CHATAFL_HYPOTHESIS=1` 配合使用，否则该组对比数据无意义。

### ⚠️ 混淆项 3：`NO_FRONTIER` 捆绑了两个机制

```c
if (!ablation_no_frontier) {
    // 机制 A：拓扑感知前沿加权 (out_degree → ×4 / ×2 / ×1)
    if (out_degree <= 1)      frontier_bonus = 4.0;
    else if (out_degree <= 3) frontier_bonus = 2.0;

    // 机制 B：接受度惩罚 (error_hint → ×0.25 / ×0.5)
    if (state->error_hint == 1) frontier_bonus *= 0.25;
    else if (...productivity < 0.01) frontier_bonus *= 0.5;
}
```

一个开关同时关闭了"IPSM 拓扑感知调度"和"可接受性惩罚"两个独立机制，无法分离各自贡献。若需细粒度证明，需拆分为两个开关（见第七节）。

### ⚠️ 混淆项 4：Bounded Execution（50ms SIGKILL）永远无法消融

```c
// send_over_network() — Opt 独有，无任何 ablation 开关
if (++kill_wait >= 250) {   // 250 × 200µs = 50ms
    kill(child_pid, SIGKILL);
    child_force_killed = 1;
}
```

ChatAFL 基线的两个 `while(1)` 对 forking daemon（pure-ftpd / proftpd / bftpd）会**无限阻塞**；Opt 所有配置（含 w/o-everything）均有 50ms 上限。对这三个目标，任何 Opt 配置与基线之间的差异都包含该机制的贡献，**无法通过消融开关排除**。

**论文写法**：在 forking daemon 目标的结果表格下加 footnote，说明 bounded-execution 始终 active，为 Opt 整体改进的组成部分之一。

### ℹ️ 非混淆项：节点停滞随机扰动始终 active

```c
// L12315 — 无 ablation 开关
if (node_stagnation_rounds > 80 && UR(100) < 30) {
    effective_algo = RANDOM_SELECTION;  // 30% 概率临时覆盖 FAVOR
}
```

该机制防止 FAVOR 热点锁定，但效果随机、幅度小（30% 概率、仅在节点 80 轮未增长后），在所有 Opt 配置中一致存在，不影响配置间对比的有效性。无需特别处理，在方法节描述即可。

---

## 三、完整传递链路

两条路径均已支持：

### 开发环境（volume 挂载，无需重建镜像）

```
宿主机 export  →  sudo -E  →  run_dev.sh
→  profuzzbench_exec_all_dev.sh（环境继承）
→  profuzzbench_exec_common_dev.sh（ABLATION_FLAGS 构建 + docker run -e）
→  容器内 afl-fuzz getenv()
```

### 生产环境（使用镜像内预编译代码）

```
宿主机 export  →  sudo -E  →  run.sh（显式转发 4 变量）
→  profuzzbench_exec_all.sh
→  profuzzbench_exec_common.sh（ABLATION_FLAGS 构建 + docker run -e）
→  容器内 afl-fuzz getenv()
```

| | run_dev.sh | run.sh |
|---|---|---|
| 消融变量转发方式 | 依赖 `sudo -E` 环境继承 | 显式传 `CHATAFL_NO_*="${CHATAFL_NO_*}"` (run.sh L23-L26) |
| 代码来源 | volume 挂载本地 → 容器内编译 | 镜像内预编译（需先 `docker build`） |

---

## 四、执行命令（以 live555/RTSP 为例）

以下所有命令在 ChatAFL-master 目录执行。live555 标准超时 **1470 分钟**（≈24.5 小时），每组 **5 次**重复。

### ▶ 推荐：一键并行运行全部 7 组（约 24.5 小时完成）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
export KEY="sk-..."
export SKIPCOUNT=40
sudo -E ./run_ablation.sh                      # 默认：live555，n=5，1470min
# 或显式指定：
sudo -E ./run_ablation.sh live555 5 1470
```

7 组同时在后台启动（35 个容器并行），结果目录自动按组命名：

```
benchmark/results-live555_ablation_full_opt/
benchmark/results-live555_ablation_wo_refinement/
benchmark/results-live555_ablation_wo_frontier/
benchmark/results-live555_ablation_wo_adaptive_100/
benchmark/results-live555_ablation_wo_adaptive_512/
benchmark/results-live555_ablation_wo_state_prompt/
benchmark/results-live555_ablation_wo_all/
```

启动后监控：
```bash
docker ps | grep live555    # 应看到 35 个容器
sudo ./monitor.sh           # 整体进度
```

---

### ▶ 手动单组运行（调试 / 单独补跑某组）

**前置准备**（仅需设置一次）：

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
export KEY="sk-..."        # 填入 API key
export SKIPCOUNT=40        # 每 40 个 testcase 统计一次覆盖率
```

> **关于 `CHATAFL_HYPOTHESIS=1`**：已由 `profuzzbench_exec_common_dev.sh` 自动注入所有 `chatafl-opt` 容器，无需手动 export。  
> **关于结果目录**：每次运行自动创建 `results-live555_<时间戳>/`，不同组不会覆盖。

---

### ① Full-Opt（消融基准，所有优化全开）

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER CHATAFL_NO_ADAPTIVE \
      CHATAFL_NO_STATE_PROMPT CHATAFL_ABLATION_THRESHOLD
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

### ② w/o Refinement（禁用 Tier-2 LLM 精炼，Tier-1 仍运行）

```bash
unset CHATAFL_NO_FRONTIER CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT CHATAFL_ABLATION_THRESHOLD
export CHATAFL_NO_REFINEMENT=1
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

> `CHATAFL_HYPOTHESIS=1` 由脚本自动注入；此处无需手动 export。Tier-1 (`validate_hypothesis_sampled`) 每 500 次 exec 仍运行，不受该开关影响。

### ③ w/o Frontier（禁用拓扑加权 + 接受度惩罚，捆绑贡献）

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT CHATAFL_ABLATION_THRESHOLD
export CHATAFL_NO_FRONTIER=1
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

### ④ w/o Adaptive —— 固定阈值 100（Opt 内部默认，最激进频率）

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER CHATAFL_NO_STATE_PROMPT CHATAFL_ABLATION_THRESHOLD
export CHATAFL_NO_ADAPTIVE=1
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

> 阈值固定为 100，比 ChatAFL 基线的 512 **触发频繁 5 倍**。Δ 体现"自适应相对于最激进固定值"的增益，而非与基线等价的固定值。

### ⑤ w/o Adaptive —— 固定阈值 512（与 ChatAFL 基线触发频率对齐）

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER CHATAFL_NO_STATE_PROMPT
export CHATAFL_NO_ADAPTIVE=1 CHATAFL_ABLATION_THRESHOLD=512
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

> 依赖 Fix 1（`afl-fuzz.c` 已实现）以及 `CHATAFL_ABLATION_THRESHOLD` 向容器的转发（已添加至两份 `exec_common` 脚本）。

### ⑥ w/o State-Prompt（禁用 rich prompt + actions[] 执行，捆绑贡献）

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER CHATAFL_NO_ADAPTIVE CHATAFL_ABLATION_THRESHOLD
export CHATAFL_NO_STATE_PROMPT=1
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
```

### ⑦ w/o All（全禁用；量化不可消融工程改进的基础贡献）

```bash
export CHATAFL_NO_REFINEMENT=1 CHATAFL_NO_FRONTIER=1 \
       CHATAFL_NO_ADAPTIVE=1 CHATAFL_NO_STATE_PROMPT=1 \
       CHATAFL_ABLATION_THRESHOLD=512
sudo -E ./run_dev.sh 5 1470 live555 chatafl-opt
# 实验结束后务必清除，避免污染后续实验
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER CHATAFL_NO_ADAPTIVE \
      CHATAFL_NO_STATE_PROMPT CHATAFL_ABLATION_THRESHOLD
```

> 此组 **≠ ChatAFL**：Fork 隔离、50ms SIGKILL bounded execution、32 线程并行 enrich、dedup ring 在所有 Opt 配置下始终 active，这 4 项没有消融开关。  
> `Full − w/o-All = 4 个开关的纯净贡献之和`  
> `w/o-All 与 ChatAFL 的差 ≈ 不可消融工程改进的基础增益`（见第六节矩阵 ⑦ 行说明）

---

**生产环境**（使用镜像内预编译代码）：将 `run_dev.sh` 替换为 `run.sh`，其他完全一致。

---

## 五、验证消融是否生效

```bash
docker logs <容器ID> 2>&1 | grep "ABLATION\|hypothesis"
```

| 开关 | 期望日志 |
|------|---------|
| `NO_REFINEMENT` | `ABLATION: Tier-2 hypothesis refinement DISABLED` |
| `NO_FRONTIER` | `ABLATION: Frontier bonus + error penalty DISABLED` |
| `NO_ADAPTIVE` | `ABLATION: Adaptive plateau threshold DISABLED (fixed=100)` |
| `NO_STATE_PROMPT` | `ABLATION: State-aware rich prompt + actions[] DISABLED (simple prompt mode)` |
| `CHATAFL_HYPOTHESIS` 生效 | `hypothesis mode DEFERRED (lazy init on first plateau)` |

**无以上日志 = 该优化正常启用（或前置条件缺失）。**

额外检查 Tier-1 是否运行（与 `NO_REFINEMENT` 无关，始终应出现）：

```bash
docker logs <容器ID> 2>&1 | grep "hypothesis-refine\|hypothesis\]" | head -5
```

---

## 六、消融矩阵设计（严格修订版）

### 关键前提：消融的逻辑起点

**消融的比较对象必须是 Full-Opt，不是 ChatAFL**。ChatAFL 是主实验（§5.1）的对比对象；消融回答的是"组件 X 对 Opt 整体贡献多少"。

另一关键约束：**同时关闭全部 4 个开关 ≠ ChatAFL**。以下机制无消融开关，始终生效：
- Fork 隔离 LLM 调用（ChatAFL 主进程同步阻塞）
- 50ms SIGKILL bounded execution（ChatAFL 对 forking daemon 无限阻塞）
- 32 线程并行 seed enrichment（ChatAFL 串行）
- djb2 64槽 prompt dedup ring

因此必须增加 **w/o-All** 配置行，以量化这些不可消融的工程改进的基础贡献。

### 严格消融矩阵（8 行）

| 行 | 配置 | NO_REFINE | NO_FRONTIER | NO_ADAPTIVE | NO_STATE_PROMPT | 阈值 | 消融目标 |
|----|------|:---------:|:-----------:|:-----------:|:---------------:|:---:|---------|
| ① | **Full-Opt** | ✗ | ✗ | ✗ | ✗ | 50-150 | 基准（所有 Δ 的分母） |
| ② | **w/o Refinement** ¹ | ✓ | ✗ | ✗ | ✗ | 50-150 | Tier-2 LLM精炼贡献（Tier-1 仍 active，不是完全无假设精炼） |
| ③ | **w/o Frontier** | ✗ | ✓ | ✗ | ✗ | 50-150 | 拓扑加权+接受度惩罚的**联合**贡献 ² |
| ④ | **w/o Adaptive (100)** | ✗ | ✗ | ✓ | ✗ | 100 | 自适应相对于固定最激进值（100）的增量 |
| ⑤ | **w/o Adaptive (512)** ³ | ✗ | ✗ | ✓ | ✗ | 512 | 自适应相对于与 ChatAFL 对齐的固定值（512）的增量 |
| ⑥ | **w/o State-Prompt** | ✗ | ✗ | ✗ | ✓ | 50-150 | rich prompt + actions[] 的**联合**贡献（含提示工程和结构化动作） ² |
| ⑦ | **w/o All** | ✓ | ✓ | ✓ | ✓ | 512 | 不可消融工程改进的基础贡献；应 ≈ ChatAFL + bounded exec + parallel enrich |
| ✦ | *(ChatAFL 参考行)* | — | — | — | — | 512 | 不参与 Δ 计算，仅作 context |

¹ 必须同时设置 `CHATAFL_HYPOTHESIS=1`，否则 w/o Refinement ≡ Full（见第二节混淆项 2）。  
² 此行测量捆绑贡献；若需细粒度分离，见第七节 Fix 3（`NO_ERROR_HINT`）和潜在的 `NO_ACTIONS` 开关。  
³ 需设置 `CHATAFL_ABLATION_THRESHOLD=512`（已实现，见第七节 Fix 1）。

每组 **Δ_X = metric(Full) − metric(w/o-X)**，Δ_X > 0 说明组件 X 有正向贡献。  
组件重要性排序：Δ 越大、$\hat{A}_{12}$ 越高、p 越小，组件越关键。

### 统计检验方法

消融配置之间**共享相同代码基础**，随机性主要来自种子选择和 LLM 回复差异，**不建议用 Mann-Whitney U**（独立样本假设不完全成立）。推荐：

**主要指标：Vargha-Delaney $\hat{A}_{12}$（效果量）**

$$\hat{A}_{12}(A, B) = \frac{\#\{a > b\} + 0.5 \times \#\{a = b\}}{n_A \times n_B}$$

| $\hat{A}_{12}$ | 效果大小 |
|:---:|:---:|
| 0.5 | 无效果 |
| 0.56 | small |
| 0.64 | medium |
| 0.71 | large |
| 1.0 | 完全分离 |

**辅助指标：Wilcoxon 秩和检验**（单侧，α=0.05），报告精确 p 值。

**n=5 vs n=10 的检验力**：

| n（每组重复次数） | Mann-Whitney $P_{min}$（U=0时） | 中等效果量下 power |
|:---:|:---:|:---:|
| 5 | 0.0079 | **~30%**（大量漏报） |
| 10 | $1.1 \times 10^{-5}$ | **~75%** |
| 15 | $3.6 \times 10^{-9}$ | **~92%** |

**n=5 时只有效果极显著（所有 A > 所有 B）才能 p<0.05**。推荐：**n=5 可接受，但以 $\hat{A}_{12}$ 为主要指标，p 值作为辅助**；在论文中明确说明 n=5 的检验力限制。

---

## 七、当前代码的已知缺陷及修复方案

### Fix 1：`NO_ADAPTIVE` 支持参数化固定阈值 ✅ 已实现

**问题**：固定值硬编码为 100，无法与 ChatAFL 基线的 512 对齐。

**已实现**（`afl-fuzz.c` L12198 附近）：读取 `CHATAFL_ABLATION_THRESHOLD` 环境变量覆盖默认固定值；banner 打印实际生效阈值及与基线的关系说明。

用法：
```bash
# 与 ChatAFL 基线触发频率对齐（512）
export CHATAFL_NO_ADAPTIVE=1 CHATAFL_ABLATION_THRESHOLD=512

# 保持 Opt 默认固定值（100，触发最激进）
export CHATAFL_NO_ADAPTIVE=1
```

启动日志中会显示：
```
ABLATION: Adaptive plateau threshold DISABLED (fixed=512 from CHATAFL_ABLATION_THRESHOLD)
...
  NO_ADAPTIVE fixed threshold : 512 (matches ChatAFL baseline)
```

### Fix 2：`NO_REFINEMENT` 前置条件检查 ✅ 已实现

**问题**：未设置 `CHATAFL_HYPOTHESIS` 时该开关无效，但当前无任何警告。

**已实现**（`afl-fuzz.c` L12198 附近）：若 `CHATAFL_NO_REFINEMENT=1` 但未设 `CHATAFL_HYPOTHESIS`，同时触发 `WARNF()` 和 `fprintf(stderr)` 双重警告，并在 ABLATION CONFIG banner 中重复打印。

验证：
```bash
docker logs <容器ID> 2>&1 | grep "NO-OP\|WARNING"
# 期望输出：
# [ABLATION WARNING] NO_REFINEMENT is a no-op without CHATAFL_HYPOTHESIS=1.
# *** ABLATION WARNING: NO_REFINEMENT is a NO-OP (hypothesis_mode=0) ***
```

### Fix 3（可选，细粒度）：分离 `NO_ERROR_HINT` 开关

**问题**：`NO_FRONTIER` 同时关闭了"拓扑加权"和"接受度惩罚"，无法分离两者贡献。

```c
static u8 ablation_no_error_hint = 0;  // 新增

if (!ablation_no_frontier) {
    // 机制 A：出度加权（始终由 NO_FRONTIER 控制）
    frontier_bonus = ...;
}
if (!ablation_no_frontier && !ablation_no_error_hint) {
    // 机制 B：接受度惩罚（可单独关闭）
    if (state->error_hint == 1) frontier_bonus *= 0.25;
    ...
}
```

---

## 八、操作注意事项

1. **`sudo -E` 必须保留**——否则 sudo 清除环境变量，消融设置不会传入
2. **`CHATAFL_HYPOTHESIS=1` 是 `NO_REFINEMENT` 的前置条件**——两者必须同时设置
3. **消融变量仅影响 `chatafl-opt`**——ChatAFL 基线和 AFLNet 的 `docker run` 不注入这些变量
4. **每次实验前用 `unset` 清除所有消融变量**，避免上次残留
5. **使用 `run_ablation.sh` 时结果目录已自动命名**（`results-live555_ablation_<label>/`）；手动单组运行时结果目录为 `results-live555_<时间戳>/`，需手动重命名区分
6. **forking daemon 目标**（pure-ftpd / proftpd / bftpd）的实验结果：Bounded Execution（50ms SIGKILL）在所有 Opt 配置下始终 active，在论文结果分析中需单独说明
