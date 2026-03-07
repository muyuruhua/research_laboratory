# ChatAFL-Opt 消融实验使用指南

## 一、4 个消融开关

| 环境变量 | 关闭的优化 | 关闭后的行为 |
|---------|-----------|-------------|
| `CHATAFL_NO_REFINEMENT=1` | Tier-2 假设精炼 | 跳过 `periodic_hypothesis_refinement()` 调用 (afl-fuzz.c L7915) |
| `CHATAFL_NO_FRONTIER=1` | 前沿加权 + 错误惩罚 | `frontier_bonus` 恒为 1.0，无 out_degree 加权、无 error_hint 惩罚 (afl-fuzz.c L1018) |
| `CHATAFL_NO_ADAPTIVE=1` | 自适应高原阈值 | 阈值固定 100，不随 `edges_growth_rate` 调整 (afl-fuzz.c L7872) |
| `CHATAFL_NO_STATE_PROMPT=1` | 状态感知 rich prompt + actions[] | 跳过 `state_ctx` 构建 (L8029)；子进程用 ChatAFL 原版 `construct_prompt_stall_original()` (L8134)；禁用 actions[] 解析 (L8258) |

**不设任何变量 = 完整 ChatAFL-Opt（所有优化开启）。**

## 二、完整传递链路

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

### 关键差异

| | run_dev.sh | run.sh |
|---|---|---|
| 消融变量转发方式 | 依赖 `sudo -E` 环境继承 | 显式传 `CHATAFL_NO_*="${CHATAFL_NO_*}"` (run.sh L23-L26) |
| 代码来源 | volume 挂载本地 → 容器内编译 | 镜像内预编译（需先 `docker build`） |

## 三、执行命令

以下所有命令在 ChatAFL-master 目录执行：

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"
export SKIPCOUNT=40
```

### ① Full（完整版，不设消融变量）

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT
sudo -E ./run_dev.sh 5 200 exim chatafl-opt
```

### ② w/o Refinement

```bash
export CHATAFL_NO_REFINEMENT=1
unset CHATAFL_NO_FRONTIER CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT
sudo -E ./run_dev.sh 5 200 exim chatafl-opt
```

### ③ w/o Frontier

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_ADAPTIVE CHATAFL_NO_STATE_PROMPT
export CHATAFL_NO_FRONTIER=1
sudo -E ./run_dev.sh 5 200 exim chatafl-opt
```

### ④ w/o Adaptive

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER CHATAFL_NO_STATE_PROMPT
export CHATAFL_NO_ADAPTIVE=1
sudo -E ./run_dev.sh 5 200 exim chatafl-opt
```

### ⑤ w/o State-Prompt

```bash
unset CHATAFL_NO_REFINEMENT CHATAFL_NO_FRONTIER CHATAFL_NO_ADAPTIVE
export CHATAFL_NO_STATE_PROMPT=1
sudo -E ./run_dev.sh 5 200 exim chatafl-opt
```

> 生产环境只需将 `run_dev.sh` 替换为 `run.sh`，其他完全一致。

## 四、验证消融是否生效

在容器日志中查找启动时打印的确认信息：

```bash
docker logs <容器ID> 2>&1 | grep "ABLATION"
```

期望输出（以 w/o Frontier 为例）：

```
[+] ABLATION: Frontier bonus + error penalty DISABLED
```

4 条消融日志的对应关系 (afl-fuzz.c L12184-L12201)：

| 变量 | 日志输出 |
|------|---------|
| `NO_REFINEMENT` | `ABLATION: Tier-2 hypothesis refinement DISABLED` |
| `NO_FRONTIER` | `ABLATION: Frontier bonus + error penalty DISABLED` |
| `NO_ADAPTIVE` | `ABLATION: Adaptive plateau threshold DISABLED (fixed=100)` |
| `NO_STATE_PROMPT` | `ABLATION: State-aware rich prompt + actions[] DISABLED (simple prompt mode)` |

**无以上日志 = 该优化正常启用。**

## 五、消融矩阵设计

标准做法：**5 组配置 × 5 次重复 × N 个 target**

| 配置 | NO_REFINE | NO_FRONTIER | NO_ADAPTIVE | NO_STATE_PROMPT |
|------|:---------:|:-----------:|:-----------:|:---------------:|
| **Full** (ChatAFL-Opt) | ✗ | ✗ | ✗ | ✗ |
| **w/o Refinement** | ✓ | ✗ | ✗ | ✗ |
| **w/o Frontier** | ✗ | ✓ | ✗ | ✗ |
| **w/o Adaptive** | ✗ | ✗ | ✓ | ✗ |
| **w/o State-Prompt** | ✗ | ✗ | ✗ | ✓ |

每组的 **Δ = Full − w/o X**，Δ > 0 说明该组件有正向贡献。使用 Mann-Whitney U 检验 p < 0.05 判定统计显著性。

## 六、注意事项

1. **`sudo -E` 必须保留**——否则 sudo 清除环境变量，消融设置不会传入
2. **消融变量仅影响 `chatafl-opt`**——ChatAFL 基线和 AFLNet 的 `docker run` 不注入这些变量
3. **同时跑多 fuzzer 时**（如 `chatafl-opt,chatafl,aflnet`），消融变量只注入到 chatafl-opt 容器，不影响其他 fuzzer
4. **每次实验前用 `unset` 清除所有消融变量**，避免上次残留
5. **结果目录命名相同**（`res_exim_*`），需按消融配置手动重命名区分
