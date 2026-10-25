# LoopFuzz 消融实验指南（11 臂版）

本指南定义当前 `LoopFuzz` 消融矩阵的 **11 个臂**、运行方式与结果解读。
旧版 wo_\*/full/fixed\* 消融组已废弃，本文档不再包含。

> 代码核对状态（2026-10-24）：臂定义与 `run_ablation.sh`、
> `LoopFuzz/afl-fuzz.c` 的真实环境变量逐一核对通过；
> `gate` 别名与 `code_retain` 臂已实装（此前仅存在于文档）。

---

## 一、11 臂定义

### 机制层级图

```
Level 0: direct (C)     无门控、无验证、无调度学习
         ↓ +准入门控 (P∧U∧R∧G_code)
Level 1: gate_only      仅门控硬过滤
         ↓ +临时验证队列
Level 2: gate_prov      门控 + provisional（状态新颖候选入临时队列）
         ↓ +shadow 误拒测量
Level 3: gate (D)       完整准入系统（门控+provisional+shadow）
         ↓ +Thompson 后验调度
Level 4: calibrated (E) ★ 满效果 = 论文提出的完整系统
```

### 臂表

| 臂名 | 环境变量（run_ablation.sh 注入） | 一句话 |
|------|--------------------------------|--------|
| **direct** | `ADMISSION_MODE=direct` + `NO_ADMISSION=1` | 可解析候选直接入队（Arm C 基线） |
| **native** | `ADMISSION_MODE=native` | AFLNet 原生 save_if_interesting 决定去留（#4 公平对照） |
| **gate_only** | `ADMISSION_MODE=gate` `PROVISIONAL=0` `SHADOW=0` | 仅 P∧U∧R∧G_code 硬过滤 |
| **gate_prov** | `ADMISSION_MODE=gate` `PROVISIONAL=1` `SHADOW=0` | 门控 + provisional（无 shadow） |
| **gate** | `ADMISSION_MODE=gate` `PROVISIONAL=1` `SHADOW=1` | 完整准入系统（Arm D） |
| **calibrated** | `CALIBRATION=1` `STATE_SELECT=calibrated` | ★满效果（Arm E = 论文完整方法，Thompson 后验调度） |
| **cal_ewma** | `CALIBRATION=1` `STATE_SELECT=ewma` | 同 E，θ̃=EWMA（专家 Q3 核心对比） |
| **cal_run_rate** | `CALIBRATION=1` `STATE_SELECT=run_rate` | 同 E，θ̃=平滑经验报酬率（更简单基线） |
| **code_retain** | `ADMISSION_MODE=gate` `PROVISIONAL=1` `SHADOW=1` `CODE_RETAIN=1` | D + U 旁路：P∧R∧¬U 候选不被拒（#8） |
| **cal_gamma099** | `CALIBRATION=1` `CAL_GAMMA=0.99` | E 的 γ 敏感性 |
| **cal_gamma100** | `CALIBRATION=1` `CAL_GAMMA=1.0` | E 的 γ 敏感性 |

说明：
- E 系臂（calibrated/cal_ewma/cal_run_rate/cal_gamma\*）继承 D 的完整准入
  （gate+provisional+shadow 为默认值），仅 θ̃ 估计器/超参不同。
- `code_retain` 必须钉死 `PROVISIONAL=1`：EC_CODE_RETAIN 在
  PROVISIONAL=0 时会被降级为硬拒绝（afl-fuzz.c 的 arm gate 逻辑）。
- `gate` 与 `gate_prov_shadow` 是同一臂的两个名字；`full`/`gated_fixed`/
  `wo_calibration` 亦为历史别名，本指南统一只用 `gate`。

### ★ 满效果臂：`calibrated` (E)

```
calibrated = 准入门控 + provisional 验证 + shadow 测量 + Thompson 后验调度
```

### 对比逻辑：三条链，不是全部跟 E 比

**链 1：消融链（从满效果逐步去掉机制）**

```
calibrated (E)
  vs gate (D)     → 去掉 Thompson → 调度的贡献？（Q3）
  vs gate_prov    → 再去掉 shadow → shadow 的贡献？
  vs gate_only    → 再去掉 provisional → provisional 的贡献？（Q2）
  vs direct (C)   → 全部去掉 → 系统总贡献？（Q1）
```

**链 2：公平对照链（满效果 vs 替代方案）**

```
calibrated (E)
  vs native       → 比原生保留好多少？（#4 公平性）
  vs direct (C)   → 比不过滤好多少？
  vs cal_ewma     → Thompson 比 EWMA 好多少？（⭐ Q3 最关键）
  vs cal_run_rate → Thompson 比 running average 好多少？
```

**链 3：敏感性/特殊通道**

```
calibrated (E) vs cal_gamma099/100 → γ 遗忘率敏感性
gate (D)       vs code_retain      → 加 U 旁路，被拒的有价值候选损失多少？（#8）
```

### 每个对比回答哪个问题

| 对比 | 回答的问题 |
|------|-----------|
| gate vs direct | Q1：门控省了多少执行？ |
| gate vs native | Q1：比原生保留好多少？ |
| gate vs gate_only | Q2：provisional 贡献了什么？ |
| calibrated vs gate | Q3：调度学习有没有用？ |
| **calibrated vs cal_ewma** | **Q3：Thompson 比 EWMA 好多少？（⭐最关键）** |
| gate 内部账本 | Q2：provisional 候选 vs 普通候选的 Productivity@64 |
| gate 的 admission-events | 发现1：G_state 与 G_code 不可互换 |
| gate vs gate_only + code_retain | 发现2：证据分离有价值 |
| gate 的 execution-events | 发现3：验证/工作量/调度三方权衡 |

### 精简建议：6 臂最小集

| 精简掉的臂 | 原因 |
|-----------|------|
| gate_prov | shadow 只做测量不改变准入行为；gate_only vs gate 已分离 provisional 贡献 |
| cal_run_rate | cal_ewma 已是足够简单的基线 |
| cal_gamma099/100 | 参数分析，机制有效性确认后再跑 |
| code_retain | 视 gate 的 shadow 误拒数据决定 |

```
最小集：direct, native, gate_only, gate, calibrated, cal_ewma   （6 个）
```

---

## 二、运行命令

### 命令格式（2026-10-24 实装，两种顺序等价）

```bash
# 新格式：<runs> <minutes> <target> custom <arms>
./run_ablation.sh 1 1540 lightftp custom direct,gate,calibrated

# 旧顺序：<target> <runs> <minutes> --groups <arms>  （--groups 与 -g 等价）
./run_ablation.sh lightftp 1 1540 --groups direct,gate,calibrated
```

### 全量实验（11 臂，真实网关）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && \
export KEY="sk-你的密钥" && \
export SKIPCOUNT=100 && \
export CHATAFL_MAX_TOKENS=4096 && \
export CHATAFL_LLM_TIMEOUT_MS=300000 && \
export ABLATION_SHUFFLE=1 && \
./run_ablation.sh 1 1540 proftpd custom \
  direct,native,gate_only,gate_prov,gate,calibrated,cal_ewma,cal_run_rate,code_retain,cal_gamma099,cal_gamma100
```

### 最小实验（6 臂，回答全部三个关键问题）

```bash
ABLATION_SHUFFLE=1 ./run_ablation.sh 1 1540 lightftp custom \
  direct,native,gate_only,gate,calibrated,cal_ewma
```

### Mock 网关运行（机制验证/无真实网关时）

```bash
# 宿主机启动 mock（另一个终端）
python3 loopfuzz/llm_mock_v5.py   # 监听 0.0.0.0:8099

# 容器经 docker0 网关访问（注意：必须是 172.17.0.1，不能写 127.0.0.1）
export KEY=mock-key
export CHATAFL_LLM_BASE=http://172.17.0.1:8099/v1/chat/completions
./run_ablation.sh 1 120 lightftp custom direct,gate,calibrated
```

### 参数说明

| 参数 | 含义 | 默认值 |
|------|------|--------|
| `TARGET` | 目标协议实现（9 个：lightftp/bftpd/exim/live555/kamailio/lighttpd1/forked-daapd/proftpd/pure-ftpd） | `live555` |
| `RUNS` | 每组重复次数（论文用途建议 ≥3） | `5` |
| `TIMEOUT_MIN` | 每组运行分钟数 | `1470` |
| `custom <臂列表>` | 指定臂（逗号分隔，覆盖预设备） | — |
| `--groups/-g` | 同上，标志写法 | — |
| `ABLATION_SHUFFLE=1` | 随机化臂运行顺序（消除组序/时间混杂） | 关 |
| `ABLATION_PARALLEL` | 同时运行的臂数（默认 6；=1 串行最稳） | `6` |

---

## 三、每臂环境变量与数据流

### 环境变量一览（仅 11 臂涉及的）

| 变量 | 作用 |
|------|------|
| `CHATAFL_ADMISSION_MODE` | `native` / `direct` / `gate` 三选一（非法值直接 FATAL） |
| `CHATAFL_PROVISIONAL` | 0/1，两级暂存队列开关（code_retain 臂必须为 1） |
| `CHATAFL_SHADOW` | 0/1，拒绝候选影子验证测量开关 |
| `CHATAFL_CODE_RETAIN` | 0/1，P∧R∧¬U 保留通道（EC_CODE_RETAIN 否则降级为 reject） |
| `CHATAFL_CALIBRATION` | 0/1，在线状态效用调度总开关 |
| `CHATAFL_STATE_SELECT` | `calibrated`(Thompson) / `ewma` / `run_rate` |
| `CHATAFL_CAL_GAMMA` | 校准 γ（默认 0.995；敏感性臂用 0.99/1.0） |
| `CHATAFL_PROVISIONAL_BUDGET/TTL_MS/MAX_LIVE` | 暂存预算（默认 64 次变异 / 600000 ms / 64 存活） |
| `CHATAFL_LLM_BASE` | LLM 端点覆盖（mock 用；不设走真实网关默认值） |
| `KEY` | LLM API key（未设则全部 LLM 功能禁用并告警） |
| `SKIPCOUNT` | 覆盖率采样间隔（legacy cov_script 目标影响 gcovr 频率；coverage_v4 目标只影响 CSV 行密度） |
| `CHATAFL_MAX_TOKENS` / `CHATAFL_LLM_TIMEOUT_MS` | LLM 采样上限 / 超时 |
| `CHATAFL_EVENT_LOG=0` | 关闭全部 JSONL 事件日志（默认开） |
| `CHATAFL_ADMISSION_LOG=0` | 仅关闭 admission 决策日志（默认开） |

### 数据流

```
run_ablation.sh (按臂注入 CHATAFL_*)
  → run_dev.sh (透传)
    → profuzzbench_exec_common_dev.sh (ABLATION_FLAGS 构建 -e 注入)
      → docker run -e CHATAFL_*=...
        → /proc/1/environ (容器内，monitor.sh 读这里判定臂)
          → afl-fuzz.c getenv()
```

### 验证臂生效

```bash
docker logs <容器ID> 2>&1 | grep -E "ADMISSION FACTORS|ADMISSION MODE"
# 期望: mode=direct|native|gate provisional=0|1 shadow=0|1
docker exec <容器ID> grep -o '"admission_mode[^,]*' \
  <outdir>/run-config.jsonl   # 持久化的最终配置
```

---

## 四、结果读取

### 结果目录

```text
benchmark/results-<target>_<timestamp含臂标签>/out-<target>-loopfuzz_1.tar.gz
```

### 每臂关键遥测文件（out 目录内）

| 文件 | 内容 | 主要服务于 |
|------|------|-----------|
| `fuzzer_stats` | execs/paths/crashes/LLM 计数 | Q1 执行预算 |
| `cov_over_time.csv.v4/terminal.json` | 分支 ID 并集 + 回放数 | 覆盖终值（唯一可信源） |
| `admission-events.jsonl` | 每候选 P/U/R/G 裁决（`intended_disposition`） | Q1/Q2 |
| `provisional-events.jsonl` | admit/convert/expire 生命周期 | Q2 |
| `scheduler-selections.jsonl` | 每次状态选择的 θ̃ 依据 | Q3 |
| `llm-calls.jsonl` | 每次调用状态（`status:"ok"` 计健康度） | 全部（数据有效性校验） |
| `execution-events.jsonl` | 逐执行 workload 账本 | 发现3 |

### 推荐指标与归一化

- 覆盖：`terminal.json` 的 `covered_branch_ids` 数（分支 ID 并集，勿用摘要文本）
- 资源：`execs_done`；Q1 节省率 = 1 − execs(gate 系)/execs(direct)
- 显著性：每目标 n 重复 Mann-Whitney U 双侧（α=0.05）
- **必须做 per-1000-execs 归一化**（paths/1K、edges/1K）消除 Docker CPU 争抢
  带来的 3× 吞吐差异
- **每个 campaign 校验 llm_ok**（`status:"ok"` 占比），transport-error 占
  100% 的行是无效数据（历史教训：端点写错导致整波作废）

### 判定语言

| 结论 | 条件 |
|------|------|
| **Supported** | 多数目标上优于对照臂，且无系统性成本膨胀 |
| **Mixed** | 部分目标提升部分下降，或成本明显变差 |
| **Not supported** | 未能在多数目标上优于对照臂 |

---

## 五、监控

```bash
./monitor.sh          # 实时全部
./monitor.sh bftpd    # 单协议
./monitor.sh -1       # 单次采集
```

`monitor.sh` 读容器 `/proc/1/environ` 的 `CHATAFL_ADMISSION_MODE/PROVISIONAL/
SHADOW/STATE_SELECT/CODE_RETAIN` 组合判定 11 臂标签，与本文档臂名一致。

---

## 六、污染防控

每个臂在 `run_ablation.sh` 的**独立子 shell** 中运行：先 unset 全部
`CHATAFL_*` 再按臂注入，子 shell 退出后变量不回写父 shell，臂间零污染。

手动跑单臂时（不走 run_ablation.sh）：

```bash
unset $(env | grep -o '^CHATAFL_[A-Z_]*' | tr '\n' ' ')   # 先清空
export CHATAFL_ADMISSION_MODE=gate CHATAFL_PROVISIONAL=1 CHATAFL_SHADOW=1   # 再注入
./run_dev.sh 1 120 lightftp loopfuzz
env | grep '^CHATAFL_' || echo "环境已干净"   # 跑完确认
```

---

## 七、已知限制与设计注意

1. **provisional 剂量结构性偏窄**：P∧U∧R∧¬G_code∧G_state 谓词决定了
   2h 窗口内准入通常只有 0~3 次；这是准入条件本身，不是机制故障。
2. **跨波次比较的混淆风险**：若用共享 mock 网关分波跑臂
   （先 direct/gate_only/native，后 gate/calibrated/cal_ewma），mock 的
   全局状态（请求序号阶段、per-protocol 记忆）会让不同波拿到系统性
   不同的 LLM 输出。**对策**：`ABLATION_SHUFFLE=1` 交错臂序，或每
   campaign 独立 mock 实例；跨波差分必须标注存疑。
3. **code_retain 与 D 的差异只有一个因子**（CODE_RETAIN），但 EC_CODE_RETAIN
   通道的触发依赖 P∧R∧¬U 候选出现频率，剂量同样偏窄。
4. fork 隔离、bounded execution、dedup ring 等始终开启，无对应开关；
   结论表述应为"当前 shipped 行为下某机制的净效应"。
5. 收集层（宿主 TAR 收集/恢复）与网关无关：真实网关与 mock 同样受
   flock 竞争影响。多臂并行时保持 `CHATAFL_CLEAN_CONTAINERS=0` 保留
   容器，收集用串行恢复 + 只认最终 `*.tar.gz`（勿用 `tar.gz*` 通配）。
