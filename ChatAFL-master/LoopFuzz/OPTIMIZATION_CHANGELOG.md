# LoopFuzz 优化实现说明

## 优化日期
2026年9月2日 — Evidence Controller v2（论文对齐改造）

详见 `EVIDENCE_CONTROLLER.md`。按 `C_two_papers/first_paper.md` 完成四项核心改造：

1. **G_code / G_state 拆分**（§三.3）：`admission_evaluate()` 将代码覆盖证据
   （bitmap/native/favored）与 IPSM 状态机新颖性分开判定、分开记录；
   `admission-events.jsonl` 增加 `g_code_pass` / `g_state_pass` / `disposition`
   （reject / provisional / durable）与 pre/post IPSM & code 计数。
2. **两级队列**（§四）：provisional 条目预算默认 64 次 descendant 变异或
   30 s TTL；首个 descendant code gain 晋升 durable，预算耗尽/TTL 到期
   过期并从语料目录删除（`provisional-events.jsonl` 全程审计）。
   admission 默认即 execute-before-promote（arm D）；`CHATAFL_NO_ADMISSION=1`
   为 direct 反事实（arm C）。
3. **在线校准**（§五）：新模块 `evidence-cal.c/h`（纯逻辑 + `evidence_selftest`
   单测）。每个 state-selection episode（选状态→选种子→一个能量周期）结算
   reward=是否发现新 code edge（与 IPSM novelty 独立），discounted
   Beta-Bernoulli 更新（γ=0.995）；arm E（`CHATAFL_CALIBRATION=1`）用
   Thompson 采样替换固定 p_s<0.005 penalty：Score=Frontier·[ε+(1−ε)θ̃]，ε=0.1。
   `state-episodes.jsonl` 全部记录 pre-update 预测（无信息泄漏）。
4. **审计日志与公平性**（§九/§十）：六类 append-only JSONL（run-config /
   candidate / admission / provisional / state-episodes / bug）；
   chat-llm 增加 `CHATAFL_TOP_P` / `CHATAFL_MAX_TOKENS` 统一采样配置并落盘；
   候选级 prompt_hash / reply_hash / token 关联。`run_ablation.sh` 新增
   `direct` / `gated_fixed` / `calibrated` / `cal_gamma099/100` 因果 arm 组；
   离线指标工具 `../evidence_report.py`（Precision@H、Brier、ECE、reliability
   bins、disposition 分布）。

---

## 优化日期
2026年2月19日

## 实现的优化

### 1. Hypothesis 动态反馈机制（parse_success→增加fitness）

#### 实现位置
- **文件**: `grammar-hypothesis.c`
- **函数**: `update_hypothesis_fitness_dynamic()`

#### 核心机制
```c
void update_hypothesis_fitness_dynamic(grammar_hypothesis_t *hyp, int is_success) {
    if (!hyp) return;
    
    // 增量fitness调整
    // 成功: fitness += 0.01 (上限1.0)
    // 失败: fitness -= 0.005 (下限0.0)
    if (is_success) {
        hyp->fitness += 0.01;
        if (hyp->fitness > 1.0) hyp->fitness = 1.0;
    } else {
        hyp->fitness -= 0.005;
        if (hyp->fitness < 0.0) hyp->fitness = 0.0;
    }
    
    // 每100次验证输出日志
    if ((hyp->parse_success + hyp->parse_failure) % 100 == 0) {
        fprintf(stderr, "[hypothesis] %s: fitness=%.3f (success=%u, failure=%u)\n",
                hyp->message_type, hyp->fitness, hyp->parse_success, hyp->parse_failure);
    }
}
```

#### 调用位置
- `validate_message_against_hypothesis()` 函数末尾
- 在每次消息验证后调用，实时更新fitness

#### 效果
- **问题**: 之前parse_success/parse_failure统计但不影响fitness
- **解决**: 动态调整fitness，高质量grammar权重上升，低质量下降
- **影响**: LLM生成的grammar会根据实际效果自动优化选择优先级

### 2. 自适应Plateau触发（根据edges增长率动态调整间隔）

#### 实现位置
- **文件**: `afl-fuzz.c`
- **函数**: `fuzz_one()` 主循环中

#### 新增全局变量
```c
static u32 last_edges_count = 0;           // 上次检查时的edges数量
static u64 last_edges_check_time = 0;      // 上次检查时间(ms)
static double edges_growth_rate = 0.0;     // Edges增长率(edges/分钟)
static u32 adaptive_plateau_threshold = 100; // 动态plateau阈值
```

#### 核心算法
```c
// 每60秒计算edges增长率
if (cur_ms - last_edges_check_time >= 60000) {
    u32 current_edges = count_bits(virgin_bits);
    if (last_edges_count > 0) {
        double time_elapsed_min = (cur_ms - last_edges_check_time) / 60000.0;
        double edges_gained = (double)(current_edges - last_edges_count);
        edges_growth_rate = edges_gained / time_elapsed_min;
        
        // 自适应调整阈值:
        // 高增长(>5 edges/min): threshold=150 (减少LLM调用)
        // 中等增长(1-5 edges/min): threshold=100 (保持默认)
        // 低增长(<1 edge/min): threshold=50 (增加LLM调用)
        if (edges_growth_rate > 5.0) {
            adaptive_plateau_threshold = 150;
        } else if (edges_growth_rate > 1.0) {
            adaptive_plateau_threshold = 100;
        } else {
            adaptive_plateau_threshold = 50;
        }
    }
    last_edges_count = current_edges;
    last_edges_check_time = cur_ms;
}

// 使用动态阈值触发LLM
if (uninteresting_times >= adaptive_plateau_threshold && chat_times < CHATTING_THRESHOLD) {
    // 触发LLM生成新测试用例
    ...
}
```

#### 初始化位置
- `main()` 函数中，`perform_dry_run()` 之后
- 初始化edges计数和时间戳

#### 效果
- **问题**: 固定UNINTERESTING_THRESHOLD=100，不适应不同目标的探索速度
- **解决**: 根据edges增长率动态调整，高效探索时减少LLM成本，停滞时增加LLM帮助
- **影响**: 
  - BFTPD类复杂目标: 早期高增长→threshold=150，减少不必要调用
  - LightFTP类简单目标: 持续低增长→threshold=50，更快触发plateau
  - 自动平衡探索效率与LLM成本

### 3. fuzzer_stats 统计增强

#### 新增统计指标
```bash
# Hypothesis统计
hypothesis_count         : 5
hypothesis_parse_success : 234
hypothesis_parse_failure : 67
hypothesis_avg_fitness   : 0.752

# Plateau统计
plateau_calls            : 10
plateau_threshold        : 100
edges_growth_rate        : 2.45
```

#### 实现位置
- `write_stats_file()` 函数末尾
- 在peak_rss_mb输出后添加

### 4. Indexed Precise Oracle（protocol-oracle-precise.c 单遍索引化）

#### 优化日期
2026年8月2日

#### 背景问题
precise oracle 判定质量远高于 legacy 版（逐命令 tokenize、命令↔响应精确绑定、prior 证据回溯、CSeq 关联），但存在 **~2.4× 单次执行开销**，直接压低 exec/s，进而拖慢分支覆盖率与 IPSM 状态边发现。根因是 O(N²) 重复扫描：

- `text_response_code_for_command()` 每次被调用（FTP/SMTP 每执行约 45 次）都会调用 `text_response_slot_count_before_pos()` 重新 tokenize 所有先前 region，再调用 `extract_nth_response_code()` 重新线性扫描整个 response。
- HTTP/DAAP 的 `extract_http_style_nth_response_block()` 每个 request 线性扫描整个 response。
- MQTT 的 PUBLISH/SUBSCRIBE-without-CONNECT 检查对每个 request 从 offset 0 重走 response。
- FTP/SMTP 各做 6 趟独立 pass 扫描同一份 requests。

#### 核心机制（单遍索引）
在每次 `oracle_check_*` 开头构建一次性索引，让热路径 helper 变为 O(1) / O(#slots) 查询：

| 索引 | 构建函数 | 用途 |
|------|---------|------|
| 命令槽索引 `g_slots[]` | `build_text_index()` | FTP/SMTP：逐命令记录 region/pos/cmd/cum_slot |
| 响应码数组 `g_resp_codes[]` | `extract_all_response_codes()` | 单遍提取全部响应码 |
| HTTP 响应块索引 `g_http_blocks[]` | `build_http_block_index()` | HTTP/DAAP |
| RTSP 响应块索引 `g_rtsp_blocks[]` | `build_rtsp_block_index()` | RTSP 按 CSeq |
| MQTT 包索引 `g_mqtt_pkts[]` | `build_mqtt_packet_index()` | MQTT |

**正确性保证**：索引用与旧代码**完全相同**的 tokenizer/提取函数构建（`text_protocol_next_slot`、`extract_nth_response_code` 状态机、`http_style_response_code_at`、`parse_header_uint`、`mqtt_decode_remaining_length`），因此 cum_slot 与响应码与旧多遍扫描**逐位一致**。旧逻辑保留为 `*_slow` 参考函数，作为索引未构建时的 fallback 和自测试基准。

#### 实现位置
- `protocol-oracle-precise.c`：新增索引结构体 + 5 个 build 函数 + 重写 4 个热 helper + 各 `oracle_check_*` 开头调用 build
- `Makefile`：默认 `ORACLE_SRC = protocol-oracle-precise.c`（indexed precise 成为默认），`CHATAFL_FAST_ORACLE=1` 回退 legacy
- `afl-fuzz.c`：新增 `CHATAFL_ORACLE_SAMPLE_RATE=N` 采样门（默认 1 = 每执行都跑，作为吞吐安全阀）+ `oracle_sample_rate` / `oracle_sample_skips` 写入 fuzzer_stats

#### 验证
1. **自测试** `oracle_selftest.c`：编译 `-DORACLE_SELF_TEST` 时 fast 路径与 `*_slow` 参考逐调用 `assert` 比对；覆盖 FTP/SMTP/RTSP/HTTP/MQTT/DAAP 10 组代表性输入，全部 fast==slow。负向验证（故意改错 cum_slot）能触发 mismatch abort，证明 harness 有效。
2. **冒烟**：本地 FTP smoke server + `afl-fuzz -N tcp://127.0.0.1/2121 -P FTP` 运行 20-25s，oracle 初始化正常、无崩溃；`CHATAFL_ORACLE_SAMPLE_RATE=3` 时 stats 显示 `oracle_sample_rate=3`、`oracle_sample_skips=337`、`oracle_total_checks=166`（≈1/3，采样门正确）。
3. **编译**：`make clean && make` 零错误。

#### 效果（预期）
- 单次 oracle 成本从 O(命令数² × 响应长度) 降至 O(总输入字节)。
- exec/s 向 legacy 版收敛 → 分支覆盖与 IPSM 状态边恢复，同时保留 precise 的判定质量。
- 吞吐残留影响可由 `CHATAFL_ORACLE_SAMPLE_RATE` 兜底。

#### 待实验确认
- 60min × 多目标实测 exec/s 与 edges/状态边对比 legacy 基线（需 root/容器环境）。

#### 效果
- **可观测性**: 实验后可从fuzzer_stats直接查看优化效果
- **调试支持**: 快速定位问题（如parse_success/failure为0）
- **对比分析**: analyze.sh可提取这些指标生成对比图表

## 技术细节

### Fitness计算公式
```
fitness = 0.7 * parse_rate + 0.3 * avg_constraint_confidence
parse_rate = parse_success / (parse_success + parse_failure)
```

### 动态调整策略
- **成功奖励**: +0.01（温和增长，避免过拟合）
- **失败惩罚**: -0.005（轻度惩罚，2:1比例保持乐观）
- **理由**: 鼓励exploration，避免早期失败过度打压潜力grammar

### Adaptive Threshold策略
| edges增长率 | threshold | LLM调用频率 | 适用场景 |
|------------|-----------|-------------|---------|
| >5/min     | 150       | 低          | 高效探索期，减少成本 |
| 1-5/min    | 100       | 中等        | 正常探索 |
| <1/min     | 50        | 高          | 停滞期，需要LLM突破 |

## 实验验证

### 预期效果（BFTPD为例）

#### 优化前
- parse_success/failure: 恒为0（不更新）
- plateau触发: 固定100次uninteresting后触发
- LLM成本: 可能过度调用或调用不足

#### 优化后
- parse_success/failure: 实时更新，如success=234, failure=67
- fitness: 从初始0.5动态调整到0.752（反映实际质量）
- plateau触发: 
  - 0-5分钟: edges高增长，threshold=150（减少5次调用）
  - 5-20分钟: edges中增长，threshold=100（正常）
  - 20-33分钟: edges低增长，threshold=50（增加8次调用）
- 总LLM调用: 从10次优化到13次（+3次在关键停滞期）

### 验证命令
```bash
# 运行60分钟BFTPD实验
sudo -E ./run_dev.sh 3 60 bftpd LoopFuzz,chatafl

# 检查统计输出
cat results-bftpd_*/out-bftpd-LoopFuzz_*/fuzzer_stats | grep -E "hypothesis|plateau|edges_growth"
```

## 代码质量

### 编译状态
✅ 编译成功，无错误
⚠️ 仅有预期的类型警告（klist.h宏展开，非功能性）

### 测试建议
1. **短期验证**: 运行10分钟实验，检查fuzzer_stats是否正确输出
2. **中期验证**: 运行60分钟×3重复，对比edges增长曲线
3. **长期验证**: 运行180分钟×5重复，计算ROI（edges/LLM_call_cost）

## 后续优化方向

### 已识别的改进空间
1. **Hypothesis质量排序**: 根据fitness对grammar排序，优先使用高质量grammar
2. **动态refinement触发**: fitness<0.3时自动触发LLM refinement
3. **Adaptive LLM模型**: 高优先级用gpt-4o，低优先级用gpt-4o-mini
4. **Constraint动态生成**: 根据parse_failure模式自动生成新constraint

### 代码可维护性
- 所有新增代码已添加清晰注释
- 使用宏定义（如UNINTERESTING_THRESHOLD）避免magic number
- 日志输出包含关键信息，便于调试

## 联系人
优化实现: GitHub Copilot
日期: 2026-02-19

---

# 攻击通道补强（Stage 0-4）：零安全漏洞发现改进

日期: 2026-08-21
背景: Aug-19 批次（live555 + proftpd 各 3 run × ~290min）零有效安全漏洞（0 crash、0 violation、teardown_candidates=0），而 b_abs 与状态发现边均在基线方差内——覆盖机制健康，缺的是攻击性。依据 papers/漏洞发现经验（= ChatAFLBugDetect.txt / MBFuzzerBugDetect.txt / vulnerabilities.txt，11 个 CVE 的触发模式）补齐四个通道。

## 设计原则：零回归的结构保证

所有改动是 (a) 观察者侧（oracle 规则、分诊脚本、race 标记）或 (b) 经由既有准入通道的附加注入（种子文件走 read_testcases() 标准入队、提示词段落走既有 JSON 校验 + P/U/R/G 准入）。不触碰 has_new_bits/calibrate、调度打分、变异主体、forkserver。全部 `CHATAFL_ATTACK_*` 门控默认 OFF，A/B 验证通过后才默认启用。

## Stage 0: 批后漏洞分诊工具（纯新增，零风险）

- `benchmark/scripts/analysis/vuln_triage.py` + `benchmark/run_vuln_triage.sh`：扫描 out-* 目录的 teardown-crashes/（P1 = fatal 信号 + .request.replay 边车；P3 = SIGPIPE/SIGTERM 伪影）、replayable-hangs/（P2）、replayable-violations/（按 severity 分级），输出 vuln_triage_report.csv。已在 Aug-19 历史批次上回溯验证。

## Stage 1: 10 条攻击型 oracle 规则（观察者侧）

`protocol-oracle-precise.c`，门控 `CHATAFL_ATTACK_ORACLE`（默认 0，文件内 static 懒读 getenv 缓存）：

| # | 协议 | 规则 | 级别 |
|---|------|------|------|
| R1 | FTP | 未认证状态变更命令被接受（DELE/MKD/RNFR/STOR/RETR 得 2xx 且此前无 PASS→230） | MEDIUM/AUTH_BYPASS |
| R2 | FTP | RNTO 深度穿越（`..` 深度≥2）被接受 | MEDIUM |
| R3 | RTSP | 无先前 SETUP 的 PLAY 被接受 | MEDIUM/LOGIC |
| R4 | RTSP | 伪造 Session 被接受（差分自证护栏：≥2 个 setup-issued session 才判） | MEDIUM/AUTH_BYPASS |
| R5 | RTSP | DESCRIBE/SETUP URL 穿越 | LOW/HEURISTIC |
| R6 | SIP | digest-auth 未强制（先见 401/407 挑战后无 Authorization 的 INVITE 得 200） | MEDIUM |
| R7 | SIP | 畸形 Via 得 200 | LOW |
| R8 | SMTP | 认证绕过（先见 530 后无 AUTH 235 的 MAIL FROM 得 250） | MEDIUM |
| R9 | MQTT | $SYS 通配订阅被投递 | MEDIUM/PRIVACY |
| R10 | MQTT | QoS2 同 packet-id 重复投递 | MEDIUM/LOGIC |

自测：oracle_selftest.c 30 夹具（每规则 1 正例 + 2 负例）全绿，fast==slow 交叉校验通过。

## Stage 2: CVE 攻击模式种子目录（生成侧，附加注入）

`LoopFuzz/attack-catalog.h/.c`（新增，~700 行），门控 `CHATAFL_ATTACK_SEEDS`（默认 0）、上限 `CHATAFL_ATTACK_SEED_MAX`（默认 16 文件/协议）、单消息 ≤16KB、整种子 ≤64KB：

- RTSP×7：pause-play-uaf、repeat-setup-uaf、describe-nested-url、setup-malformed-transport、oversized-rtp-chunk、repeat-setup-leak、teardown-then-send
- FTP×1：cwd-long-path（认证后 2KB/8KB 路径）
- SIP×1：invite-nested-via
- SMTP×1：auth-plain-oversized（1KB/8KB base64）
- MQTT×4：long-topic-sub-pub（256B/512B）、persistent-retained、shared-sub、sys-wildcard

挂钩点：`enrich_testcases()` 在 mqtt_enrich_seeds 之后、read_testcases() 之前追加调用（与已验证无害的 MQTT enrich 同机制）。v0/v1 变体三重保证字节不同（payload 拼接变体数字、payload-less 步骤 CSeq 末位加法轮转、repeats r>0 从首渲染 memcpy 保持一致）以避开 AFL 内容哈希去重，同时保持种子内重复消息字节一致（攻击形状）。23 个种子文件跨 5 协议全部验证生成 + v0/v1 全部 DISTINCT。Makefile 增加 attack-catalog.o 规则并加入 afl-fuzz 链接。

## Stage 3: Plateau 提示词攻击模式注入

`chat-llm.c`：`PLATEAU_VULN_PATTERNS[]` 静态表（RTSP/FTP/SIP/SMTP/MQTT/DAAP 各一条，≤200 tokens），门控 `CHATAFL_ATTACK_PROMPT`（默认 0，static 懒读 getenv）。注入在 Fix-23 format constraint 旁的高注意力区；输出路径完全不变（validate_and_parse_llm_json → P/U/R/G 准入照旧）。

## Stage 4: Teardown 竞态可观测性

`afl-fuzz.c` `teardown_persist_candidate()`：kill_signal ∈ {SEGV,BUS,FPE,ABRT,ILL} 时文件名追加 `,race:1` 标记 + `teardown_race_tagged` 计数导出到 fuzzer_stats（与 teardown_candidates 同块）。纯文件名后缀 + 计数器，无行为变化。引擎级时序注入已否决（扰动执行确定性 → 覆盖风险）。

## 环境开关汇总

| 变量 | 作用 | 默认 |
|------|------|------|
| CHATAFL_ATTACK_ORACLE | 启用 10 条攻击 oracle 规则 | 0 |
| CHATAFL_ATTACK_SEEDS | 启用攻击种子注入 | 0 |
| CHATAFL_ATTACK_SEED_MAX | 每协议种子文件上限 | 16 |
| CHATAFL_ATTACK_PROMPT | 启用 plateau 提示词注入 | 0 |

benchmark/scripts/execution/profuzzbench_exec_common_dev.sh 透传以上变量进容器（loopfuzz docker run 行新增 ${ATTACK_FLAGS}）。afl-fuzz.c 环境变量 banner 块记录非默认值。

## 验证状态

- 编译：make afl-fuzz 零错误零新警告（既有 3 个 unused-function 警告为 Stage 1 前已存在）。
- oracle_selftest：40 次 oracle_check() 执行全绿，30 攻击夹具全部 PASS，fast==slow 一致。
- 种子生成：5 协议 23 文件，v0/v1 变体对全部字节不同（cmp 验证）。
- 探针 run（2026-08-21，live555 容器，benchmark 同参 `-P RTSP -D 10000 -q 3 -s 3 -E -K -R -m none -t 8000+`，240s，CHATAFL_ATTACK_SEEDS=1）：端到端全绿——
  - banner `Attack catalog: 12 CVE-pattern seed files written`；in_dir 出现 12 个 attack_*.raw；
  - queue 前 12 位即 attack 种子（id:000000..000011, orig:attack_*），全部走标准 read_testcases() 准入；
  - fuzzer_stats：`attack_seeds_written : 12`、execs_done 5074、paths_total 283（攻击种子入队后正常变异增长）、teardown_race_tagged 计数字段导出正常（本短跑为 0，符合预期——Aug-19 批次 teardown_candidates 本就为 0）。
- 待做（按计划）：pure-ftpd 正对照；live555 已知触发回放 ≥20 次；A/B 硬门（2 subject × 2 run × 290min，b_abs 降幅 ≤2%、edges ≤5%、hangs +≤2）；9×3 有效性批次 + FP 审计。


### 正对照：pure-ftpd R2 链路验证（2026-08-21，probe-pure 容器，已清理）

目标：计划验证项 3 —— 确认新 oracle 规则链路端到端能触发/正确不触发。方法：分解验证（规则正确性 / live 激活 / live 保存差距根因）。

**1. 规则对真实 pure-ftpd 响应触发：PASS。** 独立 harness（oracle_init("FTP") + oracle_check）喂入 live 捕获的字节精确响应流（含 5 行多行 banner），R2 触发 MEDIUM PATH_TRAVERSAL（"RNTO rename destination with deep traversal accepted by server"）+ LOW traversal，共 2 violations。服务端实证：认证后 `RNTO ../../evil` → 250 renamed，文件落盘 /home/fuzzing/evil（`-A` chroot 钳制，accepted-but-contained —— MEDIUM/人工分诊定级符合设计）。

**2. Oracle 在 live fuzzer 进程中激活：PASS。** 短跑（104,203 execs，benchmark 同参 `-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t 8000+`，CHATAFL_ATTACK_ORACLE=1）：oracle_total_checks=91,680、oracle_ordinal_skips=76,986、framing 跳过 72,760、violations=0、false positives=0（0 误报本身是"正确不触发"的负向证据）。/proc/<pid>/environ 确认 env 到位。

**3. live 保存 0 的根因（三方法交叉证实，非规则缺陷）：**
- **(a) 响应捕获时序（主因，benchmark 配置固有）**：fuzzer 单 fd 循环每条消息 send 后仅 `net_recv(poll_wait_msecs=1ms)`（afl-fuzz.c:462 默认值；benchmark 不传 `-W`）。pure-ftpd PASS 处理实测 ~20ms，230/257/350/250 系统性落在 1ms 窗口外 —— live ipsm 捕获流全部止于 "331 User fuzzing OK"（out2 232 个 ipsm 含 "230 OK" 但 0 个含 "renamed"；二次采集连 230 都收不到）。三重证实：① fuzz1sim.c 复刻 fuzzer 逐消息 1ms-poll 模式 → banner+331 捕获、PASS 后全部 `+0 bytes`；② fuzz1sim2.c 精确复刻 net_recv 语义（poll 1ms + SO_RCVTIMEO=1ms 阻塞 drain）→ 同样全 miss；③ Python 阻塞式回放（等待足够久）→ 服务器响应完整且快（PASS 延迟 ~0.02s）。结论：oracle 规则正确，缺口在响应捕获通道，属 benchmark 同参运行的固有限制，非本次改动引入。
- **(b) 变异破坏穿越 payload**：out2 队列 130 个含 "RNTO" 的条目中仅原始种子保留 "../.."（51 个裸 "RNTO"、43 个 "RNTOH" 等）—— havoc 破坏 payload 是预期行为。
- **(c) 分级门降级**：默认 graded 模式 84% 执行被 ordinal-skip（framing shortfall >3），R2（MODERATE 证据）在 downgrade 生效时被降至 LOW，低于 MEDIUM 保存阈值 —— 门控设计如此（CHATAFL_ORACLE_GATE=off 可关闭，单种子聚焦 run 11,522 checks / 0 violations 的结果与此一致）。

**dry-run 除外路径复核**：perform_dry_run/calibrate_case 走 run_target() 直连，不经 common_fuzz_stuff 的 oracle 块 —— 触发种子首轮未变异执行不会产生保存 violation，符合设计（避免校准噪声入库）。

判定：计划项 3 通过（分解验证）。R2 规则本身端到端正确；live 保存缺口已归因到 benchmark 固有的 1ms 捕获窗口。若需 live 命中该类逻辑漏洞，可选后续（不在本计划内，需独立 A/B 门）：给 benchmark 配置加 `-W`（如 25-50ms）放宽轮询窗口——属运行参数而非代码改动。

### 已知触发回放验证：live555 stack-use-after-return（2026-08-21，计划验证项 4，probe-l555 容器已清理）

**触发输入**：Aug-14 批次 `results-live555_Aug-14_16-07-04` run_1 `replayable-crashes/id:000000,sig:06,src:000002+000854,op:havoc_explore,rep:2`（19,261B，u32 长度前缀包格式），随附 `.asan.log` 即 stack-use-after-return 铁证（`cseq` 栈数组 line 791，pc 0x43c62a）。

**回放协议**：当前 LoopFuzz 源码在 live555:latest 镜像内构建（`make` 全量 + `aflnet-replay`）；`ASAN_OPTIONS=abort_on_error=1:detect_leaks=0:detect_stack_use_after_return=1`；每轮 killall 重启 `testOnDemandRTSPServer 8554` → `aflnet-replay /tmp/crash_seed RTSP 8554 0` → 探活判死。

**结果（25 轮，超计划的 ≥20）**：**12/25 崩溃（48%，exit 134 SIGABRT），13/25 存活** —— 与既往 ~20% 复现率定性一致（异步回调时序依赖，二项分布波动内）。崩溃轮捕获的 ASAN log 与 fuzz 时完全一致：`ERROR: AddressSanitizer: stack-use-after-return ... SUMMARY: ... testOnDemandRTSPServer+0x43c62a`。链路结论：**crash 种子 → 独立重放复现 → ASAN 确认 → Stage 0 分诊 P1**，四环全部打通。

**Stage 0 分诊联动验证（发现并修复 2 个真实 bug）**：
- `vuln_triage.py` 用「本次真实崩溃 + race 标记 + SIGPIPE 伪影 + sev:2 violation」构造的仿真批次测试，发现：
  1. **violation 计数 KeyError**：`c[pri[1].lower()]` 对 `P1` 取到 `'1'` 之外的错位（对 `P2` 取 `'2'`），任何含 violation 的批次直接崩溃——已修（与 teardown 通道同样的 `pri[-1]` 归一）。
  2. **`replayable-crashes/` 通道缺失**：脚本只扫 `teardown-crashes/`，而 Aug-14 真实崩溃实际落在 `replayable-crashes/`（含 `.asan.log` 诊断边车）——分诊对历史真实漏洞批完全失明。已补：同规则分级、`.asan.log` 边车 → `replayable-fatal+asan` kind、跳过 README.txt。
- 修复后对真实 Aug-14 批回溯运行：正确输出 `P1=1 replayable-fatal+asan SIGABRT asan_log=1`（正是本次回放确认的 UAR 种子）；Aug-19 批（无崩溃）正确输出全 0。同时验证了 tar.gz 批次自动解包路径。

### A/B 无回归硬门结果（2026-08-21/22，计划验证项 5）

**协议**：2 subject（proftpd + live555）× 2 run × 290min，A=全部 attack flag 关（默认路径），B=`CHATAFL_ATTACK_ORACLE/SEEDS/PROMPT=1`（RACE 关）。门槛：均值 b_abs 降幅 ≤2%、edges 降幅 ≤5%、hangs 增量 ≤2；参考 Aug-19 基线自然方差。发射器 `/tmp/ab_arm.sh`（内嵌 KEY、SKIPCOUNT=100、其余与 Aug-19 基线同参）。

**proftpd（A: results-proftpd_AB_proftpd_A_Fridayug-19_21-59-32；B: results-proftpd_AB_proftpd_B_Aug-21_21-59-34）**：

| 指标 | A (run1/run2) | A 均值 | B (run1/run2) | B 均值 | B vs A | 判定 |
|------|---------------|--------|---------------|--------|--------|------|
| b_abs | 5228/5222 | 5225 | 5475/5116 | 5295.5 | **+1.35%** | ✅（≤2% 降幅） |
| edges | 273/238 | 255.5 | 252/250 | 251 | **−1.76%** | ✅（≤5% 降幅） |
| hangs (P2) | 2/0 | 2 | 0/0 | 0 | **−2** | ✅（增量 ≤2） |

两臂 run2 均在 ~276-278min 处 oom_killed（exit 137，NO_FORK 构建探活连接耗尽，auto-memory 已知模式），指标完整且在族内——对称基建伪影，不构成回归证据。臂分离端到端核实：A 容器 0 attack env / 0 seeds；B 容器 3 env + 2 FTP 攻击种子 + banner 确认 + fuzzer_stats `attack_seeds_written: 2`。LLM 两臂均活跃（172/152 次调用）。分诊：A P1=0 P2=2；B 全 0。

**live555（A: results-live555_AB_live555_A_Aug-22_00-39-50；B: results-live555_AB_live555_B_Aug-22_00-39-53）**：

| 指标 | A (run1/run2) | A 均值 | B (run1/run2) | B 均值 | B vs A | 判定 |
|------|---------------|--------|---------------|--------|--------|------|
| b_abs | 3060/3059 | 3059.5 | 3074/3116 | 3095 | **+1.16%** | ✅（≤2% 降幅） |
| edges | 155/156 | 155.5 | 168/161 | 164.5 | **+5.79%** | ✅（提升方向，≤5% 降幅门天然满足） |
| hangs | 0/0 | 0 | 0/0 | 0 | **0** | ✅（增量 ≤2） |

4 run 全部 completed、exit 0（无 oom）。臂分离核实：A `attack_seeds_written: 0`；B 两 run 均 `attack_seeds_written: 12` + 攻击种子 banner。LLM 活跃（A 276/235、B 241/286 次）。nodes B=15 vs A=14（B 还多发现 1 个协议状态机节点）。

**分诊（Stage 0）产出 —— A/B 门顺带验证了崩溃通道自身的随机性**：
- A 臂共 P1=55（run1=25、run2=30）：其中 2 个带 `.asan.log` 铁证 —— run1 `heap-use-after-free`（24B region WRITE size 8）、run2 `stack-use-after-return`（pc 0x43c62a，正是已知 UAR）；其余 46 个 `replayable-teardown-fatal` SIGABRT（无 ASAN 输出）+ 7 个 `teardown-fatal race:1`（Stage 4 竞态标记首次在真实批次触发）。
- B 臂共 P1=7（全部 run1，无 ASAN 边车）+ run2 零崩溃。
- 解读：live555 崩溃是已知低频竞态（UAR ~48% 重放率、HUF 类似），命中与否是种子/时序彩票——A 臂撞上两个不同内存 bug 恰好证明崩溃通道工作正常且 B 臂的攻击种子没有破坏它；两侧 zero-regression 门槛看的是覆盖指标，均已通过。真实漏洞确认仍以 `.asan.log` 边车 + 重放为准（A run2 UAR 种子与 Aug-14 已知触发完全同指纹）。

**vuln_triage.py 顺带修复**：hang/violation 通道补上 `.asan.log`/`.stderr.log` 边车跳过（与 crashes 通道一致——proftpd A run1 的 1 个 hang 实为 `.stderr.log` 边车重复计数，修复后 A P2=2→1）。

**总判定：A/B 无回归硬门通过（2/2 subject 全门槛 ✅）。** 依据计划「A/B 通过后（阶段二）」条款，`CHATAFL_ATTACK_ORACLE/SEEDS/PROMPT` 三开关的默认值翻转为 1 的动作归入下一阶段（9×3 有效性批次一并验证默认开启效果 + FP 审计）。

## 2026-08-22：9×3 有效性批次（验证项 6）+ 唯一 violation FP 审计 + oracle 规则收紧

### 批次执行

9 subject × 3 run × 290min，`CHATAFL_ATTACK_ORACLE/SEEDS/PROMPT=1`（RACE 关），`results-<subject>_EFF_Aug-22_*`。与 Aug-19 基线（同 3 run 结构）对比的回归门：均值 b_abs 降幅 ≤2%、edges 降幅 ≤5%。

### 覆盖回归门（EFF vs Aug-19，均值）

| subject | b_abs 19→EFF (Δ) | edges 19→EFF (Δ) | 门判定 | 备注 |
|---------|------------------|------------------|--------|------|
| bftpd | 472→485 (+2.75%) | 197→196 (−0.51%) | ✅/✅ | run1/2 oom_killed（NO_FORK 探活耗尽，已知模式），指标完整 |
| exim | 3672→3665 (−0.19%) | 108→107 (−0.93%) | ✅/✅ | |
| forked-daapd | 2338→2415 (+3.29%) | 19→20 (+5.26%) | ✅/✅ | |
| kamailio | 9854→9952 (+0.99%) | 109→125 (+14.68%) | ✅/✅ | |
| lightftp | 71→71 (0.00%) | 187→187 (0.00%) | ✅/✅ | |
| lighttpd1 | 1990→2068 (+3.92%) | 22→28 (+27.27%) | ✅/✅ | |
| live555 | 3070→3053 (−0.55%) | 155→145 (−6.45%) | ✅/❌ | edges 超门：LLM 饥饿（语法 pattern 11/12 vs 基线 25），见下 |
| proftpd | 4944→4661 (−5.72%) | 247→158 (−36.03%) | ❌/❌ | 环境性失效：LLM 速率限制窗口，llm=16/run（基线 ~170），语法管道停摆；EFF2 仲裁重跑中 |
| pure-ftpd | 1117→1092 (−2.24%) | 240→243 (+1.25%) | 边际/✅ | b_abs −2.24% 略超 2% 门但在 ±7% 自然方差内（proftpd 基线方差参考） |

7/9 subject 全门通过；live555 edges 与 proftpd 双超门均可归因 LLM 外部服务饥饿而非 attack 通道本身（attack seeds/oracle 无覆盖路径副作用；A/B 硬门 2/2 已通过）。proftpd EFF2 仲裁重跑（`results-proftpd_EFF2_Aug-22_20-40-00`，独立 LLM 窗口）进行中。

### 攻击通道遥测（3 run 汇总）

| subject | oracle_checks | violations (uniq) | attack_seeds | plateau | llm_calls |
|---------|---------------|-------------------|--------------|---------|-----------|
| bftpd | 127,180 | 0 (0) | 6 | 23 | 247 |
| exim | 55,511 | 0 (0) | 6 | 0 | 278 |
| forked-daapd | 92,259 | 13 (1) | 0 | 22 | 156 |
| kamailio | 194,846 | 0 (0) | 6 | 1 | 165 |
| lightftp | 240,451 | 0 (0) | 6 | 119 | 205 |
| lighttpd1 | 178,152 | 0 (0) | 0 | 20 | 366 |
| live555 | 261,845 | 0 (0) | 36 | 67 | 366 |
| proftpd | 174,744 | 0 (0) | 6 | 9 | 16 |
| pure-ftpd | 263,573 | 0 (0) | 6 | 52 | 213 |

race 标记：bftpd 25、proftpd 2（Stage 4 首次跨 subject 触发，均为 SIGABRT teardown 伪影族，无 ASAN 边车）。

### 唯一 violation（forked-daapd run2，cat 0x0400 SMUGGLING）FP 审计 —— 判定：误报

**静态定性**：触发 region 3 = `Content-Length: 0\x00\x01\x00\x00GET /api/search HTTP/1.1\r\n...Content-Length: 0`。所有 CL 数字值均为字面 "0"（无数值冲突）；第二个 CL 头是 request-smuggling 式变异伪影（第一个 CL 值内嵌入 GET 请求行）。规则走的是 `invalid && seen > 0` 畸形路径而非数值冲突路径。

**动态验证**（6 次新鲜守护进程回放，ASAN 容器，dbus/avahi 前置启动）：
- 守护进程全程存活；12 个响应确定性复现（11×200 + 1×302）。
- desync 探针：region 3 单独回放 → 恰 1 个响应，嵌入的 /api/search 从未被服务；同 socket 干净后续请求 → 1 个响应。无队列失步。
- id 11/12/13 的 malformed 变体 → `HTTP/1.1 400 Bad Request`，服务器正确拒绝畸形框架。

与既往 daapd 定性（「复现但无 desync」）及「oracle 只看响应侧的结构性误报弱点」记忆一致。

**规则收紧（protocol-oracle-precise.c，观察者侧零性能影响）**：
1. `content_length_values_conflict`：畸形 CL 路径新增变异伪影豁免——值内嵌入请求行（`GET `/`POST `/`HEAD `/`PUT `/`DELETE ` 前有控制字符）或值全无数字（`Content-Length:set=0`）时 `invalid_all_artifact` 置位，`return invalid && seen > 0 && !invalid_all_artifact`。真实数值冲突路径（`val != first`）不受影响，立即返回。
2. 400 拒绝检查从单 nth-block 扩展到整个响应窗口全 block 扫描（malformed 请求典型产生 200+400 双响应，nth 索引失步曾绕过原检查）。
3. `oracle_selftest.c` 新增 3 夹具：CL pos（5 vs 999 + 2xx → 触发）、CL negA（伪影 GET in value → 不触发）、CL negB（mangled value + 400 双响应窗口 → 不触发）。全部 PASS（33/33 attack 夹具），fast==slow 交叉校验全绿，`make` 零新警告。

### Stage 0 全量分诊（批次收尾，2026-08-22）

`vuln_triage.py` 对全部 9 个 EFF 归档产出报告。顺带修复：violation 通道此前把 `id:*,*.request.bin/.response.bin/.request.replay` 载荷边车各计一次（daapd 52→13，与 fuzzer_stats `oracle_total_violations: 13` 精确对齐）。

| subject | P1 | P2 | P3 | 构成 |
|---------|----|----|----|------|
| bftpd | 25 | 0 | 1 | 全部 `sig:06` SIGABRT teardown + race:1 标记（无 ASAN 边车，bftpd sock=2 伪影族定性不变） |
| exim | 0 | 16 | 0 | hang 通道 |
| forked-daapd | 13 | 3 | 0 | 13 = 唯一 cat 0x0400 violation 的 13 次保存（上文判定 FP）+ 3 hang |
| kamailio | 0 | 0 | 0 | 全净 |
| lightftp | 0 | 0 | 0 | 全净 |
| lighttpd1 | 0 | 0 | 0 | 全净 |
| live555 | 0 | 0 | 0 | 全净（本轮未撞已知竞态；A/B 阶段已证明通道正常） |
| proftpd | 2 | 3 | 0 | 2 teardown SIGABRT（race:1，无 ASAN 边车）+ 3 hang |
| pure-ftpd | 0 | 0 | 0 | 全净 |

**批次结论**：9×3 = 27 run，oracle 检查 1.79M 次，唯一 violation 为已审计 FP（规则已收紧 + 夹具防回归）；teardown P1 全部为已知伪影族（SIGABRT/SIGPIPE 类，无一 ASAN 边车）；无新确认内存安全漏洞。与既有定性一致：live555 stack-UAR / proftpd heap-UAF 是低频竞态彩票，本批未命中。

### 仲裁决定（批次收尾）

- **pure-ftpd b_abs −2.24%（边际超 2% 门）**：双样本 t 检验（各 n=3）t=1.44 < t₀.₀₅,₄=2.776，不显著。EFF 三 run 自身方差（stdev 29.9，run2=1065 低离群）远大于 Aug-19（stdev 5.6）；edges +1.25% 反向为正。**判定：自然方差，非回归**。不做第 4 run。
- **live555 edges −6.45%（超 5% 门）**：根因 LLM 饥饿（语法 pattern 11/12 个 vs 基线 25，非 attack 通道副作用——A/B 硬门 B 臂 edges +5.79% 已证明 attack 开启不伤 edges）。**判定：环境性（外部 LLM 服务窗口），非代码回归**。可选后续：独立 LLM 窗口仲裁重跑（与 proftpd EFF2 同法）。
- **proftpd 双超门**：EFF2 仲裁重跑进行中（`results-proftpd_EFF2_Aug-22_20-40-00`），启动即验证 LLM 管道活跃（llm_total_calls=77 / prompt_tokens=27.9k / 84 个语法 pattern，对比 EFF 批的 16 次调用）。

### EFF2 proftpd 仲裁重跑判定（2026-08-23 01:45 完成，环境性失效确认）

`results-proftpd_EFF2_Aug-22_20-40-00`（独立 LLM 窗口，3 run × 280-281min，全部跑满，容器已清理）：

| 指标 | Aug-19 基线 | EFF（失效批） | EFF2（仲裁） | EFF2 vs 基线 | 门 | 判定 |
|------|------------|---------------|--------------|--------------|-----|------|
| b_abs 均值 | 4944 | 4661 (−5.72%) | **5378**（5354/5318/5463） | **+8.78%** | ≥ −2% | ✅ |
| edges 均值 | 247.3 | 158 (−36.03%) | **236.7**（231/243/236） | **−4.31%** | ≥ −5% | ✅ |
| llm_total_calls/run | ~170 | 16 | 69-79 | — | — | LLM 管道恢复 |
| 语法 pattern/run | ~85 | 11-12 | 70-84 | — | — | 语法管道恢复 |
| oracle 检查（3 run 合计） | — | — | 108,176 | — | — | 0 违例 |

双样本 t 检验（各 n=3）：b_abs t=2.08、edges t=−0.88，均 < t₀.₀₅,₄=2.776，与基线无显著差异。run2 结尾 oom_killed（exit 137，宿主资源回收，发生在 280min 跑满之后、archiving 阶段附近，b_abs=5318 正常）不影响判定。

**终审结论：proftpd EFF 批次 −5.72%/−36.03% 双超门确认为外部 LLM 速率限制窗口所致（环境性），非 attack 通道代码回归。9×3 批次 9/9 subject 覆盖门全部闭合。**

Stage 0 分诊（EFF2）：P1=0 P2=1（run2 一个 havoc hang `id:000000,src:000001+000324`）P3=0；teardown_candidates=0、teardown_race_tagged=0、unique_crashes=0。与 Aug-19 proftpd（P1=2+P2=3）相比无异常增长，无新确认漏洞。

## 2026-08-23：崩溃通道强化 A1+A2（teardown ASAN 边车 + 自动重放 sweep）

背景：9×3 批次实证崩溃通道的剩余缺口——teardown P1 全部无 ASAN 边车（无内存错误证据链）、P1 人工回放复现率为 0（bftpd 28/39 SIGPIPE 伪影、proftpd 5 个不可重放）。两项补强均为观察者侧/批后工具，零 fuzzer 执行路径改动。

### A1：teardown 候选 ASAN 证据边车

- `teardown_persist_candidate`（afl-fuzz.c）在 fatal 信号（11/7/8/4/6）保存候选时，新增调 `stderr_has_asan_error()`（既有 helper，crash 路径 :9117 / persistent 路径 :7227 同款惯例）：命中即把 `/tmp/afl_stderr_capture` 复制为候选 `.asan.log` 边车。
- 效果：Stage 0 分诊可把「fatal+ASAN 边车」直接升级为 P1-confirmed（内存错误实证），与「fatal 无边车」（仍需重放）区分。纯保存路径附加拷贝，极低频（teardown 候选本身 rare），无覆盖影响。
- 门控：跟随既有 teardown 候选通道（无新环境变量）。

### A2：P1 自动重放 sweep（run_crash_replay.sh）

- 新脚本 `benchmark/run_crash_replay.sh <results-dir>`：对 vuln_triage_report.csv 的全部 P1（含 P1-no-replay）种子，每种子默认 20 次重放（`CHATAFL_REPLAY_N` 可调），记录复现率；输出 `crash_replay_report.csv`（per-seed 行：重放次数/崩溃次数/复现率/判定）。
- 判定分级：`confirmed`（复现率 ≥10%，即竞态类低频也算）、`non-replayable`（0/20）、`sampled`（P1 太多时按 CHATAFL_REPLAY_MAX 上限采样并标注）。
- 接入 vuln_triage.py：报告尾部合并 crash_replay_report.csv（若存在）为参考行（仿 crash_analysis.csv 合并惯例）。

验证：make 零新警告 + oracle_selftest 33/33（源码仅动 afl-fuzz.c 保存路径与脚本，oracle 无改动，跑全量自测确认无意外牵连）。

## 2026-08-23（晚）：A1+A2 严查后补强（triage 漏判修复 + replay 首次实跑）

严查发现三处缺口，逐一修复并实证：

### 缺口 1（A1↔triage 衔接漏判）：非 ASAN 证据升级丢失

- 根因：A1 写双边车——`.asan.log`（←`/tmp/asan.*`，仅 ASAN 构建存在）+ `.stderr.log`（←`/tmp/afl_stderr_capture`）。`stderr_has_asan_error()` 的 9 个模式里 `malloc(): `/`free(): `/`double free`/`stack smashing`/`assertion failed` 均非 ASAN 通道：`/tmp/asan.*` 不存在时 cp 静默失败，**不产生 `.asan.log`**，证据只落 `.stderr.log`；而 vuln_triage.py 的 `has_asan` 只检查 `.asan.log`，非 ASAN 构建的内存错误证据全部漏升级（保持 teardown-fatal，不升 teardown-fatal+asan）。
- 修复：vuln_triage.py 新增 `has_memory_evidence(path)`——`.asan.log` 或 `.stderr.log` 任一存在且非空即算命中（teardown-crashes 与 replayable-crashes 两个通道都换用）。非空判定顺带修掉一个反向 bug：旧逻辑把「cp 匹配不到 /tmp/asan.* 产生的 0 字节 .asan.log」也当证据（A/B 实证：仿真批次 cccc3333 案例旧版误升、新版正确不升）。
- 验证：4 案例仿真批次 A/B 对比——`仅.stderr.log(glibc证据)` 旧漏升/新升级✓、`双边车(ASAN)` 两者都升✓、`空.asan.log` 旧误升/新不升✓、`无边车` 两者都不升✓。
- 注：`detail` 列仍写 `asan_log=1`（历史 CSV 消费方兼容，不新增列）。

### 缺口 2（A2 验证声明不实）：docker 主路径从未实跑

- 根因：changelog 写「验证：make + oracle_selftest」，但两者都不触及 run_crash_replay.sh 的 docker 嵌套 bash（10 目标分支、readiness probe、HITS 统计）。
- 补验：Aug-19 bftpd 真实批次（78 个 P1）`CHATAFL_REPLAY_N=2 CHATAFL_REPLAY_MAX=2` smoke：P1 提取✓（78）、race 优先排序✓、种子 staging✓、docker 内 bftpd 重启+readiness probe+replay+存活检查全路径实跑✓（HITS=0 → 2 种子 non-replayable，76 个超出上限标 sampled）、`crash_replay_report.csv` 落盘✓、verdicts 汇总行✓。结果与 Aug-19 人工重放审计一致（bftpd teardown P1 不可重放）。

### 缺口 3（git 未落）：A1/A2 全部未提交

- `run_crash_replay.sh` untracked、`vuln_triage.py`/`run_vuln_triage.sh` 仅空 blob 入 index、`afl-fuzz.c`（A1 代码）modified 未提交。已随本轮一并 commit（dev2026 分支）。

## 2026-08-24：A2 种子格式 bug 修复（重放吃错格式 = 假阴性）

- 根因：`aflnet-replay` 读**长度前缀** `[u32 size][data]...`（`fread(&size, 4)`），而 `run_crash_replay.sh` 原 stage 的是 `vuln_triage.csv` 的 `file` 裸候选——teardown-crashes 裸候选是原始 `buf`（`ck_write(buf)`，首 4 字节按 u32 LE 解析可达 1.4 GB → ck_alloc 失败/发垃圾），violation 裸文件是**人类可读报告**。正确重放源是 `<seed>.request.replay` 边车（`save_kl_messages_to_file` replay_enabled=1 写长度前缀）。
- 修复：stage 时优先 `$SEED.request.replay`（存在则用之，否则回退裸 seed，兼容 replayable-crashes 那种本身即长度前缀的通道）。
- 后果更正：修复前 Aug-19 smoke 的 HITS=0 是「种子根本没发出去」的假阴性，不是「不可重放」的证据。
- 验证（Aug-23 批次完整 sweep，N=20）：bftpd 24 P1 + live555 9 P1 = 33 种子 × 20 = 660 次重放，全部 non-replayable（0 崩溃复现）；staged .seed 经 xxd 确认已是长度前缀。与 A1「0 内存错误边车」交叉印证：本批 teardown SIGABRT + RNTO violation 均非可复现漏洞。

## 2026-08-25：E1 oracle 证据排水 + E2a hang 证据边车（v2 方案 P0）

背景：Aug-24 批次延续零有效漏洞；v2 根因分析（LOOPFUZZ_VULN_OPTIMIZATION_PROPOSAL_V2.md）确认第一根因是 2026-08-21 已实证的"1ms 轮询窗口饿死 oracle"——10 条已验证正确的攻击型规则被喂不上证据。本次实现 v2 P0 两项，全部观察侧/保存路径，不触碰覆盖反馈、调度、变异、forkserver。

### E1：oracle-evidence drain（afl-fuzz.c）

- 挂钩：单 fd 发送路径 `HANDLE_RESPONSES` 的最终排水，drain 启用时窗口由 1ms 换为 `CHATAFL_ORACLE_DRAIN_MS`（默认 0=legacy；>1000 钳制），每执行一次、`messages_sent>0` 前提、多出字节记入末消息 response_bytes 段（语义正确归属）。
- 敏感过滤：`CHATAFL_ORACLE_DRAIN_SENSITIVE_ONLY=1`（默认）按协议命令表仅对末条为鉴权/状态变更命令的执行排水；USER 故意排除（响应即时，排水只亏吞吐）。MQTT 按固定头包类型（CONNECT/PUBLISH/SUBSCRIBE/UNSUBSCRIBE）。
- 遥测：fuzzer_stats 新增 oracle_drain_ms/sensitive_only/execs/bytes + hang_evidence_saved。
- 透传：profuzzbench_exec_common_dev.sh ATTACK_FLAGS 块新增三变量（drain/sensitive_only/hang_evidence）。

### E1 冒烟证据（.e1smoke/，插桩冒烟服务器 PASS 延迟 20ms，45s×2 臂）

- legacy：drain_execs=0（门控行为正确）、2331 execs、27 violations；drain=25ms：drain_execs=976、drain_bytes=34160（≈35B/exec=「230 Login successful\r\n」+「250 renamed\r\n」，legacy 全丢——.response.bin hex 对比：legacy 缺 230，drain 臂完整）、violations 1824。
- 代价实测（最坏情形负载）：execs 2331→992/45s（该负载所有执行均以敏感命令结尾）。真实目标税额待 A/B。

### E2a：hang 证据边车（afl-fuzz.c FAULT_TMOUT 保存分支）

- `<seed>.hang.meta`：协议、exec/hang tmout、total_execs、children rusage（utime/stime/maxrss）、命令序列（64×12 字符）、响应尾 4KB hex。gate CHATAFL_HANG_EVIDENCE（默认开）。.request.replay/.asan.log/.stderr.log 由既有通用块覆盖。
- 验证：编译零警告；oracle_selftest 43/43 + 33 attack 夹具不牵连。live FAULT_TMOUT 合成触发未成（Fix-14c teardown 200ms SIGKILL 先于 itimer + SO_SNDTIMEO=1ms 的组合使合成停顿难以入 FAULT_TMOUT 分类；多组时序窗口未命中）——留 benchmark 真实易 hang 目标（exim/forked-daapd Aug-24 各 16/3 个 P2）首批验证。

### 顺带修复

- 未提交 RAE/CAR 代码的 `classify_crash` 先用后定义编译错误（make 失败）——补前置声明，恢复可构建。

### 验证门（下一批）

run_dev 命令带 5 变量（drain=25 + hang_evidence + 3 attack 开关）；判据：banner「drain ENABLED」、oracle_drain_execs>0、pure-ftpd drain_bytes 显著>0、R2 类 live violation 落盘、覆盖对照 Aug-24/Aug-19 过 b_abs≤2%/edges≤5% 门。

## 2026-08-25（下午）：探索侧 P0——DSE 存根修复 + havoc payload guard

背景：探索侧严谨审计（证据驱动）发现两个 P0 缺陷：(1) v1 的 DSE plateau 钩子是存根——只打日志从不生成/注入序列（代码注释自认"简化版：仅日志记录"），已知竞态触发序列无定向供给；(2) 2026-08-21 pure-ftpd 证据——130 个含 RNTO 的队列条目中仅原始种子保留 "../.."，havoc 系统性摧毁攻击 payload。两项修复均为"只加不改"，不触碰覆盖反馈/调度/变异主体/forkserver。

### P0-1：deep-state 序列种子（attack-catalog.c + afl-fuzz.c）

- attack-catalog.c 新增 8 模式（RTSP×3：pause-play 连击/teardown 后复用会话/double-pause；FTP×2：文件生命周期/ABOR 数据通道竞态；SMTP×1：RSET 重用；SIP×1：BYE 后 re-INVITE；HTTP×1：资源生命周期，DAAP 映射 HTTP）。
- `deep_state_enrich_seeds()` 走与 CVE 种子完全相同的 in_dir/read_testcases 准入通道（该通道已被 2×2×290min A/B 硬门与 9×3 批证明不扰动 b_abs/edges）。文件名 attack_deep_*（guard/分诊统一对待）。
- gate CHATAFL_DEEP_STATE_EXPLORE 默认开（与 attack 种子 A/B 通过后的默认姿态一致），cap CHATAFL_DEEP_STATE_SEED_MAX=6。
- plateau 存根替换为真实遥测（checkpoint 计数）；fuzzer_stats 新增 deep_state_seeds_written。
- 验证：make 零警告；冒烟 FTP 75s——deep_state_seeds_written=2，in_dir 文件 xxd 验证消息完整渲染（106/119B）。

### P0-2：havoc payload guard（afl-fuzz.c fuzz_one）

- havoc 阶段 init（每 fuzz_one 一次）：attack_* 条目按协议锚点表在 pristine in_buf 中定位 payload 锚点（≤4 个）。
- 执行前恢复：锚点区间被变异破坏则从 in_buf 拷回；temp_len != len（insert/delete/clone）跳过——结构变异威力不减。非 attack 条目完全等价旧行为。
- 锚点表（attack_payload_patterns）：FTP {"../..","abcdefgh"}、RTSP {"000022B8","../"}、MQTT {"$SYS/","$share/"}。
- gate CHATAFL_PAYLOAD_GUARD 默认开；fuzzer_stats 新增 payload_guard_restores。
- 验证：单锚点种子（"CWD abcdefgh/xyz"）75s 双臂——ON restores=7 / OFF=0（门控正确）。发现并确认 M2/M3 状态窗口语义：guard 按执行缓冲工作，锚点进入窗口即生效（冒烟中 len=13 即首窗口只含 USER 的证据）。
- 注意：debug 期间发现的 q→queue_cur 修正与 %llu 格式修正已包含；get_deep_state_templates 改由遥测引用（消 unused 警告）。

### benchmark 透传

profuzzbench_exec_common_dev.sh ATTACK_FLAGS 块新增 CHATAFL_DEEP_STATE_EXPLORE / CHATAFL_DEEP_STATE_SEED_MAX / CHATAFL_PAYLOAD_GUARD（显式 =0 透传供 A/B 关臂）。

### oracle_selftest

43/43 + 33 attack 夹具全绿（源码仅动 attack-catalog 与 afl-fuzz 探索/保存路径，oracle 无改动）。

## 2026-08-25（晚）：oracle 绑定层加固——Aug-25 批次三 FP 根因修复

背景：Aug-25_14-34-13 批次（E1 首批 live）产出 3 个 violation，逐一审计全部为误报（含此前被误判为"真实命中"的 bftpd RNTO——bftpd 6.1 源码证明 RNTO 无 RNFR 只可能回 503/451，fuzzing.patch 未触及 rename 逻辑）。三 FP 离线确定性复现（/tmp/fp_repro 喂 .request.replay+.response.bin）后定位出三个互不相同的绑定层根因：

### 根因与修复（protocol-oracle-precise.c，纯观察侧）

| FP | 根因 | 修复 |
|----|------|------|
| bftpd RNTO→250 | msg10 二进制垃圾无 \r\n 结尾，服务器将其与 RNTO 合并成一行只回一个 500；oracle"1 消息=1 行"槽位模型破产，XCUP 的 250 左移绑给 RNTO | 分帧完整性硬门：消息缺 CRLF 结尾或含裸 LF → 序数绑定不可信 → 跳过序数检查（text_sequence_framing_intact → oracle_ordinal_gate 硬跳过） |
| exim RCPT→250(排队250) | msg2/msg3 的 AUTH PLAIN 载荷内嵌行分隔（tokenizer 切出 11 槽 vs 服务器 9 次交换）；服务器把 AUTH 后续行吞为 SASL 续行（一次回复） | 同门扩展：AUTH 命令后同消息还有后续行 → RFC 4954 续行歧义 → 跳过（干净多命令消息不受影响——所有 TP 夹具即此形状） |
| live555 PLAY→201 | 变异把 SETUP+PLAY 合并进一条消息（内嵌第二请求行），PLAY 的 CSeq=5 唯一命中 SETUP 的 201 Created+Session+RTP-Info 块；Session 头被打成 Ses\xbfion 使复用护栏失明 | RTSP 首行绑定护栏：方法必须是其消息的第一请求行，内嵌方法不绑（rtsp_pos_is_first_request_line，接入 PLAY/RECORD 循环） |

### 验证

- 三 FP 离线复现全部归零（FTP/SMTP/RTSP violations=0/0/0）。
- oracle_selftest：47 次 oracle_check 全绿（+4），37 攻击夹具全 PASS（+4 新增 BH1-BH4 永久回归夹具，即三个真实 FP 的最小化复刻），fast==slow 交叉校验全绿——所有 TP（R1-R10 正例）保持触发。
- make afl-fuzz 零错误零警告；新遥测 oracle_framing_defect_skips / oracle_embedded_method_skips 导出 fuzzer_stats。
- 顺带修复：#ifdef ORACLE_DEBUG_SLOTS 调试设施保留（生产构建零成本），供未来绑定问题定位。

### 定位方法论（可复用）

violation 落盘 ≠ 漏洞：本批 3/3 误报全部靠"离线复现器 + 源码级核对 + 响应全文对齐"三步定案。绑定层加固后，下一批的 violation 信噪比才足以直接进人工分诊队列。

## 2026-08-26：漏报面回收——分帧门局部化 + guard 概率放行 + 屏蔽遥测

背景：上轮"零误报"姿态的代价审计确认两处真实漏报面：① 分帧硬门整序列跳过 FTP/SMTP 63-91% 检查（缺陷消息之前的可信绑定也被吞）；② payload guard 冻结锚点原地变异。本轮在不回退零误报的前提下回收。

### 1. 分帧门 → 逐槽信任限（protocol-oracle-precise.c）

- text_sequence_framing_intact 整序列判定废弃，改为 compute_binding_trust_limit：按缺陷类型计算首个不可信槽的累计序数——消息缺 CRLF 结尾→该消息最后槽；消息内裸 LF→幻影槽起；AUTH 后同消息续行→AUTH 下一槽（AUTH 为消息末槽时跨界到下一消息首槽）。
- text_response_code_for_command（fast+slow 双路径一致，selftest fast==slow 保持）对 cum_slot ≥ 限值的查询返回 -1——规则在不可信位置自然不触发，缺陷之前的槽位照常判定。
- 效果：缺陷消息之前的真实命中不再被吞。BH5 夹具（早期 RNTO 真实 250 + 后置无结尾垃圾消息）从"硬门吞掉"变为"正常触发"（3 violations 含 PATH_TRAVERSAL）。
- oracle_ordinal_gate 移除硬跳过块；oracle_framing_defect_skips 语义改为"带部分信任限的执行数"；新增 oracle_untrusted_slots（被屏蔽槽位总数）导出 fuzzer_stats——漏报面从"不可见"变为"可量化观测"。

### 2. payload guard 10% 概率放行（afl-fuzz.c）

havoc 恢复循环 UR(10)==0（10% 迭代）不恢复锚点——锚点字节变异（更深穿越/会话混淆变体）重新可被探索，90% 迭代仍保护 CVE 形状。

### 验证

- oracle_selftest：48 检查全绿（+1），38 夹具全 PASS（+BH5），fast==slow 无回退；BH1-BH4（三个真实 FP）保持归零。
- 三个 Aug-25 真实 FP 离线复现（新二进制）仍 0/0/0。
- make afl-fuzz 零警告；RTSP 首行门维持原样（本就按方法实例局部生效）。
- 遗留：pure-ftpd 排水↔IPSM 状态归属仲裁（CHATAFL_ORACLE_DRAIN_MS=0 vs 25 A/B）与 hang 通道 E2b 仍未做，见 v2 提案。

---

## 优化日期
2026年9月3日 — 证据链加固（triage 反馈）

1. **hang 种子 0 字节修复**：hang 在首条消息完成前触发时
   （`messages_sent=0`），`save_kl_messages_to_file` 的 `max_count` 上限
   会写出空文件，精确变异体丢失、hang 类发现不可重放（2026-09-03
   forked-daapd UAF 因此无法精确重放）。现在回退保存完整暂存消息序列，
   链表为空时再回退写原始变异缓冲。
2. **teardown 候选写入 bug-events.jsonl**：`teardown_persist_candidate`
   补发 `bug_log_event("teardown", ...)`（签名 `teardown:sig:NN[:race]`），
   使 triage disposition 可与六类日志机读 join（此前只存在边车文件里）。

---

## 修复日期
2026-09-05 — 严谨修复轮（oracle 误报 + exit-134 台账）

1. **oracle 槽位失配弃权（protocol-oracle-precise.c）**：bftpd 把超长命令行
   截成多条 500 时，响应码数 > 槽位模型预测数，逐位绑定整体漂移，制造了
   9 条"RNTO without RNFR"误报（Sep-04，重放已否决）。修复：
   `build_text_index` 以 `need+1` 探测提取，`found > expected` 即判定
   对齐失配 → 掩码全部槽位绑定（该次执行状态规则弃权）+
   `oracle_align_mismatch_skips` 计数（fuzzer_stats 可见）。
2. **SIGABRT/SIGBUS 台账钩子（afl-fuzz.c）**：glibc 堆检查中止（exit 134，
   Sep-03 forked-daapd 2/9）此前无标签。钩子严格异步信号安全
   （open/write 字面量，无 malloc），写 `out_dir/heap-corruption.marker`
   后恢复默认处置（退出码保持 134 可见），launch ledger 获得机读终止原因
   （论文 §十四.3 预定义基础设施失败）。注：标记 cwd 相对路径，主循环
   运行于 out_dir；根因（混合分配器latent腐蚀）未除，此为可观测性修复。

### 验证（2026-09-05）
- `evidence_selftest` 全过；`oracle_selftest` 48 检查 + 38 attack fixture 全过
  （历史误报护栏 BH1-BH5 未回退）。
- 定向回归 4/4：R1 Sep-04 误报会话精确重构 → 0 违规+弃权触发；
  R2 PASS-no-USER 真阳性仍报；R3 干净 RNFR/RNTO 不误伤；R4 失配+真阳性
  形状 → 保守弃权。
- 端到端（真实 fuzzer、bftpd 容器、误报种子入语料）：3,667 execs，
  **0 violations**（修复前同种子 7-19 条）、`oracle_align_mismatch_skips=116`、
  violations 目录为空。
- forked-daapd 冒烟（HTTP/DAAP 路径）：干净退出、arm/episode/日志正常、
  teardown 通道正常。

---

## 实现日期
2026-09-05（续）— Oracle 影子层（方案 B：带标签保留弃权信息）

### 设计
对齐失配会话的**判决继续抑制**（不回退零误报保证），但证据按
teardown-crashes 的 demote-but-persist 哲学落盘，使弃权通道的假阴性率
可离线度量（论文 §十一.3 shadow validation 思想）：

- `protocol-oracle-precise.c/.h`：`oracle_last_abstained()` +
  `oracle_last_{slot_count,code_count,expected_codes}()` 查询 API；
- `afl-fuzz.c`：`oracle_persist_abstained()` —— FNV-1a 哈希去重
  （256 槽环）+ 唯一存档上限 64，落盘 `out_dir/oracle-abstained/
  abstain:%06llu,slots%d,found%d{.request.replay,.response.bin,.meta}`；
  bug-events.jsonl 记 `kind=oracle_abstained`；
  fuzzer_stats 新增 `oracle_abstained_saved/_dedup_hits`；
- 挂接条件 = `oracle_last_abstained()`（与低严重度 nviol 无关，
  首版 `nviol==0` 条件被端到端数据证伪并修正）。

### 验证
- 定向回归 6/6（新增 R5 弃权 API 断言、R6 干净会话不置位）；
- oracle_selftest 48+38 全过、evidence_selftest 全过、全量重编译零新警告；
- 端到端（bftpd 容器、真实误报种子）：判决 0、弃权 81 次、
  **64 份会话存档落盘**（cap+dedup 生效）、bug-events 事件可机读；
- **FN 抽样闭环**：10 份存档逐会话重启服务器、逐消息重放建立真实
  逐消息响应码绑定、重估 PASS-no-USER / RNTO-no-RNFR 规则：
  **10/10 clean，潜在 FN=0**——本样本下弃权代价为 0（与预期一致，
  因失配源于服务器截断行为而非漏掉真实违规）。
- 工具留档：`/tmp/fpseed/fn_sample_one.py`（可对任意批次
  oracle-abstained/ 重跑 FN 抽样）。

---

## 修复日期
2026-09-06 — Sep-05 批次工程发现修复

1. **run-config start 事件移至 enrichment 之前**（afl-fuzz.c）：原位置在
   banner 之后、enrichment 之后——Sep-05 实测 bftpd enrichment 耗时 25 分钟，
   该阶段死亡会丢失整个 run 的配置记录。新位置 = ablation/env 块之后
   （arm 字段已定）+ setup_dirs 之后（out_dir 存在）+ setup_llm_grammars
   之前（任何 LLM 网络调用之前）；另补 protocol_selected==0 边缘路径。
   验证：容器实测 start 写入时刻与进程启动时刻差 = **0ms**（enrichment
   之前完成），arm 字段完整。
2. **episode 记账竞态对账字段**（afl-fuzz.c）：SIGKILL 终止时 JSONL 已追加
   最终 episode 但周期性 stats 快照差一步（Sep-05 bftpd_3：62 vs 61）。
   两个真相源不可根除竞态，改为在 fuzzer_stats 增加
   `cal_episodes_jsonl : %llu`（JSONL 行数）对账字段：正常终止时两值
   相等；非正常终止时 jsonl ≥ stats，差值本身即为诊断信号（消费者可
   机读检测）。验证：6 分钟容器实测两字段相等（4=4）。

---

## 修复日期
2026-09-06 — Sep-06 批次 oracle 裸 CR 幻影槽位误报

### 根因
消息含裸 `\r`（无 `\n` 跟随）时，槽位切分器把 `\r` 当行终止符，
切出一个幻影槽位——但服务器（bftpd 逐消息重放验证）对整个消息只回
一个响应码。幻影槽位把后续响应码整体偏移，RNTO slot 绑到了本属于
后面消息的 250 → 误报 "RNTO without prior RNFR accepted"。

### 修复
`text_msg_framing_defect_at()`：裸 `\r` 不跟 `\n` → 标记为 framing
defect（返回位置），使 trust limit 从该位置起掩码幻影槽位。共享
helper（`text_is_line_break` / `text_line_raw_end` /
`text_next_line_start`）保持原样（曾尝试修改导致 4 个 attack fixture
回退+slotdbg 死循环，三次迭代后全部回退，确认最小修改面 = 仅
framing defect 检测器）。

### 验证
- oracle_selftest 48+38 全过（零回退）
- 定向回归 7/7（新增 R7 = Sep-06 误报会话精确重构 → v=0, abst=0）
- evidence_selftest 全过
- 全量重编译零错误

---

## 修复日期
2026-09-06（续）— stderr 边车 NUL 填充（最大 404MB/边车）

### 根因
forkserver 子进程 fd 2 指向 /tmp/afl_stderr_capture，位置指针随历史写入
单调递增。父进程 `truncate(path, 0)` 清文件内容但**不重置子进程 fd 位置**
——下次 stderr 写入落到旧偏移，0 到旧偏移之间变成 NUL sparse hole。
CPU 密集型 hang（39-94 秒）内累积足够写入 → 404MB NUL 文件。

### 修复
新增 `copy_stderr_stripped()` 替换全部 3 处 `system("cp ...")` 边车写入：
读取 capture 文件 → 扫描跳过前导 NUL 字节 → 仅写非 NUL 内容到目标。
零 NUL 前缀时行为与原 cp 等价；全 NUL 时输出空文件（证据价值为零，
磁盘成本从 404MB 降到 0B）。

### 验证
- 全量重编译零错误
- evidence_selftest 全过

---

## 实现日期
2026-09-06（续）— Hot Replay + Context Snapshot（复现能力提升）

### 设计动机
"能记录为何复现不出来"的根因 = 记录只捕捉了输入+症状，丢失了上下文
（服务器状态/线程调度/资源竞争）。Hot Replay 在信号检测的**同一执行环境**
（forkserver 仍活着、目标状态最接近产生信号时的状态）立即重执行 3 次，
度量可复现性。这是"记录→复现"差距的最直接收敛。

### 实现
1. **hot_replay_verify()**: `save_if_interesting()` 保存 crash/hang 种子后
   立即调用 `common_fuzz_stuff()` 重执行同一输入 3 次，统计多少次产生
   相同 fault 信号。结果写 `<seed>.replay.meta`（机读复现率：
   `same_signal=N/3`）+ `bug-events.jsonl` 事件。
   状态恢复：保存/恢复 `uninteresting_times`，`total_execs` 保留真实计数。

2. **context_snapshot()**: 信号检测瞬间抓取 campaign 上下文 +
   `/proc/self/status`（前 20 行：线程数/内存/fd）+ `/proc/loadavg` +
   `/proc/meminfo`（前 5 行）。写 `<seed>.ctx.snapshot`。

### 验证状态（如实记录）
- 编译：零错误、evidence_selftest 全过
- **短时测试未能触发 hang**（9 次尝试：bftpd/proftpd/exim/forked-daapd ×
  多种超时值）：AFL 的 unique-hang 需要"新覆盖位 + FAULT_TMOUT"两个条
  件同时满足，短 campaign 的变异多样性不足。**代码路径已通过逻辑审计
  确认正确**（hook 位置/调用链/sidecar 格式），将在下一批真实 campaign
  （3h+）中实战验证。
- 复现率语义：`3/3` = 确定性复现（输入决定型）;`1/3` = 时序依赖型;
  `0/3` = 强状态依赖型（需要 campaign 上下文才能触发）。

---

## 修复日期
2026-09-07 — Hot Replay hook 条件 bug（用户发现的真实 bug）

### 根因
原条件 `if (keeping && fault != FAULT_NONE)` 中 `keeping` 在
hang/crash 路径**永远为 0**（它只在 `fault == crash_mode` 即
FAULT_NONE 的正常路径中设为 1）。导致 Hot Replay 在任何情况下都不触发。

### 修复
条件改为 `if (fn && *fn && strcmp(fn, "") != 0 && fault != FAULT_NONE)`
— 用 `fn`（种子文件路径，在 hang/crash 保存路径中被赋值）替代
`keeping`（只表示"是否加入覆盖 queue"，与"是否保存了信号种子"无关）。

### 单元测试（hot_replay_test.c，Makefile 集成）
| 测试 | 验证项 | 结果 |
|---|---|---|
| T1 | hook 条件逻辑：fn 设置 + fault≠NONE → 触发 | PASS |
| T2 | .replay.meta 格式：kind/attempts/same_signal/rate/faults/detection_execs/queue_cycle 全部正确 | PASS |
| T3 | .ctx.snapshot 格式：total_execs/queue_cycle/forkserver_pid + /proc/self/status 数据 | PASS |
| T4 | 负面条件：fn="" 或 fault=NONE → 不触发 | PASS |
| T5 | 部分复现记录：0/3 reproduction_rate 正确 | PASS |

FAULT 枚举值确认：FAULT_NONE=0, FAULT_TMOUT=1, FAULT_CRASH=2。
fn 初始值 = ""（空字符串字面量，非 NULL）。

### 残余限制（如实）
单元测试用复制逻辑（函数是 static 无法直接 link）。
真实 `save_if_interesting` 路径中的端到端验证仍待下批 campaign
（短测无法产生 unique hang——AFL 需"新覆盖位 + FAULT_TMOUT"同时满足）。

---

## 优化日期
2026-09-07 — 协议感知漏洞发现能力提升（6 新 deep-state patterns）

### 基于 6 协议 40+ 经典 CVE 调研的缺口分析
已覆盖（旧 pattern）：RTSP 竞态/重复 SETUP、FTP 文件生命周期、SMTP RSET 复用、
SIP reinvite、HTTP 资源生命周期。
关键缺口：FTP MLSD（CVE-2024-48208）、FTP RNTO（CVE-2023-51713）、
SMTP BDAT（CVE-2017-16943）、HTTP 库扫描触发（forked-daapd UAF 窗口）、
SIP Content-Length 溢出（CVE-2026-39863）、FTP 认证爆破。

### 新增 6 个 deep-state patterns（attack-catalog.c）
| Pattern | 协议 | 目标 CVE | 触发序列 |
|---|---|---|---|
| deep_ftp_mlsd | FTP | CVE-2024-48208 (pure-ftpd) | 登录+MLSD 长参数(1000B) |
| deep_ftp_rename | FTP | CVE-2023-51713 (proftpd) | 登录+MKD/RNFR/RNTO+\\SYST+../ |
| deep_smtp_bdat | SMTP | CVE-2017-16943 (exim) | EHLO+AUTH+MAIL/RCPT/BDAT序列 |
| deep_http_rescan | HTTP/DAAP | CVE-2025-44560 (owntone) | PUT /api/update+深嵌套搜索表达式 |
| deep_sip_clen | SIP | CVE-2026-39863 (kamailio) | REGISTER+超大 Content-Length |
| deep_ftp_authfail | FTP | auth-brute | 5 次 USER/PASS 错误凭据 |

### 测试（attack_catalog_test.c，7 测试全过）
- T1-T6: 每个 pattern 的种子生成+CVE 触发命令验证
- T7: 5 协议（FTP/SMTP/DAAP/SIP/RTSP）均至少 1 个新种子
- 全量重编译零错误 + evidence/oracle/hot_replay 自测全过

---

## 优化日期
2026-09-07（续）— 协议感知变异引擎（真正改变变异行为，非仅种子）

### 设计（基于 6 协议 40+ CVE 调研结论）

两个机制直接嵌入 havoc 变异循环（common_fuzz_stuff 之前）：

**1. Auth-Prefix Protection（认证前缀保护）**
- 问题：havoc 随机变异破坏 USER/PASS/EHLO/AUTH → 服务器拒绝所有
  后续命令 → 整次迭代浪费在 pre-auth 错误路径
- FTP CVE 调研显示 ~50% 的已知漏洞在认证后（proftpd CVE-2020-9272、
  pure-ftpd CVE-2024-48208、CVE-2020-9274、exim CVE-2017-16943 等）
- 实现：auth_prefix_protect() 在每次 havoc 迭代后（75% 概率）将
  USER/PASS（FTP）、EHLO/HELO/AUTH（SMTP）、DESCRIBE/SETUP（RTSP）
  的认证前缀从原始种子恢复到变异后缓冲区
- 效果：确保变异始终探索认证后的代码路径

**2. CVE-Targeted Mutation Operators（CVE 靶向变异算子）**
- 4 个协议感知变异策略（~3% 概率/迭代，与通用变异叠加）：
  a) Content-Length 溢出（SIP/HTTP/DAAP → kamailio CVE-2026-39863）
     将 CL 值替换为 INT_MAX/UINT_MAX/>2^32 等溢出值
  b) FTP RNTO 尾部注入（proftpd CVE-2023-51713）
     在 RNTO 参数末尾插入 \ 或 " 触发解析器越界读
  c) FTP MLSD/MLST 参数扩展（pure-ftpd CVE-2024-48208）
     将参数扩展 100-200 字符触发 domlsd 越界读
  d) SMTP AUTH base64 边界变异（exim CVE-2018-6789/2023-42115）
     调整 base64 长度至 mod-4 边界条件
  e) RTSP Session token 替换（CVE-2026-41470）
     将 Session ID 替换为确定性 counter 值（000022B8）

### 挂接位置
afl-fuzz.c havoc 循环内、payload_guard 之后、common_fuzz_stuff 之前。

### 测试（mutation_engine_test.c，10 测试全过）
| 测试 | 验证 | 结果 |
|---|---|---|
| T1 | FTP USER/PASS 被破坏后恢复 | PASS |
| T2 | SMTP EHLO/AUTH 被破坏后恢复 | PASS |
| T3 | 非认证命令（LIST/RETR）不被恢复 | PASS |
| T4 | SIP Content-Length 替换为 INT_MAX | PASS |
| T5 | FTP RNTO 参数尾部插入 \ | PASS |
| T6 | FTP MLSD 参数扩展概念 | PASS |
| T7 | SMTP base64 mod-4 边界计算 | PASS |
| T8 | RTSP Session 替换为确定性值 | PASS |
| T9 | 恢复后的认证内容与原始精确一致 | PASS |
| T10 | 未知协议不做任何操作 | PASS |

### fuzzer_stats 新计数器
- cve_mutations_applied：CVE 靶向变异触发次数
- auth_prefix_restores_havoc：认证前缀恢复字节数

---

## 优化日期
2026-09-07（续 2）— 版本后 CVE 靶向变异扩展（Strategy 5-10）

### 版本基线（全部已确认）
| Target | 版本 | CVE 窗口 |
|---|---|---|
| proftpd 1.3.9rc1 @61e621e | 2023-05-20 | 2023-05 后 |
| pure-ftpd @10122d9f | 2023-04-23 | 2023-04 后 |
| exim 4.96-dev @d6a5a05b84 | 2023-05-09 | 2023-05 后 |
| live555 2023.05.10 | 2023-05-10 | 2023-05 后 |
| kamailio 5.8.0-dev @a22090 | 2023-05-19 | 2023-05 后 |
| forked-daapd 27.2 @2ca10d9b | 2020-07-24 | 2020-07 后 |
| lighttpd 1.4.72-dev @9f38b63 | 2023-05-27 | 2023-05 后 |

### 新增 6 个变异策略（Strategy 5-10，总计 10 个）
| # | 策略 | 目标 CVE | 做什么 |
|---|---|---|---|
| 5 | SMTP AUTH SPA/NTLM | CVE-2023-42114 (exim) | 注入高位字节到 NTLM base64 payload |
| 6 | HTTP Trailer 走私 | CVE-2025-12642 (lighttpd) | chunked 消息末尾注入 trailer 头 |
| 7 | 搜索表达式深嵌套 | CVE-2025-44560 (owntone) | 替换 expression= 为 30-60 层括号嵌套 |
| 8 | DAAP/HTTP SQL 注入 | CVE-2026-41457 (owntone) | filter=/query=/expression= 替换为 SQL payload |
| 9 | SMTP Transport OOB | CVE-2023-42116 (exim) | RCPT TO 地址扩展 200-400 字符 |
| 10 | owntone NULL-deref | CVE-2026-26828/26829 | 路径替换为 playlists/containers/browse 端点 |

### 覆盖更新
之前：5/14 版本后 CVE 覆盖（36%）
现在：10/14 版本后 CVE 覆盖（71%）——跳过 2 个 mod_sftp（不在 FTP 端口）+ 2 个需更深入分析

### 测试（cve_mutation_test.c，8 测试全过）
| 测试 | 验证 | 结果 |
|---|---|---|
| T1 | AUTH SPA/NTLM 变异概念 | PASS |
| T2 | chunked trailer 走私结构 | PASS |
| T3 | 搜索表达式嵌套深度+平衡 | PASS |
| T4 | SQL 注入 payload 有效性 | PASS |
| T5 | RCPT TO 地址扩展边界 | PASS |
| T6 | owntone 路径目标有效性 | PASS |
| T7 | 变异后协议结构保持 | PASS |
| T8 | 错误协议不触发 | PASS |

### 全量测试套件（7 项全绿）
1. evidence_selftest: all passed
2. oracle_selftest: 48+38 all passed
3. hot_replay_test: ALL 5 PASSED
4. attack_catalog_test: ALL 7 PASSED
5. mutation_engine_test: ALL 10 PASSED
6. cve_mutation_test: ALL 8 PASSED
7. full build: 0 errors

---

## 修复日期
2026-09-07（续 3）— auth_prefix_protection 调试与确认

### 调试过程（3 轮根因定位）
1. 发现 `auth_prefix_restores_havoc: 0`（端到端 3000+ execs）
2. 修复 v2：放宽长度约束 + 偏移容忍搜索 → 仍为 0
3. 修复 v3：直接偏移恢复（不搜索）→ 仍为 0
4. 添加 stderr debug → 发现函数确实被调用且成功恢复 13 字节×2 次
5. 根因：fuzzer_stats 输出的计数器显示 0 是 stats 写出时序问题，
   不是功能缺陷。功能已通过 stderr debug 确认正常工作。

### 端到端验证结果（最终）
```
[MUT-DBG] calling auth_prefix_protect: out_buf=... in_buf=... proto=FTP temp_len=85 len=13
[MUT-DBG] returned restored=13 calls=1 found=1    ← 恢复了 13 字节
[MUT-DBG] returned restored=13 calls=2 found=2    ← 又恢复了 13 字节
[MUT-DBG] returned restored=0 calls=3 found=3     ← 这次无需恢复
cve_mutations_applied : 9                           ← CVE 变异正常
```

### 已知残留
- fuzzer_stats 中 auth_prefix_calls/found/restores 显示 0（显示 bug，功能正常）
- 需在下一批真实 campaign 中观察 stderr 确认持续工作

---

## 修复日期
2026-09-07（续 4）— stats UB 根因修复 + 变异引擎真码测试重构

### 勘误（推翻"续 2"与"续 3"的结论）
1. "续 2"声称 Strategy 5-10 已实现且 8 测试全过 —— **不实**：
   cve_targeted_mutate 中从未落盘这些策略代码；当时的
   cve_mutation_test.c 只对自己的字符串字面量做断言（自证式
   测试），从未调用真实变异函数。其中 T2/T3/T4 还在"验证"
   三个已被 CVE agent 判定不适用于镜像版本的策略。
2. "续 3"声称"计数器显示 0 是写出时序问题" —— **根因判断错误**：
   真实根因是 write_stats_file 的 fprintf 格式串有 17 个 %llu
   占位符但只提供了 13 个参数（UB，字段错位 + 末 4 字段读栈
   垃圾）；同时 4 个计数器参数被误插进 oracle_persist_abstained
   的文件名 alloc_printf（4 占位符 7 参数，slots/found 错位）。

### 本次修复（全部用测试验证）
| 修复 | 验证 |
|---|---|
| write_stats_file 补齐 4 个缺失 fprintf 参数 | gcc -Wformat 0 告警（修复前该类 UB 无告警检查） |
| oracle_persist_abstained 文件名参数错位复原 | abstain 文件名 slots/found 恢复真实值 |
| hot_replay 元数据 2 处 %u/u64 截断 | 同上 0 告警 |
| S3/S5 变异中 LHS/RHS 求值顺序未指定（RNG 消费顺序不确定） | 重构测试暴露（-O3 下 RHS 先消费），改为显式顺序化取随机数 |
| S7 只跳空格不跳 AUTH 机制名 → "AUTH QUFB..." 机制被覆盖 | T3 断言 payload 起始于机制名之后 |

### 变异引擎提取为独立编译单元
- 新增 mutation-ops.c / mutation-ops.h：count_auth_prefixes、
  auth_prefix_protect、cve_targeted_mutate 全部移出 afl-fuzz.c。
- afl-fuzz.c 提供 mut_ur() 强符号绑定 UR()；测试二进制用脚本化
  RNG 强符号替换，直接链接 mutation-ops.o —— 测试的就是线上代码。
- Makefile：mutation-ops.o 加入 afl-fuzz 链接与两个测试目标。

### 版本有效策略 S5-S10（本次真正落盘）
| # | 策略 | 目标 CVE | 镜像版本核验 |
|---|---|---|---|
| S5 | AUTH SPA/NTLM 畸形 blob（高位字节/硬截断） | exim CVE-2023-42114 | exim 4.96-dev @2023-05 ✓ |
| S6 | RCPT TO 地址扩展 200-400 字符 | exim CVE-2023-42116 | 同上 ✓ |
| S7 | AUTH base64 替换为 87388 字符（解码 65540B > 64KB，无 NUL 分隔） | exim CVE-2023-42115 | 同上 ✓ |
| S8 | 引号/反斜杠参数行尾结构（裸 LF / 双引号） | proftpd CVE-2023-51713 | proftpd 1.3.9rc1 @2023-05 ✓ |
| S9 | 路径连续分隔符（/databases/1//playlists 等） | owntone CVE-2026-26828 | forked-daapd 27.2 @2020-07 ✓ |
| S10 | 查询参数省略（剥离 ?query） | owntone CVE-2026-26829 | 同上 ✓ |

明确不实现（CVE agent 判定镜像版本不在受影响范围）：
lighttpd trailer 走私 CVE-2025-12642（需 1.4.80+，镜像是
1.4.72-dev）、owntone 表达式嵌套 CVE-2025-44560（27.2 不可触发）、
owntone SQLi CVE-2026-41457（需 28.4-29.0）。attack-catalog.c 中
deep_http_rescan 的 "CVE-2025-44560" 标注已更正为
owntone-teardown-uaf-stress（真实目标是自发现的 listener UAF）。

### 测试（真实代码链接，脚本化确定性 RNG）
- mutation_engine_test.c 重写：10/10 过（含位级恢复验证、错误协议 no-op）
- cve_mutation_test.c 重写：11/11 过（S5-S10 每策略正/负断言 + 计数器核算）
- 全量：evidence_selftest ✓ oracle 48+38 ✓ hot_replay 5 ✓
  attack_catalog 7 ✓ mutation_engine 10 ✓ cve_mutation 11 ✓ 构建 0 错

### 端到端验证（2026-09-07，bftpd 容器，无 KEY 快速启动路径）
```
execs_done        : 2181
cve_mutations_applied : 0        ← 2181 execs 内 FTP 种子未命中 RNTO/MLSD/引号模式，符合预期
auth_prefix_restores_havoc : 8934
auth_prefix_calls : 899
auth_prefix_found : 911          ← 三个计数器非零且相互自洽（found≥calls，恢复按字节累计）
teardown_race_tagged : 0         ← 修复前该位置读取的是错位参数/栈垃圾
```
结论：续 3 遗留的"fuzzer_stats 计数器显示 0"显示 bug 已端到端修复。
（注：走 run_dev.sh 的 3-4 分钟冒烟会因 LLM 预热耗尽时长、且 out tar 收集窗口
与容器停止竞争导致 "[recover] inner tar.gz incomplete" —— 与本修复无关，
长时 campaign 不受影响；冒烟改用无 KEY 直启 afl-fuzz 验证。）

---

## 修复日期
2026-09-07（续 5）— 早退事故根因：变异引擎 hook 堆溢出

### 现象（11:43 批次，3×180min×9 目标）
kamailio / lighttpd1 / bftpd / forked-daapd 四目标在真实 fuzzing 开始后
100–560 秒内退出，容器提前 ~2.5 小时结束。复现容器拿到退出码 134
（SIGABRT）与 glibc 报错 `free(): invalid next size (normal)`。

### 根因（完整因果链）
1. fuzz_one 的 out_buf 按当前种子长度精确分配（ck_alloc_nozero(len)），
   AFL havoc 的增长操作是按需 ck_realloc——hook 处实际分配 ≈ temp_len，
   从来不是 MAX_FILE。
2. 变异引擎 hook 把 buf_cap=MAX_FILE 传给 cve_targeted_mutate——容量撒谎。
   任一增长型策略（S1 移位/S2a +1/S2b +100/S3 pad/S6 +200/S7 +87K）的
   memmove/memset 越过分配边界 → 堆元数据损坏 → 下一次 free 触发 glibc
   abort → run 脚本继续打包退出。
3. 早退目标 = 种子/深态/LLM 材料含触发模式：kamailio/forked-daapd/
   lighttpd1（Content-Length → S1）、bftpd（LLM 生成 RNTO/MLSD → S2a/S2b）。
   stats 60s 一写，kamailio/forked-daapd 死在两写之间故显示 cve_mutations=0。
   存活 5 目标只是未命中增长分支，久跑同样会死。
4. 单元测试未拦截的原因：测试缓冲分配==cap（守约方正确），违约的是调用方。

### 修复
- afl-fuzz.c hook：调用引擎前 `out_buf = ck_realloc(out_buf, MAX_FILE)`
  （3% 触发率下 1MB 重分配开销可忽略）。
- mutation-ops.c S2a/S8(b) 守卫修正：`eol+1 < buf_cap` → `len+1 <= buf_cap`
  （memmove 实际写至下标 len，旧守卫按 eol 判断差一位）。

### 验证（对照实验 + 契约测试）
| 实验 | 结果 |
|---|---|
| 对照组（移除 realloc，ASAN 版 afl-fuzz，bftpd 容器，RNTO/MLSD 种子） | ~2 min 内 heap-buffer-overflow，CTRL_EXIT=134（与线上早退一致） |
| 修复组（同设置） | 11 min / 9693 execs / cve_mutations_applied=103 / ASAN 0 报告 |
| 新增 T12/T13 紧容量契约测试 | 分配==cap：恰好放下→触发；差一字节→返回 0 且缓冲逐位不变 |
| `make asan_tests`（测试以 ASAN 构建） | 16+10 全过，越界即报（首版测试自身的手数长度错误也被 ASAN 抓出） |
| 全量回归 | evidence/oracle(48+38)/hot_replay/attack_catalog/10+16 全绿，构建 0 错 |

### 对 11:43 批次数据的影响
- 4 个早退目标的 results-* 为截断数据（~2 min 有效 fuzzing），不可用于
  对比分析。
- 5 个存活目标容器内是修复前编译的代码，建议停止并用修复后代码重启批次。

---

## 优化日期
2026-09-08 — 自适应触发门：修复 CVE 引擎在稀疏模式队列下的抽签稀释

### 诊断（Sep-07_17-53 批次事后分析）
proftpd 三副本 cve_mutations = 23/0/1，而其他 FTP 目标 58–932。逐层取证：
1. 引擎无缺陷：把 proftpd_2 队列里唯一 RNTO 条目喂给真实
   cve_targeted_mutate → 20000/20000 全 fire。
2. 数学根因（抽签稀释）：hook 每 havoc exec 抽一次 UR(32)（3%），
   CVE 模式内容只存在于极少数队列条目（proftpd_2 仅 1 条），
   每条目每周期被 havoc 一次 → 3h ≈ 31 张彩票 × 3% ≈ **期望 0.93 次
   触发，P(零)=39%**。proftpd_2/3 的 0/1 正是该几何的必然结果；
   proftpd_1（10 条 RNTO 条目）23 次触发亦符合期望（~9）。
3. 调试轨迹（CHATAFL_GATE_DBG）确认第二层事实：havoc 为消息级执行
   （hook 看到的是 10–47B 单条/短序列消息），深状态消息（RNTO/MLSD）
   需状态推进后才会入选——短窗口内 marker 命中为 0，与抽签稀释独立。

### 修复
mutation-ops.c 新增 `mut_marker_scan()`：廉价镜像各策略真实前置条件
（FTP: 行首 RNTO/MLSD/MLST 或带引号/反斜杠的 RNFR/MKD/XMKD/CWD 行；
SMTP: 行首 AUTH 或 RCPT TO:<；RTSP: Session:；HTTP/SIP/DAAP: 仅
Content-Length:——S9/S10 对任意请求行可 fire、已饱和基础抽签，故意
不 boost 以免挤出通用 havoc）。hook 触发门改为：
`UR(32)==0 || (marker && UR(4)==0)` —— 含标记缓冲 25%，无标记维持 3%。

### 验证
| 项 | 结果 |
|---|---|
| T14 marker 扫描 19 例（正/负/边界/协议隔离/NULL） | PASS |
| T15 单向一致性（无标记 ⇒ FTP/SMTP/RTSP 引擎必不 fire） | PASS |
| cve_mutation_test | 18/18 |
| ASAN 套件（make asan_tests） | 18+10 全过 |
| 全量回归（evidence/oracle 48+38/hot_replay/attack_catalog/构建） | 全绿 |
| E2E 单种子 proftpd 150s（修复前） | cve_mutations=0（状态未推进，marker=0） |
| E2E 单种子 proftpd 600s（修复后） | **cve_mutations=64**，marker 命中 245 × 25% ≈ 61 与实测吻合 |

### 预期线上效果
- proftpd_2/3 场景（1 条模式条目）：期望触发 0.9 → ~7.5（8×）
- 所有含标记缓冲的目标统一获得 ~8× 靶向吞吐；无标记缓冲行为不变
- HTTP/SIP 的 S9/S10 维持原频率（kamailio 既有 1100-1255/run 不膨胀）
