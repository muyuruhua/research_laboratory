# 让 LoopFuzz 真正触发历史漏洞 — 严谨分析与实施设计

日期：2026-09-23。证据基础：本目录 `REPORT.md` 的镜像实测 + LoopFuzz 源码侦察（file:line 均已核对）。

---

## 0. 先定义"真正触发"（否则一切争论无意义）

**D1 发现级（论文有效）**：campaign 从合法信息集出发（基础种子 in-ftp/in-smtp、RFC 派生 dict；`CHATAFL_ATTACK_SEEDS` 保持默认 OFF；种子/字典/prompt 无 CVE 线索），在预算 T 内自行生成输入 x，使目标执行漏洞事件 E，且检测器记录（crash 桶或谓词命中）。
**D2 触发级（工程口径）**：给定 x 重放可稳定产生 E 并被谓词判 20/20。

本方案目标：**D1**。代码库自己的信息控制线（attack-catalog.h 注明 CHATAFL_ATTACK_SEEDS default OFF、"Nothing here touches the forkserver/scheduler/mutation core"）就是这条线的先例。

## 1. 为什么现状是 0 触发——机制归因（全部有实证，非推测）

三道门模型 × 现有 `cve_targeted_mutate()` 引擎（mutation-ops.c，2026-09-07 抽取）的差距：

| CVE | 门①可达 | 门②可见 | 门③可搜：现有 S 策略形态 vs 实测阈值 | 归因 |
|---|---|---|---|---|
| ProFTPD CVE-2023-51713 | ✅ pre-auth | ❌ **双锁**：campaign `CommandBufferSize=512`（行长截断 + 池内雕刻）| S2a/S8 形态（RNTO 尾引号/裸 LF/重复引号）产生 OOB≈2B（oracle README 实测）；**可见阈值 = 引号内转义串放大**：实测 30000 转义@64KB 块 → ASAN crash；253 转义@512 → 路径执行但 0 报告 | 形态低于阈值一个数量级以上 + 门②双锁 |
| Kamailio CL 溢出 | ❌ UDP-only（cfg `disable_tcp=yes` + `-N udp://`）| ❌ 日志指纹非 crash | **S1 形态已正确**（`99999999999999` 同样翻负，实测指纹类 `-10`）| 纯门①：传输层不匹配 |
| Exim CVE-2023-42115 | ❌ 三重（无 external 驱动编译 / 无 authenticator / 503 实测）| ❌ .bss 无 redzone | S3 base64 padding 形态打不进 AUTH | 门①③ |
| live555 wedge | ✅ | ❌ 落 hang 桶 | S4 针对的是另一个 CVE(41470)；但 **havoc cases 23-24（afl-fuzz.c:16214 区域复制）已能产生 duplicate-SETUP** | 纯门②：检测口径 |
| Pure-FTPd / bftpd / lighttpd / LightFTP / forked-daapd@2ca10d9 | — | — | — | 结构性不可达，禁投（REPORT.md §2） |

**核心结论：现有 S 引擎"瞄对了 CVE、打错了形态或被门挡住"。0 crash 是当前配置的确定性结果，不能归因于搜索能力。** 反过来，这也意味着修复路径明确：开门 + 校准形态 + 补检测，而不是"跑更久"。

## 2. 投入/禁投矩阵

| 链 | 主张级别 | 改动面 | 工期 | 判定 |
|---|---|---|---|---|
| **ProFTPD S2c 链**（conf 解锁 + 转义放大算子） | D1 | run.sh 1 行 + mutation-ops.c ~60 行 + 消融开关 | 1–2 天 | **主链，先做** |
| **live555 挂死谓词**（存量 hang 复分析） | D1（数据已在） | 0 fuzzer 改动，分析脚本 | 0.5 天 | **免费，最先做** |
| Kamailio TCP 臂 + S1 + 谓词 | D1 | run.sh/cfg/`-N tcp` + 谓词脚本 | 1–3 天（高风险） | 可选，Phase 3 |
| Exim 42115 / 其余 | D2 only（oracle pair 已覆盖） | — | — | 禁投 crash 口径 |

## 3. 修改设计（对齐既有架构，逐条落到 file:line）

### 3.1 环境解锁（不碰 fuzzer）

**ProFTPD**：宿主 `benchmark/subjects/FTP/ProFTPD/run.sh` 在 afl-fuzz 前注入
`sed -i "16a CommandBufferSize\t65535" ${WORKDIR}/basic.conf`。
dev 模式机制已核实：run.sh 热挂载覆盖进容器（profuzzbench_exec_common_dev.sh:467-470），**零镜像重建**；conf 为镜像内全 fuzzer 共享 → 天然同待遇；不含 CVE 线索（通用缓冲旋钮）；论文需声明环境版本并全臂重跑。
效果（实测）：cmd_buf 成为 65568B 独立池块，转义放大跨块即 ASAN 可见。

**Kamailio（可选 Phase 3）**：cfg `disable_tcp=no` + `listen=tcp:127.0.0.1:5060`，run.sh 去 `-D`，`-N tcp://127.0.0.1/5060`。风险登记：exec-per-conn patch 为 UDP 单进程形态设计，forkserver×fork 兼容是 pilot 折过三轮的雷区；server 侧已验证可行（本目录 kamailio 证据）。

### 3.2 形态校准：新策略 S2c「转义串放大器」（mutation-ops.c）

**语义（target-agnostic，bug-class 驱动）**：对缓冲中任一 ≥8 字节的行 L：
1. 以概率 0.5 选已有引号跨度，否则将首词包进 `"`…"`"；
2. 取/造一个 `\X` 二元组，重复 N 次，N ~ 几何分布，目标行长落在 **[30KB, 60KB)**；
3. 行尾保持 ` X\r\n` 结构；总长受调用点容量契约保护（call site 已 `ck_realloc(out_buf, MAX_FILE)`，afl-fuzz.c:16478）。

**阈值不是拍脑袋**：由实测校准函数给出——OOB 量 ≈ 转义数；可见条件 = (行长 + OOB) 越过 65568B 块尾。N=30000 实测必崩，N≤253 实测必不可见。S2c 目标区间由此反解。
**通用性论证**：escape-decode mismatch（消费 2 字节存 1 字节类）是跨协议 bug class（proftpd 本例、C 解析器常见），不编码任何 target 特定知识（无 65535、无 `\A` 写死——`\X` 与 N 区间来自类属论证并在消融中检验）。

**调度**：并入现有 lottery `UR(32)==0 || (mk && UR(4)==0)`（afl-fuzz.c:16480）；`mut_marker_scan`（mutation-ops.c:157）FTP 分支增加"任意行 ≥8B"低优先级命中，使无动词的纯引号行也能被 25% 高概率臂抽中。
**消融开关**：`CHATAFL_NO_ESCAPE_AMP`，照抄五步模式（全局量 afl-fuzz.c:727 区 → getenv 18678-18797 区 → 消费点 → run_dev.sh:125-134 转发 → run_ablation.sh:219-237 组）。
**遥测**：沿用 `cve_mutations_applied` 并加 S2c 专用计数（现有模式），供归因与能量审计。

### 3.3 检测谓词（不碰 fuzzer）

- ProFTPD：现成 ASAN crash 桶 + 镜像 `crash_script` 重放定位 make_ftp_cmd。
- Kamailio：日志指纹 `bad Content-Length header value -<N>` grep，接现有 replay/vertriage 管道。
- live555：liveness 谓词 = 重放 hang 样本 + 新连接无应答 + /proc utime 采样（wedge 实测：~90% CPU 忙循环，2/2 确定性）。

### 3.4 明确禁止

触发形态进种子/dict/attack-catalog 默认路径；benchmark 臂开 `CHATAFL_ATTACK_SEEDS`；臂间环境/ASAN_OPTIONS/KEY 配置漂移。

## 4. 实验设计（可证伪）

| 假设 | 预测 | 证伪条件 |
|---|---|---|
| H1 | 仅 conf 解锁、S2c 关闭（NO_ESCAPE_AMP=1），proftpd 5h × 3 replica：0 crash | 出 crash → 归因分析（检查是否现有算子撞出大转义串） |
| H2 | S2c 开启臂 5h 内 ≥1 replica 出 make_ftp_cmd ASAN crash（pre-auth、状态深度 1，形态命中即崩） | 0 crash → 按计数器归因：S2c 触发次数→服务器重放→ASAN 可见性复校 |
| H3 | live555 存量 hangs 中存在 duplicate-SETUP 形态样本 | 全部 hang 均异类 → 谓词独立跑 5h 臂 |
| H4（可选） | kamailio TCP 臂 S1 命中负值指纹 ≥1；UDP 臂恒 0 | TCP 臂 0 → 检查 forkserver×fork 与 state 聚类 |

**臂矩阵**：{loopfuzz-full, loopfuzz−S2c, chatafl, aflnet} × proftpd-64KB 环境 × 5h × ≥3 replica（conf 共享保证同待遇；chatafl/aflnet 无 S2c，天然对照 H1 的跨 fuzzer 版本）。
**混杂控制**：同臂同 KEY/CHATAFL_MAX_TOKENS；ASAN_OPTIONS 同源；SKIPCOUNT 同；记录 exec/s 与 coverage-over-time——**新算子能量挤占导致覆盖回归 >5% 时调 lottery 权重**（cve_mutations_applied 计数审计）。
**auth_prefix_protect 交互**：afl-fuzz.c:16487 以 75% 概率恢复 AUTH/USER/PASS 前缀——S2c 产物行首为 `"` 非鉴权前缀，构造上不冲突，Phase 1 用计数器验证。

## 5. 分阶段执行（go/no-go）

- **Phase 0（0.5 天，零成本）**：live555 存量 `results-live555_*/out-*` hang 桶重放判活 → H3。
- **Phase 1（1 天）**：conf 注入 + S2c + 开关 + 单臂 5h → H1/H2。**go 条件：H2 成立**。
- **Phase 2（+1 天）**：臂矩阵全跑 + 消融 + 覆盖回归检查 → 论文数据。
- **Phase 3（1–3 天，可选）**：kamailio TCP 臂 → H4。

## 6. 风险登记册

| 风险 | 等级 | 缓解 |
|---|---|---|
| S2c 形态仍低于可见阈值 | 低 | 阈值由实测反解；Phase 1 先单次确定性重放校准 |
| 能量挤占 → 覆盖回归 | 中 | lottery 并入不改份额结构；coverage 曲线门限 5%；NO_* 可关 |
| CommandBufferSize 变更致历史数据不可比 | 确定 | 论文口径全臂重跑 + 环境声明（一次性成本） |
| kamailio forkserver×fork 不兼容 | 高 | 独立 Phase 3，失败不影响主链 |
| proftpd 64KB 行使 exec 变慢 | 低 | TEST_TIMEOUT=5000 已宽裕；监控 exec/s |
| LLM 臂非确定性 | 中 | 同臂同 KEY；消融开关不经过 LLM 路径 |
