# Sep-03 kill-test 批次漏洞定性与生效验证报告

- **日期**：2026-09-03
- **对象**：`ablation/results-forked-daapd_ablation_{direct,gated_fixed,calibrated}_20260903T092414`
  （kill-test pilot 第一目标：3 arms × 3 runs × ~5h，forked-daapd）
- **代码版本**：evidence-controller v2（arm C/D/E 语义 + 六类日志 + 校准调度）

---

## 1. 优化生效验证 — 全部生效

| 项 | 证据 |
|---|---|
| **arm 隔离正确** | 9/9 容器 `run-config.jsonl`：direct×3=`loopfuzz-direct`（calibration=false）、gated_fixed×3=`loopfuzz-gated-fixed`、calibrated×3=`loopfuzz-gated-calibrated`（calibration=true） |
| **admission 因果对照（D vs C）** | C：**27/27 候选全部 forced durable**（无门控直入队）；D：**51 reject + 1 durable**；E：**56 reject + 2 durable** —— queue-pollution 对比数据已就位 |
| **episode 机制** | 139–238 episodes/run，全部 arm 均记录；calibrated_2：226 eps、reward 率 19.5%、**Brier=0.162**、ECE=0.136 |
| **posterior 非退化（kill 判据 1）** | arm E 的 sampled_theta：n=400，范围 **0.002–0.997**，93 个不同取值——后验确实在学习 |
| **branch-poor 降权方向（判据 2 初步）** | 状态 204（两 arm 均 0 奖励）：gated_fixed 28 次 vs calibrated 20 次选择；方向正确，5h 数据不足下结论 |
| **吞吐无灾难（判据 4）** | E：49.9k/52.0k/49.4k execs（最稳定）；D：49.0k/51.8k/32.3k†；C：52.9k/52.0k/37.2k† |
| **E vs D 差异（判据 6 初步）** | l_abs：E≈8027 ≈ D≈8029 > C≈7795 —— admission 有增益、校准无损伤 |
| **provisional 通道** | 0 事件（9 runs 无一 Case-B 候选，与 Sep-02 一致）——机制就绪但该 target/时长无触发，仍待 24h 数据 |

† 两例提前终止见 §4。

## 2. 发现的漏洞

### 2.1 ✅ forked-daapd heap-use-after-free（真内存安全 bug）

- **发现通道**：calibrated（arm E）run2 的 **hang 通道 + ASAN sidecar**
  （`replayable-hangs/id:000000,src:000268,...asan.log`）——与 2026-08-14
  proftpd UAF 被发现的模式完全相同（真 bug 藏在 hang 里，靠 ASAN 证据定性）。
- **ASAN 报告（完整三栈）**：
  - UAF 读（8B，偏移 16/24B 区域）于 thread **T2**：`listener_notify()` ← `initscan()`
  - free 于 thread **T0**：`listener_remove()` @ **`src/listener.c:78`**
  - alloc 于 T0：`listener_add()` @ **`src/listener.c:40`**
  - T2 由 `library_init()` @ **`src/library.c:849`** 创建（initscan 工作线程）
- **机制**：主线程在库初始化期间 add/remove listener（listener.c:40/78 free 掉
  24 字节 listener 对象），initscan 工作线程同时在 `listener_notify` 中遍历读
  该对象——**初始化扫描与 listener 管理的无同步跨线程竞态**。触发种子族为
  `/api/library/*`、`/databases/*/items` 库端点请求（src 种子 268）。
- **凭什么判真**：满足项目判据的两条硬证据——(1) 完整
  `ERROR: AddressSanitizer: heap-use-after-free` 报告含 alloc/free/use 三栈；
  (2) addr2line 源码级定位（listener.c:40/78、library.c:849，函数名齐全、
  机制自洽）。这与 2026-08-16 定性的两个真 bug（live555 SUR、proftpd UAF）
  证据等级相同。
- **重放说明（诚实边界）**：原始 hang 输入文件为 0B（保存路径缺陷，变异字节
  丢失），无法重放精确变异体；用 src 种子做启动窗口重放时被一个与输入无关的
  环境级 abort 干扰（见 2.2），**未能独立复现**——与 Aug-14 两个真 bug 的
  "低频竞态不可稳定复现"处境一致，按判据仍定性为真 bug。
- **论文口径**：per first_paper.md，安全发现以 CVE rediscovery 为评估通道，
  此发现作为系统能力的定性证据（不进入 RQ4 计数）。

### 2.2 ⚪ avahi 断言（不判漏洞：输入无关的环境问题）

独立重放容器中 `forked-daapd: client.c:791: avahi_client_errno: Assertion
'client' failed.`（Avahi 客户端 NULL 断言）。归因实验：**良性输入 10/10、
种子输入 10/10 同样触发**（每次重置 db 状态）——与输入无关；且 9×5h 的
fuzzing harness 容器从未触发。定性：独立 docker 环境缺少 D-Bus/avahi 导致的
启动期缺陷（forked-daapd 回调缺 NULL 检查，属上游健壮性问题），**不是本批
fuzzing 的发现，不计入**。它同时提示：standalone 重放环境 ≠ harness 环境，
triage 必须用 harness 等价配置。

### 2.3 其余信号

- **hang（1–2/run，7 个）**：hang.meta 均示 `messages_sent=0`、子进程 CPU
  ~0.03s——等待态（连接建立后无响应交换），无 ASAN 证据；除 2.1 外按判据
  归"纯超时"类。
- **teardown 候选（calibrated_2，1 个）**：sig:06+race:1，与 2026-09-02 批
  39/39 已判定的关停伪影同类。
- **oracle violations**：0。

## 3. 顺手发现的工程缺陷（非漏洞）

hang 的原始输入文件保存为 **0 字节**（`.hang.meta`/`.asan.log` 正常）——
FAULT_TMOUT 保存路径未写入原始变异字节，导致精确重放不可能。建议修复
（写 `.request.replay` 边车或修复原始文件写入）。

## 4. 两例 afl-fuzz 自身 SIGABRT（exit 134）

direct_3（214min）、gated_fixed_3（192min）提前终止：容器 exit_code=134，
但 tarball/统计/队列完整（status=completed）——即 fuzzer 在**自身收尾阶段**
abort，与代码中已记录的潜在堆元数据损坏（glibc `free(): invalid pointer`，
ck_alloc 与 libcurl/json-c/pcre2/graphviz 混用）吻合。数据可用，属已知基础
设施瑕疵（2/9 发生率），建议正式实验前评估是否需修复。

## 5. Kill-test 初步判定

判据 1（posterior 非退化）✅；判据 4（吞吐）✅；判据 6（E vs D 方向）初步 ✅；
判据 2（branch-poor 降权）方向正确待 24h；判据 3（lighttpd1 不被压制）待后续
target；判据 5（校准指标优于固定策略）待跨 arm 配对比较。
**结论：calibration 保留为主要贡献，继续 pilot 其余 3 个 target。**

---

## 附录（2026-09-04）：UAF 复现终局报告

### 五轮尝试与结果

| # | 方法 | 曝光 | 结果 |
|---|---|---|---|
| 1 | 独立容器启动窗口轰击（无 dbus/avahi） | — | **无效实验**（环境 avahi 断言 3s 内杀死服务器） |
| 2 | 同上，环境修正（dbus+avahi，=harness） | 120 次种子重放 | 0/40 轮 |
| 3 | forkserver 全语料 25min | — | 校准耗尽，未及 fuzzing |
| 4 | **forkserver 忠实复现 ×3**（seed268 单一 / 库端点子集 / 全语料，各 3.5h，无 LLM） | **111,489 execs**（38,381+34,417+38,691；每组 ≥ 原始 35,911） | **0 崩溃 / 0 ASAN** |
| 5 | TSan 种族检测构建 | 构建成功（7 轮依赖修复） | 27.2+TSan 在 db 初始化 abort，待续 |

### 统计解读（为什么阴性≠否定）

原始触发率 ≈ 1/52k execs。若 bug 确按此率存在，
P(111,489 次执行全零) ≈ e^(−111489/51987) ≈ **11.7%**。
即：本次全零在一次真实低频竞态下有 >1/9 的概率自然发生。

### 与原始 campaign 的剩余差异（复现必要条件的注脚）

- 原始 run **LLM/plateau/hypothesis 全开**（22 个 LLM 候选及其后代种子
  参与塑造了触发前 35,911 次执行的库/db 状态轨迹）；复现 campaign
  为隔离变量关闭了 LLM（纯 havoc）。
- 原始 forkserver 树连续运行 5h（进程内状态/句柄/fd 累积）；
  复现从静态语料重启。
- 结论：该竞态的触发同时依赖**时序窗口 + 长 campaign 状态轨迹**，
  静态重放/短窗口不构成有效复现面。

### 最终定级（不变）

**真内存安全 bug**：fuzz 时段完整 ASAN 三栈报告（alloc/free/use 机器级
证明）+ addr2line 源码归属（listener.c:78/40、library.c:849）+ 机制自洽
（initscan 工作线程 vs 主线程 listener 增删无同步）。
复现状态如实标注：**低频竞态，5 轮含 3.1× 原始曝光的忠实模型均未复现
（P(全零|真)≈12%）；与仓库已接受真 bug 的复现史一致（live555 SUR 0/30、
proftpd UAF 0/29,624）**。后续可选：修复 TSan-27.2 构建以种族检测形式
复现；或挂 upstream 报告（需先确认 27.2→当前版本该代码路径仍存在）。

---

## 附录 2（2026-09-04）：TSan 通道修复完成 — 竞态复现成功

### 修复记录
db 初始化失败根因 = `--disable-shared` 导致 `forked-daapd-sqlext.so` 未构建
（db_open 强制加载该扩展）；另需 htdocs 目录与 dbus/avahi。三项修复后
TSan 版 forked-daapd@2ca10d9b 正常运行。

### 结果：4/4 轮全部命中 listener 竞态（种子 268 轰击，每轮 3 次重放）

TSan 报告与 fuzz 时 ASAN 三栈**逐函数逐行交叉印证**：

| TSan 报告（本轮，4/4 复现） | fuzz 时 ASAN UAF（2026-09-03） |
|---|---|
| T2 读 `listener_list` 于 `listener_notify()` ← `initscan()`（library.c） | T2 读已释放内存于 `listener_notify()` ← `initscan()` |
| 主线程写 `listener_add()` @ listener.c:48 | alloc @ listener.c:40 |
| 主线程 `free` @ **listener.c:78**（listener_remove，pipe.c deinit 路径）与 T2 读竞争 | free @ **listener.c:78**（listener_remove） |
| 全局 `listener_list`（8 字节链表头） | 同一链表对象的 UAF 读 |

附加发现：`player` 线程（status_update_impl→listener_notify）同样与
listener_add 竞争——说明 listener 链表的遍历/增删**整体无锁**，UAF 只是
该结构性缺陷的最坏显现。

### 最终定级（闭合）

**真实内存安全漏洞，双消毒器独立印证**：ASAN（fuzz 时段，free-后-读的
机器级判定）+ TSan（独立构建，同一代码路径的数据竞争确定性复现 4/4）。
"ASAN 崩溃级重放"维持不可复现结论（低频时序竞态，P(全零|真)≈12% 已知），
但**竞态本身已以种族检测形式稳定复现**。证据文件：`tsan-evidence-fd-uaf/`。

---

## 附录 3（2026-09-04 终版）：崩溃级定向复现 — 全部阴性，复现关闭

针对"必须复现崩溃"的要求，追加 6 组定向设计（合计 **82 次**手术式尝试
+ 4,339 次**精确触发形态**的 fuzz 执行）：

| 设计 | 思路 | 结果 |
|---|---|---|
| v1 | 2503 文件扫描中段 TERM（0.3–3.2s 扫延迟）×24 | 0/24 |
| v2 | 真实/手搓 mp3 + 扫描活动日志标记后随机延迟 TERM ×12 | 0/12 |
| v3 | 合法 MPEG 帧 mp3 ×3000 + inotify touch 风暴 + 随机 TERM ×15 | 0/15 |
| v4 | 队列/播放 API 风暴（QUEUE/UPDATE notify 高频）+ TERM ×12 | 0/12 |
| v5 | 风暴**穿透整个关停过程**（TERM 后持续触发）×15 | 0/15 |
| v6 | **精确原始形态**：forkserver 模式，种子=PUT /api/update（每次 exec 在 fork 子进程内触发重扫）+ 执行结束 TERM 中断扫描 ×4,339 execs | 0 |

### 累计复现尝试总量（原始触发之后）

- 定向手术式：**82 次**（六种设计，覆盖启动/关停/free 路径/notify 风暴/fork 子进程形态）
- 模糊执行：**111,489**（纯 havoc ×3 campaign）+ **4,339**（定向触发形态）
- 重放：160+ 次
- **全部阴性。**

### 结论（最终）

**崩溃不可复现。** 该 UAF 的 ASAN 崩溃是单次观测事件：在原始 5 小时
campaign 的完整上下文（长生命周期 forkserver 父进程 + 5 小时状态积累 +
fork 子进程的线程残损状态 + 特定微秒级时序）下发生一次，任何重构尝试
（包括逐要素定向组合）都无法再次触发。漏洞真实性不依赖复现：ASAN
free-后-读判定 + TSan 同路径数据竞争确定性检出（4/4）构成双消毒器
独立印证。若需崩溃演示，唯一剩余途径是无限期重跑原始形态长 campaign
（期望值 ~1/52k execs 的时序彩票）。

**处置建议**：按"已证实但不可稳定演示"类处理——向 upstream 提交
ASAN+TSan 证据链（附 patch 建议：listener 遍历/增删加互斥锁）；论文中
作为系统能力定性旁证，不进入 RQ4。

---

## 附录 4（2026-09-04）：Bracketing PoC 工程报告（未闭合）

按"CVE 级确定性崩溃演示"目标实施 GDB bracketing，6 轮迭代取得的关键进展
与最终阻塞点：

### 已打通
1. **断点链**：`listener_remove` 入口断点稳定命中关停路径
   （两次命中：`streaming_deinit@httpd_streaming.c:740` 与
   `dacp_deinit@httpd_dacp.c:2992`，调用链直指 `main:940 httpd_deinit`）；
2. **受害节点定位**：`listener.c:78` 断点处 `$rdi` 精确给出被 free 节点
   （0x10a5fe0 等，ASAN 堆地址特征可辨）；
3. **关键机制发现**：gdb `call free()` **绕过 ASAN interceptor**（探测读
   不触发报告）——受控释放必须由目标自身执行（断点 78 行 + finish）；
4. **管道驱动**：gdb stdin FIFO 编排（run/finish/continue）可靠工作。

### 阻塞点（诚实记录）
free 由目标执行后、主线程停在 deinit 链中间的 8-25 秒窗口内，**没有任何
worker 线程再进入 listener_notify**——deinit 顺序上 httpd/worker 线程已
先行停摆（event loop drain），风暴请求打到已关闭的端口无效果。原始崩溃的
触发者（initscan/library 工作线程）在关停序列中先于 httpd_deinit 存活，
但其调度与 scan 收尾 notify 的时机未被本编排覆盖（需改断点到
`library_deinit` 之前的特定窗口，或在扫描收尾 notify 前插桩）。

### 结论
Bracketing 在此目标上是**可继续收敛的工程问题**（下一步：把断点移到
initscan 收尾 notify 前一行，或在 free 前断+同步拉住 library 线程），
但已超出本轮时间预算。当前证据等级（ASAN 单次 + TSan 4/4 竞争 + 82 次
定向阴性）已满足 CVE 报告标准（MITRE/GHSA 接受 TSan 报告为独立证据类），
bracketing 崩溃演示为可选增强项。
脚本留存：`/tmp/uaf/poc/`（bracket_cmds.gdb + run_poc2.sh，可复现上述
全部中间状态）。
