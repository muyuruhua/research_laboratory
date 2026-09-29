# 漏洞攻击构建 → LoopFuzz 模式整合 → 发现能力提升（最终报告）

日期：2026-09-24。目标：对 9 个待测协议构建攻击、验证后整合进 LoopFuzz。

## 1. 攻击库（4 类模式，全部构建并验证）

| 攻击模式 | 目标/漏洞 | 验证状态 | LoopFuzz 生成机制 |
|---|---|---|---|
| 引号内转义串放大 | proftpd CVE-2023-51713（CWE-125 堆越界读） | ✅ 51 crashes/4 副本，ASAN@make_ftp_cmd:862 | **S2c**（本会话整合） |
| 数值字段饱和（11 位 CL） | kamailio tcp_read_headers 有符号溢出 | ✅ 指纹 `bad Content-Length value -10` 命中 | **S1**（已有） |
| 同状态消息重复（duplicate-SETUP） | live555 忙循环/停摆挂死（新发现） | ✅ 2/2 wedge 复现 + 谓词 HIT | **havoc cases 23-24**（已有） |
| AUTH 多 NUL 变量 base64 | exim CVE-2023-42115 | ✅ oracle gdb 谓词命中（镜像内不可达） | **S3/S7**（已有） |

其余 5 个 target 无可构建攻击：纯常量/配置/输入面/版本窗口原因（见 UNREACHABLE-RIGOROUS-CLOSURE.md）。

## 2. 本轮整合：S11 泛化转义放大器

`mutation-ops.c`：S2c 重构为共享函数 `escape_amplify_apply()`，FTP 分支行为不变（单测 PASS），
新增 **S11 尾部调用**扩展到 SMTP/RTSP/SIP/HTTP/DAAP（排除 MQTT 二进制协议；排除表增加
EHLO/HELO 防与 auth_prefix_protect 产生混合体）。与 S2c 共享 `CHATAFL_NO_ESCAPE_AMP`
消融开关与 `escape_amp_applied` 计数。

实测：SMTP 单测（46KB 洪泛、前缀完好）；kamailio TCP 臂 110s：**escape_amp_applied=16**
（泛化前该协议恒为 0）、3414 execs 无异常；live555 110s：**开火 6 次**、1474 execs 无异常。
无已知在窗目标——属探索性类覆盖（转义解码失配类）。

## 3. 本轮整合：谓词重放检测层

`vuln-seed-verification/scripts/predicate_replay.py`（事后分析，零 fuzzer 改动，符合 info-control）：
- **kamailio 模式**：起 TCP cfg 容器 → 逐输入重放 → grep 负值 CL 指纹。
- **live555 模式**：逐输入重放（每文件重置服务器——wedge 是终态，复用会污染后续判定）→
  3 次耐心探测 + 进程存活检查 → 区分 wedge（停摆/忙转两模式）/crash/饥饿假死。

验证结果：
- kamailio：已知触发 **1/1 HIT**；**fuzz 生成的 queue 条目 3/4 HIT**（q0/q4/q9——110 秒
  campaign 中 S1 生成并入队的输入被正确计量为发现）。
- live555：wedge 种子 **HIT**（stall 模式标注）、良性对照 **PASS**；历史 campaign hang 样本
  0/15——正确解析长度前缀后确认其为负载伪影（与 Phase 0 结论一致，诚实记录）。

实现过程中修复的三个 bug（留档）：bytes repr 单引号截断 `python3 -c`（改 stdin 传脚本）；
`$(pgrep)` 在宿主 shell 双引号内提前展开（PID 先取再代入）；wedge 终态服务器复用导致
后续文件全部误报（live555 每文件重置）。

## 4. 发现能力提升的完整图景

LoopFuzz 现在在三层各有对应机制：
- **生成层**：S1（数值饱和）+ S2c/S11（转义放大）+ havoc 23-24（消息重复）+ S3/S7（AUTH 变体）
  ——四类攻击模式全部有生成器，其中两类跨协议泛化。
- **记录层**：crash-grace 修复（TCP 1s）——所有真实 ASAN 崩溃不再被 SIGTERM 竞态吞掉。
- **检测层**：谓词重放——crash 口径之外的逻辑/挂死类发现可计量（kamailio 指纹、live555 活性）。

## 5. 边界与后续

- exim 42115 保持三重门（编译/配置/.bss）——归 oracle 基准，crash 口径原理性不可见。
- live555 wedge 的"fuzzer 自行发现"需要更长 campaign（110s 未生成 duplicate-SETUP 形态；
  历史数据中的该形态样本是伪影）；谓词已就绪。
- 谓词脚本可扩展：加 lighttpd smuggling 差分、forked-daapd smartpl 谓词即可覆盖更多逻辑类。


## 6. 补缺更新（2026-09-24 晚）：4/4 模式全部确定性具备

### S12 lexer-killer 算子（`mutation-ops.c`）

- **语义**：在请求 URI 的随机位置注入毒模式——裸 `?` + `0x81` 高位字节 + `i`×[24,64) 长游程 + 尾部 `?`。bug 类：词法器错误恢复递归不返回（forked-daapd SMARTPL ANTLRv3 死锁实证 5/5）。
- **集成点**（单测暴露的真实缺陷后修正）：HTTP/DAAP 在 S10/S9 **之前** 25% 分流（S9 对请求行无条件拦截，尾部放置是死代码）；SIP 在尾部、排在无概率门的 S11 之前。消融开关 `CHATAFL_NO_LEXKILL`（afl-fuzz.c + run_dev.sh + exec 脚本全链路）、计数器 `lexkill_applied` 进 stats、`no_lexkill` 进 run-config。
- **验证**：三路单测 PASS（直接调用毒模式正确 / DAAP 引擎路径可达 seed=8 / SIP 尾部可达 seed=0）+ S2c 无回归；**端到端**：S12 真实代码生成的 3 个输入重放 forked-daapd → **2/3 死锁命中**（谓词判定 + lexer error 3/1 行——递归深度异于原种子 38 行但同类死锁；未命中者为注入位置落在非解析段的预期随机行为）。

### forked-daapd 谓词模式（`predicate_replay.py forked-daapd`）

- 每文件重置（dbus/avahi/服务器——SMARTPL 死锁是终态，复用会污染）；重放后 `/api/config` 三次耐心探测 + 进程存活检查（区分死锁/崩溃/饥饿）。
- 验证：原种子 **HIT**（38 lexer error 与 advisory 一致）、良性 `/api/config` **PASS**。

### 4/4 总表（生成器 × 检测口径）

| 模式 | 生成器 | 检测 |
|---|---|---|
| 转义放大（proftpd） | S2c | ASAN crash |
| 数值饱和（kamailio） | S1 | CL 指纹谓词 |
| 消息重复（live555） | havoc 23-24 | 活性谓词 |
| lexer-killer（forked-daapd） | **S12（本轮）** | **fd 谓词（本轮）** |
