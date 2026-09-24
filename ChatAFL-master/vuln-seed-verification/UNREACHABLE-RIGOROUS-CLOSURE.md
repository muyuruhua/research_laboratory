# 其他协议"不可达"的严谨解决报告

日期：2026-09-24。方法：对每个 target 做门级诊断（可达/可见/可搜），能解锁的做工程解锁并实测，不能解锁的给源码级证明。

## 总表（本轮更新后）

| Target | 门级诊断 | 本轮处置 | 结论 |
|---|---|---|---|
| **Kamailio** CL 溢出 | 唯一阻塞 = 传输层（UDP-only） | ✅ **TCP 臂工程解锁并实测跑通** | 可达，需 predicate 检测 |
| **live555** CVE-2023-37117 | 漏洞输入 = .mkv 文件字节 | ✅ 修复版源码 diff 闭环证明 | **结构性不可达**（非 fuzzer 问题） |
| **bftpd** CVE-2025-11947 | 函数网络可达（USER 命令）但溢出输入 = 配置 GROUP 行 | ✅ 源码逐行分析 | **结构性不可达** |
| **pure-ftpd** CVE-2024-48208 | 行长上限 1024B vs 64KB 全局 cmd 缓冲 | 源码引证补齐（ftpd.c:5241 `char line[1024]`、globals.h:35 `cmd[PATH_MAX+32]`） | **结构性不可达** |
| **Exim** CVE-2023-42115 | 编译门（无 external 驱动，strings 实证）+ 配置门（503）+ 检测门（.bss） | 三重门，重编译也绕不过检测门 | 仅 oracle 谓词口径 |
| lighttpd / LightFTP / forked-daapd | 无适用 CVE / 竞态无修复 commit / commit 不带洞 | 维持注册表结论 | 不投 |

## 1. Kamailio TCP 臂 —— 解锁成功（本轮最大进展）

**阻塞机制实证**：basic.cfg `fork=no` + 启动参数 `-D` 强制单进程 → TCP 监听永不建立（`-D` 模式下 kamailio 不启动 tcp_main，实测 0 监听）；去掉 `-D` 后 kamailio **守护化**（master ppid=1）——担忧是 forkserver 生命周期破裂。

**实测结果**（campaign 二进制 + 真实 loopfuzz afl-fuzz）：
- cfg：`fork=yes` + `disable_tcp=no` + `listen=tcp:127.0.0.1:5060`；启动参数去 `-D`；exec 超时放宽 `-t 12000+`。
- **3118 execs / 202 paths / 无 PFATAL / ~28 execs/s**——守护化实例意外形成"持久服务器"形态：每 exec 新实例绑定失败快速退出，流量由长存守护实例服务，覆盖率经继承的 bitmap 正常回流，状态机正常学习。
- S1（Content-Length 溢出策略）开火 118 次，全部发往 TCP 读路径。
- **指纹命中实证**：对臂内活监听手工发送 11 位 CL → `bad Content-Length` 在捕获文件命中 1 次。fuzz 期的指纹被逐 exec 的 capture truncate 抹掉——**检测必须后置**：campaign 后对 queue/hangs 条目重放到独立 TCP kamailio，grep 负值指纹（复用 oracle 谓词管道）。

**改造清单（若正式入 benchmark）**：subjects/SIP/Kamailio/ 增加 TCP 版 cfg + run.sh 变体（去 -D、-t 12000+、-N tcp://），全 fuzzer 共享；加 predicate 重放脚本。

## 2. live555 CVE-2023-37117 —— 不可达的源码级证明

对比 2023.05.10（campaign 版）与修复后源码（GitHub 镜像 rgaufman/live555，含 2023.06.14 修复），安全相关 hunk 全部位于 **EBML 文件解析路径**：
- `parseEBMLVal_binary/string`：`unsigned` → `u_int64_t` 长度类型修复 + `constrainSize` 变体（防文件声明长度溢出缓冲）；
- track 编号守卫（`track->trackNumber == 0` 检查，防重复编号）。

这些修复消费的输入全部是 **.mkv 文件的 EBML 字节**。harness 的 test.mkv 是固定服务端内容；RTSP 客户端只经 URL 选择预解析的 track，任何客户端字节不进入该解析器。NVD 的 "while handling SETUP" 描述的是**时机**（首次 DESCRIBE/SETUP 才懒解析文件），不是**输入源**。

**结论：网络不可达是代码结构性的，与 fuzzer 能力无关。**（live555 的可发现物仍是我此前报告的 duplicate-SETUP 忙循环挂死——落 hang 桶，需 liveness 重放谓词计为发现。）

## 3. bftpd CVE-2025-11947 —— "函数可达、溢出输入不可达"

源码分析（bftpd 6.1 源码包）：`expand_groups()`（options.c:116）确实被 `command_user()`（commands.c:224）在 **USER 命令、pre-auth** 调用——函数本身网络可达，VulDB "Configuration component" 字面误导。但两个溢出点的输入均**不来自网络**：
1. `strcat(grp->temp_members, ",")` —— `temp_members` 由 config 文件 GROUP 行的成员列表构建；
2. `sscanf(temp_members, "%[^,]", foo)`，`foo[USERLEN+1=31]` —— 无界扫描的 token 同样来自 GROUP 行成员（>30 字符成员即栈溢出）。

网络用户名在 expand_groups 执行时**不流入**上述缓冲（成员匹配发生在其后的 login 路径）。且 campaign `basic.conf` 无任何 GROUP 指令（实测 grep=0）→ `config_groups == NULL` → 函数体直接跳过。**双保险不可达。**

## 4. pure-ftpd CVE-2024-48208 —— 常量级证明

`ftpd.c:5241` 命令行读取缓冲 `char line[1024]`（行长硬上限 1024B），漏洞扫描目标为 `globals.h:35` 的全局 `cmd[PATH_MAX+32]`（~64KB）。1024B 行的参数在 64KB 缓冲内必然先命中空白/NUL（oracle 四类实验 + 本目录复测一致）。无任何配置可改该上限。**不可达为常量级，除非改源码。** 注：S2c 现在每次 campaign 都在该目标上实证这一点（60KB 洪泛被 1024B 行截断，零 ASAN）。

## 5. Exim CVE-2023-42115 —— 三重门，重编译也绕不过第三重

strings 实证 campaign 二进制仅含 `plaintext` 驱动（external 未编译）；configure 无 authenticator（EHLO 无 AUTH、实测 503）；即使重编译+配置（镜像重建级改动），auth_vars[4..5] 越界写落 `.bss`，ASAN 无 redzone——crash 口径**永远不可见**，只有 gdb 硬件观察点谓词（oracle pair 已 20/20 验证）。**归 oracle 基准管辖，不属 campaign 范畴。**

## 6. 对"9 协议 campaign"的最终预期

- **proftpd**：CVE-2023-51713，S2c+conf+crash-grace 三修复已闭环（3 分钟 2 crash 实证）。
- **kamailio**：换 TCP 臂后可达；检测靠后置指纹重放。UDP 臂维持原行为（crash-grace 已按传输层门控，零回归）。
- **live555**：CVE 结构性不可达（本轮证明）；wedge 需 liveness 谓词才会被计为发现。
- **pure-ftpd / bftpd / exim**：结构性不可达或仅谓词口径（本轮源码级证明）。
- **lighttpd / LightFTP / forked-daapd**：无适用 CVE（维持注册表结论）。
- **全 target**：crash-grace 修复（TCP-only 1s）恢复所有被 SIGTERM 竞态吞掉的真实崩溃记录——这是不依赖任何 S2c 的普适增益。
