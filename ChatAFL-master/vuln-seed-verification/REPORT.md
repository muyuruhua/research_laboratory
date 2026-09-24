# 历史 CVE 触发种子验证报告（campaign 镜像版本）

日期：2026-09-22　|　验证人：ZCode 会话　|　对象：`run_dev.sh` 所用 9 个 campaign 镜像

## 结论总表

| Target | 镜像版本 | 历史 CVE | 当前镜像可触发？ | 检测方式 | 证据 |
|---|---|---|---|---|---|
| ProFTPD | 61e621e (1.3.9rc1, ASAN) | CVE-2023-51713 (make_ftp_cmd OOB read, pre-auth) | **条件触发**：`CommandBufferSize 65535` 时 ASAN crash；**campaign 默认 512 不可见** | ASAN heap-buffer-overflow | `logs/pftp_asan_evidence.log` |
| Exim | d6a5a05b84 (4.96, ASAN) | CVE-2023-42115 (AUTH EXTERNAL auth_vars OOB write) | **否**（三重门） | 仅 gdb watchpoint（.bss 无 redzone） | `logs/exim_oracle_gdb_evidence.log` |
| Kamailio | a2209018fb | tcp_read_headers Content-Length 有符号溢出 | **TCP 形态可触发**；campaign 为 UDP-only，结构性不可达 | 日志指纹 `bad Content-Length header value -10` | `logs/kamailio_overflow_evidence.log` |
| Pure-FTPd | 10122d9f | CVE-2024-48208 (domlsd OOB read) | **否**（arg 落 64KB 全局 cmd 缓冲，扫描界内必命中空白） | 无（ASAN 盲） | oracle README 四类实验 + 本次复测 425/0 ASAN |
| live555 | live.2023.05.10 | CVE-2023-37117 (SETUP UAF) | **新发现：duplicate SETUP 同 track → 100% 忙循环挂死**（pre-auth DoS）；ASAN 不报 | 超时/挂死桶（非 crash） | 本报告 §5 |
| bftpd | 6.1 | CVE-2025-11947 (expand_groups 堆溢出) | **否**（Configuration 组件，非网络面） | — | [NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-11947) |
| lighttpd1 | 9f38b63 (1.4.71-dev) | CVE-2018-25103 只影响 ≤1.4.50；CVE-2025-12642 为逻辑型 smuggling | 内存安全类：**无适用** | — | [redmine](https://redmine.lighttpd.net) |
| LightFTP | 139af7c | 无满足约束 CVE（竞态/无修复 commit） | — | — | REGISTRY-PRIVATE.md |
| forked-daapd | 2ca10d9 | CVE-2025-44560 | **否**（该 commit ANTLR lexer 先拒，完整 PoC 0/5） | — | REGISTRY-PRIVATE.md |

## 1. ProFTPD CVE-2023-51713 — 已实证（campaign 镜像 + 官方修复前 commit）

- 种子：`seeds/pftp_cve-2023-51713_b64k.raw`（`"` + `\A`×30000 + `"` + ` X\r\n`，60006 B）
- campaign 默认 conf（CommandBufferSize=512）：路径执行（500 应答），**ASAN 0 报告**——OOB 留在池块内。
- 加 `CommandBufferSize 65535`：**ASAN heap-buffer-overflow, READ of size 1, 0 bytes right of 65568-byte region**，`addr2line` = `make_ftp_cmd main.c:862`（与 oracle 完全一致）。
- 小缓冲变体种子：`seeds/pftp_cve-2023-51713_b512.raw`（512 B，当前 conf 即可发送，用于证明"路径可达但不可见"）。

## 2. Exim CVE-2023-42115 — 三重不可达

1. **编译门**：campaign 构建 `strings` 仅见 `plaintext` 驱动，无 `external`（需 `AUTH_EXTERNAL=yes`）。
2. **配置门**：`/usr/exim/configure` 无任何启用 authenticator → EHLO 无 AUTH 能力，`AUTH EXTERNAL/PLAIN` 一律 `503 not advertised`（实测）。
3. **检测门**：auth_vars[4..5] 越界写落 `.bss`，ASAN 无 redzone——oracle 侧只能用 gdb 硬件观察点判 20/20（本次复跑 1 次命中：external.c:108 New value）。
- 种子：`seeds/exim_cve-2023-42115.raw`（EHLO + AUTH EXTERNAL b64("i1\0i2\0i3\0i4") + QUIT）。

## 3. Kamailio tcp_read_headers 溢出 — TCP 可触发、campaign UDP-only

- campaign `kamailio-basic.cfg`：`disable_tcp=yes` + `fork=no` + `-D -E` 启动 → 单进程 UDP recvfrom 形态，TCP 监听从未建立。
- 手工开启 TCP（cfg `disable_tcp=no` + `listen=tcp:127.0.0.1:5060`，去掉 `-D`）后：`Content-Length: 21474836470` → **`tcp_read_headers(): bad Content-Length header value -10 in state 24`**（有符号溢出指纹，campaign 二进制带洞实证）。
- 该形态无 ASAN 信号，只能日志判据；fuzzer harness `-N udp://…` 无法进入 TCP 读路径。

## 4. Pure-FTPd CVE-2024-48208 — 结构性不可达（复测一致）

登录 230 OK 后 `PASV` + `MLSD -AAAA…(4000)` → `425 No data connection`/正常流程，ASAN 0。与 oracle 四类实验（inetd/standalone、堆铺底、流水线残尾）结论一致：行长上限 ~4KB 的 arg 落在 64KB 全局 `cmd[]` 内，无 NUL 守卫的空白扫描总在界内命中。种子存档：`seeds/pureftp_cve-2024-48208_nontriggering.raw`。

## 5. live555 — 新发现：duplicate SETUP 忙循环挂死（CVE-2023-37117 相关形态）

受控实验（pre/dup/post，服务器 ASAN 构建）：
- `OPTIONS` → 210 OK（健康）
- `DESCRIBE matroskaFileTest` → 200 OK；`SETUP track1` → 201 OK
- **同一 track 再次 `SETUP` → 0 应答；此后新连接 `OPTIONS` 也 0 应答**（事件循环挂死）
- `utime` delta 350 jiffies / ~4 s 窗口 → **CPU 忙循环**，非阻塞等待；2/2 确定性；无 ASAN 报告。
- 意义：pre-auth 远程 DoS，fuzzer 侧表现为 hang/timeout 而非 crash；与公开报告 "two successive RTSP SETUP for the same track causes UAF/crash" 形态吻合，但在本 ASAN 构建中呈现为 wedge（是否同一根因待源码级定位）。
- 种子：`seeds/live555_dup-setup-wedge.raw`（375 B）。

## 6. 为什么 loopfuzz 难以触发历史漏洞（根因分解）

1. **配置/编译门（可达性）**：3/5 的 CVE 被镜像配置挡在门外（exim 无 AUTH、kamailio 无 TCP、bftpd CVE 在配置组件）。
2. **检测器盲区（可见性）**：4/5 的 CVE 无 ASAN 信号（.bss OOB 写、池内 OOB 读、有符号溢出逻辑指纹、忙循环挂死）——**crash 计数指标对它们结构性失明**。
3. **传输层不匹配**：kamailio 漏洞在 TCP 读路径，harness 全走 UDP。
4. **搜索空间形态极端**：唯一"可触发且 ASAN 可见"的 ProFTPD 触发串是 60,006 B 单行、内含 30,000 个 `\A` 引号内转义——而 in-ftp 种子仅 86–135 B 纯命令、dict 全裸动词，字节级变异+拼接几乎不可能合成该形态；CHATAFL_MAX_TOKENS=4096 也生不出 60KB 单行。
5. **版本错位**：forked-daapd campaign commit 先于漏洞引入/词法层拒绝 PoC。

## 7. 让模糊测试真正触发它们的改法（按成本排序）

1. **一行配置（立即可做）**：ProFTPD `basic.conf` 加 `CommandBufferSize 65535` → CVE-2023-51713 立即变成 fuzzer 可记录的 ASAN crash（前置条件：变异器能造出转义引号长行，见 3）。
2. **Kamailio 加 TCP 臂**：cfg `disable_tcp=no`+`listen=tcp:...`，fuzzer `-N tcp://127.0.0.1/5060`（需解决 exec-per-conn 与 fork 模式的兼容——oracle 已验证 fork=yes+TCP 可行）；同时把 crash 指标扩展为 crash+谓词（grep 负值指纹），否则触发也计 0。
3. **变异器增强（target 无关）**：
   - 转义/引号放大器：对消息内引号段做 `\X` 重复注入，行长向 CommandBufferSize 饱和；
   - 数值饱和变异：解析消息中数字字段，替换为 2147483647/21474836470/4294967296 等边界常量（Kamailio/Exim base64/长度字段通用）；
   - 状态重复变异：对同一状态的请求重放（SETUP×2 直接命中 live555 wedge）。
4. **种子/字典富集（工程口径）**：加入 `\"`、`\\A`、`AUTH EXTERNAL`、大数值 Content-Length 等词条与"结构骨架"种子。注意：论文 benchmark 的 info-control 禁止 PoC 入种子（meta.json `poc_in_seeds:false`），该口径只用于工程验证臂。
5. **指标升级**：对 crash-invisible 的 4 类 CVE 采用 cve-benchmark 的 pair+谓词 recall 作为主要"漏洞发现"指标（基础设施已就绪），crash 计数仅作辅助。
6. **镜像侧**：forked-daapd 若要 CVE-recall，按注册表建议换 13a8f71c^（修复直接父提交）。
