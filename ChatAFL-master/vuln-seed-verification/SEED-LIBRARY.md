# 种子库：9 目标版本对应的输入型漏洞种子（验收制）

日期：2026-09-24。验收标准：种子输入后**目标崩溃**（ASAN/信号级、可复现）或**违反安全属性**
（可观测证据：可用性丧失 / 整数校验被绕过 / 校验失败）。

## 验收表

| 目标（版本） | 种子 | 判定 | 证据 |
|---|---|---|---|
| **proftpd** 61e621e | `pftp_cve-2023-51713_b64k.raw`（60,006B，需 conf 65535） | ✅ **崩溃** | ASAN `heap-buffer-overflow` @ `make_ftp_cmd main.c:862`；51 crashes/4 副本；重放 100% |
| **kamailio** a2209018 | `kamailio_clen-overflow_tcp.raw`（需 TCP cfg） | ✅ **安全属性违例** | 有符号溢出使负值 Content-Length 被接受，日志指纹 `bad Content-Length header value -10 in state 24`；谓词重放 HIT |
| **live555** 2023.05.10 | `live555_dup-setup-wedge.raw` | ✅ **安全属性违例（可用性）** | pre-auth 单连接 duplicate-SETUP → 事件循环永久挂死，新连接无应答；2/2 + 谓词 HIT（stall/busy 两模式） |
| **forked-daapd** 27.2 | `forked-daapd_smartpl-deadlock_doS.raw` | ✅ **安全属性违例（可用性）** | 未认证单请求 SMARTPL 死锁 → 全局无应答、进程存活；今日复验：38 行 lexer error、`/api/config` 超时——与 advisory 5/5 一致 |
| exim d6a5a05b84 | — | ✗ 构造不出 | 电池 12 形态（BDAT 边界/格式串/lexer-killer/16K 参数）全部规整应答；CVE-2023-42115 三重门（编译/配置/.bss） |
| pure-ftpd 10122d9f | — | ✗ 构造不出 | 电池 10 形态全部正常（exec-per-conn 一次性 harness，正常会话后退出为设计行为）；CVE-2024-48208 常量级锁死（1024B 行 vs 64KB 扫描区） |
| bftpd 6.1 | — | ✗ 构造不出 | 电池 29 形态（pre+post auth：4–32K 参数、格式串、lexer-killer、NUL、深 glob、高位字节、SITE/PASV 洪水）全部正常应答、0 ASAN；STAT 将格式串原样回显（无格式串执行） |
| lightftp 139af7c | — | ✗ 构造不出 | 电池 15 形态；4K USER 触发行长防护 reset（守护进程设计内行为）；exec-per-conn harness；竞态 CVE 无修复 commit 不可稳定复现 |
| lighttpd1 9f38b63 | — | ✗ 构造不出 | 电池 12 形态：TE+CL 冲突 400、负 CL 400、头/URI 超限 431、NUL URI 400——防护全部正确；负 chunk-size 被 404 容忍属轻微 RFC 偏差，无 harness 可观测安全影响 |

**结论：9 个目标中 4 个构造出合格种子（1 崩溃 + 3 安全属性违例），5 个在这些版本上构造不出——每个负结论都有明确的尝试记录与既有源码级证明支撑。**

## 电池覆盖（负结论目标的尝试记录）

统一电池（`scripts/seed_battery.py` + 目标内联变体）覆盖的形态类：
- 长参数（1K/4K/16K/32K）× 各协议核心动词
- 格式串（`%n`×64、`%s`×64、`%99999999d`）
- lexer-killer（`0x81` 高位字节 + 裸 `?` + 长记号——forked-daapd 死锁同类形态）
- NUL 注入、深 glob、高位字节串、重复命令洪水、巨大/负数值字段（CL/chunk/BDAT）
- 登录前 + 登录后两个阶段（FTP 类）

一次性 harness 修正：bftpd/lightftp/pure-ftpd 的 campaign 构建是 exec-per-conn 形态
（服务一条连接即退出）——电池必须每形态重启服务器并以 ASAN 日志为崩溃证据，
"连接后死"是设计行为不是漏洞（已用正常会话对照组证实）。

## 种子使用注意

- proftpd 种子需 `CommandBufferSize 65535`（campaign run.sh 已自动注入）；
- kamailio 种子需 TCP cfg（`KAMAILIO_TCP=1` 臂或手工 TCP cfg）；
- exim 目录中的 `exim_cve-2023-42115.raw` 仅在 oracle 镜像（配 AUTH EXTERNAL）有效——保留作 oracle 用途，不计入 campaign 验收；
- `pureftp_..._nontriggering.raw` 为不可达性对照存档。
