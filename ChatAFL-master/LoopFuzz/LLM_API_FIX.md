# LLM API 调用修复记录

验证日期：2026-10-27。

## 已确认根因

实验启动命令中的 KEY 少复制了一个大写 `T`，与成功运行 `testLLM` 时的 KEY 不同。失败凭据为 50 字节，SHA-256 前 16 位为 `30d34720356ba9dc`；用户随后提供的正确凭据为 51 字节，指纹为 `5a2f967c478bbebd`。密钥值不写入本记录。

15:00–15:01（北京时间）的最终对照验证：接口和模型保持 `https://www.cctq.ai/v1/chat/completions`、`codex-auto-review`，使用正确凭据重新编译 `testLLM.c` 后首次请求 HTTP 200、退出码 0；直接编译实际 `chat-llm.c` 的预检入口也 PASS、退出码 0；以相同 bftpd 镜像启动临时验证容器，运行同一实际客户端，仍 PASS、退出码 0。临时容器已清理，原始实验容器和结果保留。

因此此次 401 的根因是凭据抄写差异，未发现当前 C 客户端认证构造或 Docker 传参导致的差异。应在启动实验的终端 export 完整正确凭据，预检通过后重新运行实验；无需将密钥写入 C 文件或重新构建 bftpd 镜像。

## 问题与修改

- `testLLM.c` 已提交版本的 `codex-auto-review` 分支使用 `messages` 和 `/v1/chat/completions`，但默认主机为 `code.b886.top`；另一个 `gpt-5.4` 分支向 `/v1/completions` 手工拼接未转义的 `prompt`，可能产生无效 JSON。现统一使用 json-c 序列化，默认向 `https://www.cctq.ai/v1/chat/completions` 发送 `messages` 数组，解析 `choices[0].message.content`。
- `chat-llm.c` 默认端点本来正确，常用提示词构造器也已有转义；但外层请求仍手工拼接。现使用 json-c 构造完整请求和 JSONL 日志，并严格解析输入 JSON、检查响应字段类型。
- 修复空响应缓冲区未初始化、realloc 失败丢失原指针及部分错误路径资源泄漏。Authorization 头动态分配，密钥只从环境变量 `KEY` 读取。
- 区分 curl 传输错误与 HTTP 错误，记录详细错误。仅对临时网络错误及 HTTP 408/429/500/502/503/504 有限重试；400/401 等错误直接结束。保留 TLS 证书与主机名校验。
- 公共函数每次尝试在锁内预留调用次数，重试与同进程并发线程共同遵守调用上限；模型记录改为线程局部，累计用量受锁保护。现有计数仅在进程内共享，fork 子进程的累计值不会回写父进程。token 上限根据已报告用量检查，在途请求仍可能使最终用量超过上限。

## 验证结果

以下检查均已通过：

```sh
python3 llm_api_regression.py
python3 llm_api_regression.py --sanitize
make -j2 afl-fuzz
git diff --check
```

普通和 ASan/UBSan/LeakSanitizer 检查各通过 18 项本地回归测试，涵盖 JSON 转义、中文、响应类型、空响应、HTTP 错误、重试、并发调用上限和独立测试客户端。回归测试使用本地 HTTP 服务及虚拟 key，无须真实凭证。

早期真实接口验证记录使用可用 key 和 `codex-auto-review`：`testLLM` 首次请求 curl=0、HTTP 200、退出码 0；直接链接修复后 `chat-llm.c` 的公共函数也在一次调用内成功返回 RTSP 回答。该记录当时未比较凭据指纹，不能据此认定与后续失败实验使用同一 KEY；最终确认两者存在一个字符的抄写差异。实际 `afl-fuzz` 已重编译，早期验证未启动 fuzz 实验。测试用的临时 key 文件已删除。

原日志中的 curl=35 是独立的 TLS 握手错误，本次未复现；当前证书与主机名校验通过。新增错误诊断和有限重试不能证明间歇性网络故障已永久消失。

## 配置

`KEY` 为必需环境变量；`LLM_MODEL` 可覆盖默认模型。`CHATAFL_LLM_BASE` 必须是完整请求地址，例如 `https://www.cctq.ai/v1/chat/completions`。公共函数保留原有采样、超时和调用额度配置。

## 2026-10-27 容器 HTTP 401 实查

原先报告的容器 `e3d642209ba6` 已不存在，因此不能声称读取到了它的日志。本次实际检查了 12:34（北京时间）启动的九个 bftpd 容器，涉及 `wrapdirect8`、`wrapgate8`、`salvage8`，三个重复；其日志均包含 `HTTP=401`、`Invalid token`。请求地址为 `https://www.cctq.ai/v1/chat/completions`，模型为 `codex-auto-review`。

证据链：

1. 启动脚本进程、九个容器的 `Config.Env`、实际 `afl-fuzz` 进程的 `KEY` 长度和 SHA-256 指纹一致：50 字节，前 16 位指纹 `30d34720356ba9dc`，不存在首尾空白或传参截断。
2. 运行容器内的 `chat-llm.c` 与宿主机源码 SHA-256 一致：`d03318a06249e14ffe85540a513044302663339021ea47e3f0b438e3e2379470`。启动脚本复制源码后执行了 `make clean && make`。此次 401 不能归因于只改宿主机、未编译容器。
3. 直接取容器中的同一 KEY，在宿主机重新编译 `testLLM.c`，并在容器内部另行编译运行同一测试，均得到 `curl=0`、HTTP 401、退出码 1。12:40、12:45 的复测结果一致。14:49 再以该 KEY 调用实际 `chat-llm.c` 的预检入口，仍得到 401。
4. 当前两个 C 客户端都只读取 `getenv("KEY")`，采用相同默认地址和 Bearer 认证。已提交的 `dev2026` 版本曾用 256 字节的 Authorization 缓冲区，只有超过 233 字符的 KEY 才会截断，与此次 50 字节凭据无关；当前代码已动态分配该头。

上述失败请求使用的是最初启动命令中的 50 字节 KEY。用户后来提供成功请求的 51 字节 KEY，对比后确认原命令少了一个字符；最终三个客户端/环境对照均通过，见本文开头。此次无需依赖令牌撤销、服务端异常等推测解释结果。

中途用户运行新预检时，实际贴出的结果仍是 401（请求 ID `202610270652047574929618268d9d6BhfWFiaE`）。14:53 再检查宿主机现有 `LoopFuzz/testLLM` 可执行文件，其内嵌地址同样是 cctq 的 chat completions 地址；使用旧容器 KEY 运行也返回 401。该阶段尚未获得后来补充的正确凭据，并未复现“同一配置下 testLLM 成功、chat-llm 失败”。

九个容器已于 14:11–14:12 自然结束，退出码均为 0、无 OOM。完整账本和 Docker 日志交叉验证结果如下：

| 实验组 | 请求数 | HTTP 401 | 传输失败 | 成功 |
| --- | ---: | ---: | ---: | ---: |
| wrapdirect8（三次重复） | 131 | 128 | 3 | 0 |
| wrapgate8（三次重复） | 138 | 135 | 3 | 0 |
| salvage8（三次重复） | 137 | 133 | 4 | 0 |
| 总计 | 406 | 396 | 10 | 0 |

账本中所有 `model_served` 均为空，报告的输入、输出 token 均为 0。进程退出成功不代表 LLM 调用成功；这批结果不满足预期的大模型消融条件，不能直接作为上述三组机制的有效比较。保留原始结果，待有效 KEY 的实际预检通过后重新运行。现存响应侧车数量少于账本行数，不能将 `archived=true` 解释成每次调用都有独立存档；上述统计采用完整账本与 Docker 日志。

## 新增启动前预检

`run_ablation.sh` 在启动分组之前调用 `scripts/check_llm.sh`。该脚本在临时目录编译当前实际 `chat-llm.c` 和 `llm_preflight.c`，使用调用者的 KEY、模型、完整接口地址及采样配置发送一次 `Reply OK.` 请求。只有得到非空的 `choices[0].message.content` 才继续；401 等失败直接使启动器退出，不再启动一批缺少 LLM 的实验。预检不替换 KEY，不切换接口，不输出凭据或成功回复。临时编译目录自动清理；显式 `CHATAFL_NO_LLM` 模式跳过网络请求。

```sh
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
./scripts/check_llm.sh
python3 -c 'import os,hashlib; k=os.environ.get("KEY", ""); print("key_bytes=",len(k.encode()),"sha256=",hashlib.sha256(k.encode()).hexdigest()[:16])'
```

必须在刚刚请求成功的同一个终端执行，才能比较其配置。预检是宿主机上的一次真实请求，可能产生少量费用；它不能保证稍后容器内的每次请求都成功，也不计入各实验进程的调用额度。运行中容器的进程保留启动时的环境，宿主机重新 export KEY 不能更新它们。

新增预检、配置透传、401 单次失败、禁用模式及启动器失败停止的集成检查后，普通回归和 ASan/UBSan/LeakSanitizer 回归各通过 22 项测试。还通过脚本语法检查及 `git diff --check`。同时移除了 `run_dev.sh` 输出 KEY 前缀的日志。两个活动启动脚本均以原子替换方式更新，保留旧 Bash 实例正在读取的 inode。
