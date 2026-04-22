# Loopfuzz：ChatAFL / ChatAFL-Opt 严谨架构、调用链、工作流、数据流与脚本总说明

> 适用仓库：`/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master`
>
> 本文基于当前仓库中的实际实现、README、执行脚本、审计笔记与源码接线关系整理，目标是回答四个问题：
>
> 1. **ChatAFL 和 ChatAFL-Opt 的本质区别是什么**
> 2. **ChatAFL-Opt 的调用链路、框架、工作流、数据流是什么**
> 3. **当前仓库里所有 `.sh` 脚本分别做什么**
> 4. **开发 / 实验 / 分析时，应该如何理解整个系统的分层与边界**

---

## 1. 一句话结论

- **ChatAFL** 本质上是：
  - 基于 AFLNet 的**状态反馈网络协议灰盒模糊测试器**；
  - 再叠加三类 LLM 辅助：
    1. 启动期语法模板抽取；
    2. 启动期种子富集；
    3. plateau（覆盖停滞）时让 LLM 生成一条新请求。
- **ChatAFL-Opt** 本质上已经不是“多调几个 LLM 接口”的小改版，而是一个：
  - **状态感知（state-aware）**、
  - **带验证闭环（validator / hypothesis / refinement）**、
  - **带严格结构化 LLM 交互（strict JSON + actions[]）**、
  - **并对 MQTT 提供专项增强（binary↔text bridge、多连接 driver、多 broker 差分反馈、调度器）**
  的协议模糊测试框架。

因此，两者的本质差异不是“Opt 比 baseline 多几个 heuristic”，而是：

> **ChatAFL 是“开环 LLM 辅助模糊测试器”，而 ChatAFL-Opt 是“状态驱动 + 验证闭环 + 协议专项扩展”的系统化 fuzzing framework。**

---

## 2. 仓库总分层

可以把整个仓库分成 5 层：

### 第 1 层：Fuzzer 核心实现层

目录：

- `aflnet/`
- `ChatAFL/`
- `ChatAFL-CL1/`
- `ChatAFL-CL2/`
- `ChatAFL-Opt/`

职责：

- `aflnet/`：AFLNet 基线实现。
- `ChatAFL/`：基线版 LLM 增强。
- `ChatAFL-CL1/`、`ChatAFL-CL2/`：中间/变体版本。
- `ChatAFL-Opt/`：当前最完整的优化版，包含 hypothesis、validator、state-aware prompt、MQTT 专项能力等。

### 第 2 层：实验编排层

目录：

- `run.sh`
- `run_dev.sh`
- `run_ablation.sh`
- `benchmark/scripts/execution/`

职责：

- 负责把“要跑哪些 target、哪些 fuzzer、几个容器、多久、哪些环境变量”转成 docker 实验。
- 负责创建结果目录、启动容器、等待结束、收集 tar 包、恢复缺失结果、生成 summary。

### 第 3 层：镜像与目标程序层

目录：

- `benchmark/subjects/...`

职责：

- 为 LightFTP、BFTPD、Mosquitto、Exim、Live555 等被测网络服务构建镜像。
- 每个 subject 镜像内都包含被测服务、fuzzer 源码副本、以及统一的 `run` 入口。

### 第 4 层：结果分析层

目录：

- `analyze.sh`
- `run_summary.sh`
- `benchmark/scripts/analysis/`

职责：

- 从 `.tar.gz` 结果包中提取：
  - `cov_over_time.csv`
  - `plot_data`
  - `fuzzer_stats`
- 进一步生成：
  - `results.csv`
  - `states.csv`
  - 覆盖图 / 状态图
  - LLM token / 成本估算
  - `run_summary.csv`

### 第 5 层：观测与维护层

目录：

- `monitor.sh`
- `live_cov.sh`
- `clean.sh`
- `ablation/merge_tar.sh`

职责：

- 在线观察容器运行状态、覆盖增长、状态空间探索。
- 清理旧容器和镜像。
- 合并不同结果目录的 tar 包。

---

## 3. ChatAFL 与 ChatAFL-Opt 的本质区别

## 3.1 相同点

两者都建立在 AFLNet 的核心范式上：

- 输入是消息序列种子；
- 执行时与服务端交互；
- 用覆盖反馈 + 状态反馈指导后续探索；
- plateau 时可以请求 LLM 帮忙；
- 结果仍以 AFL 风格产物落盘，例如 `queue/`、`plot_data`、`fuzzer_stats` 等。

## 3.2 ChatAFL 的核心特征

从 `ChatAFL/Makefile` 和 `ChatAFL/afl-fuzz.c` 可以看出，ChatAFL 只额外挂入了：

- `chat-llm.o`
- 没有 hypothesis 子系统
- 没有 llm-validator
- 没有 RFC 知识模块
- 没有 multi-party driver
- 没有 MQTT builder / scheduler / differential 模块

也就是说，ChatAFL 主要是把 LLM 当成三个时间点的“增强器”：

### A. 启动期 grammar/template 提取

- `setup_llm_grammars()`
- 通过 `chat_with_llm()` 向模型询问协议消息模板
- 把回答解析成 message types / pattern

### B. 启动期种子富集

- `enrich_testcases()`
- 根据已知消息类型，补齐输入序列中缺失的消息类型

### C. plateau 时请求新消息

- 在 `uninteresting_times >= UNINTERESTING_THRESHOLD && chat_times < CHATTING_THRESHOLD` 时触发
- 使用 `construct_prompt_stall()` 构造 prompt
- 调用 `chat_with_llm()`
- 从自由文本中抽取 `suggested_request`
- 再把该消息送回执行路径

### D. 基线局限

ChatAFL 的 LLM 通道总体是**开环的**：

- plateau prompt 不真正携带丰富状态图上下文；
- LLM 输出多是自然语言 / 自由文本；
- 没有统一 JSON schema 验证；
- 没有真正把验证失败反馈成 hypothesis 局部修正；
- 没有严格的 action-level 控制接口；
- 没有 MQTT 专门的二进制协议桥接与差分增强。

因此 ChatAFL 的 LLM 更像：

> “在几个关键时机给 fuzzer 一点语义建议”。

而不是主循环中的闭环子系统。

## 3.3 ChatAFL-Opt 的核心特征

`ChatAFL-Opt/Makefile` 显示 `afl-fuzz` 链接了这些额外模块：

- `grammar-hypothesis.o`
- `hypothesis-adapter.o`
- `rfc-knowledge.o`
- `llm-validator.o`
- `mqtt-builder.o`
- `mp-driver-mqtt.o`
- `mqtt-generate.o`
- `mqtt-scheduler.o`
- `mqtt-differential.o`
- `mqtt-race.o`
- 以及 `chat-llm.o`, `aflnet.o`

这说明 ChatAFL-Opt 已经把“LLM 参与点”拆成了多个独立模块，而不是把所有逻辑揉在 `afl-fuzz.c` 里。

### ChatAFL-Opt 的本质升级

#### 1. 从“自由文本建议”升级为“结构化 LLM 接口”

- plateau prompt 可以携带 `state_ctx`
- LLM 可以返回：
  - `suggested_request`
  - 或 `actions[]`
- `actions[]` 支持：
  - `set_target_state`
  - `prioritize_seeds`
  - `propose_mutations`
  - `suggest_strategy`
- 返回值统一经过 `validate_and_parse_llm_json()` 做 schema 验证

#### 2. 从“LLM 生成结果直接执行”升级为“验证闭环”

- 引入 `grammar_hypothesis_t`
- 支持 `parse_success / parse_failure`
- 支持 `counterexamples`
- 支持 `refine_hypothesis_with_counterexamples()`
- 支持 sampled validation 和 periodic refinement

#### 3. 从“只看 AFLNet 状态计数”升级为“状态感知调度”

- 引入 frontier bonus
- 引入 `error_hint`
- 引入 `productivity`
- plateau prompt 中加入最差状态/最卡状态的上下文
- LLM 能直接建议跳到某个 state 或优先某些 seed

#### 4. 从“面向文本协议的通用逻辑”升级为“MQTT 专项工程化扩展”

- binary↔text 桥接：`mqtt_binary_to_text()` / `mqtt_text_to_binary()`
- multi-party driver：`mp_driver_for_protocol()` + `mp-driver-mqtt.c`
- 多 broker 差分反馈：`mqtt-differential.*`
- MQTT 程序化 seed 生成：`mqtt_generate_v5_seeds()`
- MQTT 种子富集：`mqtt_enrich_seeds()`
- MQTT 调度器：`mqtt-scheduler.*`

### 最终结论

| 维度 | ChatAFL | ChatAFL-Opt |
|---|---|---|
| LLM 角色 | 辅助增强器 | 结构化闭环子系统 |
| plateau 输出 | 自由文本为主 | 严格 JSON / actions[] |
| validator | 基本无 | 有统一 JSON validator |
| hypothesis | 无系统化闭环 | 有 grammar hypothesis + refinement |
| 状态调度 | 基于 AFLNet 统计 | state-aware + frontier/productivity |
| MQTT 二进制支持 | 弱 | 强，有 bridge |
| 多 broker 差分 | 无 | 有 |
| 协议专项 driver | 无 | 有 MP driver |
| 调度器 | AFL/AFLNet 原生 | MQTT Q-learning + UCB1 |

---

## 4. ChatAFL-Opt 的框架图（概念视角）

可以把 ChatAFL-Opt 理解成下面 8 个子系统：

### 4.1 启动期协议知识构建子系统

主要入口：

- `setup_llm_grammars()`
- `enrich_testcases()`

职责：

- 根据协议名和初始 seeds 抽取 message templates
- 识别 message types
- 对 seed corpus 做启动期富集
- 对 MQTT 额外做：
  - 文本桥接 enrichment
  - v5 seed 自动生成

### 4.2 主 fuzzing 循环子系统

主要入口：

- `afl-fuzz.c` 主循环
- `fuzz_one()`
- `common_fuzz_stuff()`
- `send_over_network()`

职责：

- 选 state
- 选 seed
- 做 mutation
- 把请求发给 server
- 接收响应
- 更新覆盖与状态图
- 判断是否 interesting

### 4.3 状态感知调度子系统

主要信息：

- state score
- frontier bonus
- error penalty / productivity penalty
- stagnation 检测
- plateau threshold 自适应

职责：

- 决定当前更值得 fuzz 哪个 state
- 决定是否需要通过 LLM 打破 plateau

### 4.4 LLM plateau 处理子系统

核心文件：

- `chat-llm.c`
- `llm-validator.c`

职责：

- 组装 rich prompt
- 注入 `state_ctx`
- 要求 LLM 输出严格 JSON
- 验证 JSON 合法性
- 执行 `actions[]` 或提取 `suggested_request`

### 4.5 Hypothesis / Verifier / Refinement 子系统

核心文件：

- `grammar-hypothesis.*`
- `hypothesis-adapter.*`
- `rfc-knowledge.*`

职责：

- 将 LLM 给出的协议规则组织为可验证的 hypothesis
- 对实际消息进行 sampled validation
- 收集 counterexample
- 在低 fitness 或失败积累后触发 refinement

### 4.6 MQTT binary-text 桥接子系统

核心文件：

- `mqtt-builder.*`
- `mqtt-generate.*`

职责：

- 把 MQTT 二进制 seed 转成 LLM 可理解的文本形式
- 再把文本 suggestions 转回合法二进制 packet
- 让 LLM 真正能参与二进制协议 fuzzing

### 4.7 MQTT multi-party / differential 子系统

核心文件：

- `mp-driver.h`
- `mp-driver-mqtt.c`
- `mqtt-differential.*`

职责：

- 建立多连接/多角色协议执行框架
- 多 broker 回放同一输入
- 比较不同 broker 的响应差异
- 将差分信号回流给 state score / queue score / plateau prompt

### 4.8 MQTT adaptive scheduling 子系统

核心文件：

- `mqtt-scheduler.*`
- `mqtt-race.*`

职责：

- 用 Q-learning / UCB1 指导 MQTT message type 调度
- 根据覆盖收益和差分收益更新 reward
- 进一步提高 MQTT 深路径探索效率

---

## 5. ChatAFL-Opt 的调用链路

这里按“从用户执行命令开始，到最终拿到结果”为顺序说明。

## 5.1 开始点：用户入口脚本

常用入口有 3 个：

### A. `run_dev.sh`

用途：开发模式运行。

特点：

- 读取 `KEY`
- 设置 `SKIPCOUNT`、`TEST_TIMEOUT`
- 导出 `TARGET_LIST`、`FUZZER_LIST`
- 导出 `PROJECT_ROOT`
- 调用 `benchmark/scripts/execution/profuzzbench_exec_all_dev.sh`

开发模式核心思想：

- 用 volume 挂载本地源码到容器，避免每次改代码都重建镜像。

### B. `run.sh`

用途：标准实验模式运行。

特点：

- 不走开发态挂载
- 会把消融环境变量透传到执行层：
  - `CHATAFL_NO_REFINEMENT`
  - `CHATAFL_NO_FRONTIER`
  - `CHATAFL_NO_ADAPTIVE`
  - `CHATAFL_NO_STATE_PROMPT`
  - `CHATAFL_ABLATION_THRESHOLD`
- 调用 `profuzzbench_exec_all.sh`

### C. `run_ablation.sh`

用途：并行启动成组消融实验。

特点：

- 基于预设（`core`、`threshold`、`appendix`、`legacy`）
- 为每一组启动一个后台子 shell
- 每组导出不同 `CHATAFL_NO_*` 变量
- 内部仍然复用 `run_dev.sh`

## 5.2 第二层：总调度脚本

### A. `profuzzbench_exec_all_dev.sh`

职责：

- 遍历 `TARGET_LIST` 与 `FUZZER_LIST`
- 为每组 target/fuzzer 创建时间戳结果目录
- 调用 `profuzzbench_exec_common_dev.sh`
- 在所有子任务结束后，对结果目录做 recovery pass

### B. `profuzzbench_exec_all.sh`

职责：

- 与 dev 版类似，但面向标准镜像运行
- 根据 target/fuzzer 组合拼出各自命令行参数，例如：
  - `-P FTP`
  - `-P SMTP`
  - `-P RTSP`
  - `-P MQTT`
  - 以及 `-E -K -R -q 3 -s 3` 等
- 每个具体组合都调用 `profuzzbench_exec_common.sh`

这一步的本质是：

> **把“实验矩阵”展开成一组具体容器任务。**

## 5.3 第三层：单组运行脚本

### A. `profuzzbench_exec_common.sh`
### B. `profuzzbench_exec_common_dev.sh`

这两者是最关键的执行桥接层。

它们负责：

1. 为当前 `(target, fuzzer)` 创建结果 manifest；
2. 根据运行次数 `RUNS` 启多个容器；
3. 为 `chatafl-opt` 自动注入：
   - `KEY`
   - `CHATAFL_HYPOTHESIS=1`
   - 各类 ablation 变量
4. 若目标是 MQTT，还会：
   - 创建 docker network
   - 启动稳定 reference broker
   - 为每个容器注入 `CHATAFL_MQTT_BROKERS`
5. `docker wait` 等待容器结束；
6. 调用 `recover_result_archives.sh` 收集 tar 包；
7. 在 dev 模式下还会做 summary 生成与 trap 场景的善后。

### 它们是“外部实验世界”和“容器内部 fuzzing 世界”的边界

也就是说，外面看到的是：

- 多个 docker 容器
- 每个容器代表一次 fuzz run
- 最后落成 tar.gz

里面实际发生的是：

- 容器进入被测 subject 环境
- 调用统一 `run` 入口
- 编译/执行指定 fuzzer
- 生成 out-dir
- 执行覆盖统计脚本
- 打包产物

## 5.4 第四层：容器内的被测 subject + fuzzer 启动

虽然不同 subject 镜像细节不同，但整体模式一致：

1. 容器进入 `/home/ubuntu/experiments`
2. 执行统一 `run <FUZZER> <OUTDIR> <OPTIONS> <TIMEOUT> <SKIPCOUNT>`
3. 目标服务被启动
4. 选中的 fuzzer（二进制通常是 `afl-fuzz` 变体）开始运行

这时如果选择的是 `chatafl-opt`，那么真正跑起来的是：

- `ChatAFL-Opt/afl-fuzz`
- 链接了 `aflnet.o + chat-llm.o + hypothesis + validator + mqtt*`

## 5.5 第五层：ChatAFL-Opt 进程内调用链

按时间顺序如下。

### 阶段 1：启动初始化

- 解析命令行与 AFL/AFLNet 参数
- 初始化共享内存、fork server、IPSM
- 读取协议信息
- 若需要 LLM：
  - `setup_llm_grammars()`
  - `enrich_testcases()`
- 若是 MQTT：
  - 可能执行 `mqtt_enrich_seeds()`
  - 可能执行 `mqtt_generate_v5_seeds()`
- 初始化各类 runtime flags：
  - `CHATAFL_HYPOTHESIS`
  - `CHATAFL_NO_*`
  - MQTT scheduler / differential 开关

### 阶段 2：主循环

- 选择 target state
- 选择 seed
- 进行 mutation
- 进入 `send_over_network()`

### 阶段 3：网络发送与反馈采集

对非 MQTT / 非 multi-party 协议：

- 走单连接路径
- 请求发送给 target
- 读取响应
- 更新 response-based state feedback

对 MQTT：

- `mp_driver_for_protocol("MQTT")` 命中 driver
- 进入多连接/多角色路径
- 如果配置了多 broker，则对多个 broker 同步回放
- 用 `mqtt-differential` 分析差异

### 阶段 4：interesting 判定与统计更新

- `common_fuzz_stuff()`
- `save_if_interesting()`
- 更新 coverage / queue / plot_data / stats
- 可能触发 `validate_hypothesis_sampled()`

### 阶段 5：plateau 处理

当长期没有新覆盖：

1. 构造 `history`
2. 构造 `examples`
3. 构造 `state_ctx`
4. 调用 `llm_handle_plateau()`
5. LLM 返回严格 JSON
6. `validate_and_parse_llm_json()` 校验
7. 执行：
   - `suggested_request`
   - 或 `actions[]`
8. 若启用 refinement，则在合适时机调用 `periodic_hypothesis_refinement()`

### 阶段 6：收尾与落盘

- 生成 `fuzzer_stats`
- 生成 `plot_data`
- 生成 `cov_over_time.csv`
- 容器内将 out-dir 打成 tar.gz
- 外层 recovery/summary 脚本收集结果

---

## 6. ChatAFL-Opt 的工作流

下面用“准备期 → 启动期 → 热路径 → 收尾期”的方式说明。

## 6.1 准备期

### 输入

- fuzzer 源码：`ChatAFL-Opt/`
- 被测目标：`benchmark/subjects/*/*`
- 初始语料 / 协议样本
- API Key：`KEY`
- 运行参数：容器数、时间、target、fuzzer、ablation 开关

### 典型脚本

- `deps.sh`：装基础依赖
- `setup.sh`：把各 fuzzer 复制到 benchmark subjects，并构建镜像
- `run_dev.sh` / `run.sh` / `run_ablation.sh`：发起实验

## 6.2 启动期

### ChatAFL 基线做什么

- 语法模板抽取
- 种子富集
- 读入 testcases

### ChatAFL-Opt 额外做什么

- 并行 enrichment
- hypothesis 模式开关初始化
- adaptive plateau 配置
- MQTT 桥接 / 差分 / scheduler 初始化

## 6.3 热路径

### 核心循环要素

- state selection
- seed selection
- mutation
- network execution
- state / coverage feedback
- verifier sampling
- plateau recovery

### 与基线差异最大的地方

1. **状态调度更强**
2. **plateau 提示更强**
3. **输出解析更严格**
4. **失败反馈可回灌 hypothesis**
5. **MQTT 不是“特殊 case”，而是专门的一条增强链路**

## 6.4 收尾期

### 容器内

- 输出 `out-*`
- 包含 queue、plot_data、fuzzer_stats、cov_over_time.csv 等
- 打包成 tar.gz

### 容器外

- `recover_result_archives.sh` 确保 tar 完整
- `run_summary.py` 生成 run summary
- `analyze.sh` / `profuzzbench_generate_csv.sh` / plotting 脚本生成图表

---

## 7. ChatAFL-Opt 的数据流

## 7.1 数据源输入

### A. 用户输入

- 命令行参数
- 环境变量：
  - `KEY`
  - `SKIPCOUNT`
  - `TEST_TIMEOUT`
  - `CHATAFL_NO_*`
  - `CHATAFL_ABLATION_THRESHOLD`
  - `CHATAFL_MQTT_BROKERS`

### B. 协议语料输入

- 初始 seeds
- PCAP / 历史交互样本
- 被测服务实际响应
- 协议名（FTP/SMTP/RTSP/MQTT/...）

## 7.2 启动期中间数据

- message templates
- message type set
- enriched seeds
- MQTT text-form seeds
- MQTT v5 generated seeds

## 7.3 运行期中间数据

### 状态与覆盖数据

- `virgin_bits`
- `queued_paths`
- `ipsm.dot`
- `paths_discovered`
- `selected_times`
- `productivity`

### LLM 相关数据

- prompt messages
- `state_ctx`
- `suggested_request`
- `actions[]`
- `stall-interactions/llm-suggest-*`
- token usage 统计

### hypothesis 数据

- `grammar_hypothesis_t`
- `parse_success`
- `parse_failure`
- `counterexamples`
- `fitness`

### MQTT 专项数据

- text↔binary bridge buffer
- broker response signatures
- differential signal
- scheduler reward

## 7.4 输出数据

### 容器内 out-dir 常见产物

- `queue/`
- `replayable-queue/`
- `plot_data`
- `fuzzer_stats`
- `cov_over_time.csv`
- `ipsm.dot`
- `responses-ipsm/`
- `stall-interactions/`
- `diffs/`（MQTT 差分时）

### 容器外结果目录产物

- `out-<target>-<fuzzer>_<n>.tar.gz`
- `.result_manifest.tsv`
- `run_summary.csv`
- `results.csv`
- `states.csv`
- `llm_cost.csv`
- `cov_over_time_<...>.png`
- `state_over_time_<...>.png`

---

## 8. 为什么说 ChatAFL-Opt 是“框架”而不是“补丁版 ChatAFL”

因为它已经具备框架的几个标志：

### 8.1 有模块边界

- `chat-llm` 负责与模型对话
- `llm-validator` 负责返回值验证
- `grammar-hypothesis` 负责规则对象与 refinement
- `mp-driver` 负责协议多方连接骨架
- `mqtt-*` 负责 MQTT 特化能力

### 8.2 有协议分层

- 非 MQTT 协议仍能走共享路径
- MQTT 只在命中协议时才走增强链路
- 说明作者在刻意保持：
  - 通用骨架
  - 协议特化扩展
  两层分离

### 8.3 有策略分层

- state selection
- hypothesis validation
- plateau prompting
- refinement
- MQTT differential
- scheduler

这些不是同一函数里的 if-else 小补丁，而是多个可单独开关的 policy bundle。

### 8.4 有实验编排分层

- setup
- run
- run_dev
- run_ablation
- execution scripts
- analysis scripts
- monitor scripts

说明整个仓库已经把“算法实现”和“实验工程”拆开了。

---

## 9. 所有 `.sh` 脚本总表与用途说明

下面按层分类，覆盖当前仓库中需要关注的 shell 脚本。

> 注：其中有一批脚本在 `aflnet/`、`ChatAFL/`、`ChatAFL-CL1/`、`ChatAFL-CL2/`、`ChatAFL-Opt/` 中是**同类复制版本**，用途相同，只是分别跟随各自 fuzzer 目录发布。

---

## 9.1 根目录实验入口与维护脚本

### 1. `setup.sh`

用途：一键准备正式实验环境。

做的事：

- 检查 `KEY`
- 把 `KEY` 写入各版本 `chat-llm.h`
- 将 `aflnet/`、`ChatAFL/`、`ChatAFL-CL1/`、`ChatAFL-CL2/`、`ChatAFL-Opt/` 复制进每个 benchmark subject 目录
- 调用 `profuzzbench_build_all.sh` 构建镜像

适用场景：

- 正式实验前更新所有镜像。

### 2. `deps.sh`

用途：安装最低限度依赖。

做的事：

- `apt-get update`
- 安装 `docker`、`python3`、`python3-pip`
- `pip3 install matplotlib pandas`

适用场景：

- 新机器初始准备。

### 3. `run.sh`

用途：标准实验入口。

做的事：

- 设置 `PFBENCH`
- 透传容器数量、时长、targets、fuzzers
- 透传 ablation 环境变量
- 调用 `benchmark/scripts/execution/profuzzbench_exec_all.sh`

适用场景：

- 跑正式 benchmark。

### 4. `run_dev.sh`

用途：开发模式入口。

做的事：

- 检查 `KEY`
- 设置 `PROJECT_ROOT`
- 调用 `profuzzbench_exec_all_dev.sh`
- 用 volume 挂载支持“修改代码后无需重建镜像”

适用场景：

- 迭代开发 / 快速验证新改动。

### 5. `run_ablation.sh`

用途：消融实验启动器。

支持预设：

- `core`
- `threshold`
- `appendix`
- `legacy`

做的事：

- 按组设置 `CHATAFL_NO_*`
- 后台并行启动多组 `run_dev.sh`
- 等待所有组结束
- 修复结果目录权限

适用场景：

- 系统性对比 adaptive / refinement / frontier / state_prompt 等策略。

### 6. `analyze.sh`

用途：对某个结果目录进行后处理。

做的事：

- 自动找到最新 `results-*`
- 检查 tar 是否存在
- 提取 fuzzer 列表与重复次数
- 调 `profuzzbench_generate_csv.sh`
- 生成 `results.csv`、`states.csv`
- 生成 coverage/state 图
- 生成 `llm_cost.csv`
- 复制分析产物到 `res_*`

适用场景：

- fuzzing 完成后做离线分析。

### 7. `clean.sh`

用途：清理旧容器与镜像。

做的事：

- 遍历 subject 名称
- stop / rm 对应容器
- 删除镜像

适用场景：

- 清空实验环境。

### 8. `monitor.sh`

用途：运行时监控所有或指定协议的 fuzzing 容器。

做的事：

- `docker exec` 读取容器内 `fuzzer_stats`、`plot_data`、`ipsm.dot`
- 统计覆盖、状态数、LLM token、CPU/内存等
- 可单次采集或定时刷新
- 可输出 CSV

适用场景：

- 长时间实验过程中的在线观察。

### 9. `live_cov.sh`

用途：在容器内对 Mosquitto 队列做实时 coverage snapshot。

做的事：

- 用备用端口启动 gcov 版 mosquitto
- 重放 queue / replayable-queue
- 跑 `gcovr`
- 输出 `l_abs / b_abs`

适用场景：

- 想在 fuzzing 尚未结束时观察当前 coverage。

### 10. `run_summary.sh`

用途：给一个结果目录补生成 `run_summary.csv`。

做的事：

- 解析参数中的 results-dir
- 找到 `benchmark/scripts/analysis/run_summary.py`
- 调用 Python 生成 summary

适用场景：

- 结果已有，但缺少 summary 时补跑。

### 11. `ablation/merge_tar.sh`

用途：把多个 ablation 子目录中的 tar 包重命名后并入主目录。

做的事：

- 统计主目录中每个 tar 前缀的最大编号
- 将子目录 tar 复制到主目录并顺延编号

适用场景：

- 合并分批实验结果。

---

## 9.2 benchmark 执行脚本

### 12. `benchmark/scripts/execution/profuzzbench_build_all.sh`

用途：构建 benchmark subjects 对应的 docker 镜像。

做的事：

- 逐个进入各协议 target 目录
- 运行 `docker build`
- 产出 `lightftp`、`bftpd`、`mosquitto-v2.1.2` 等镜像

### 13. `benchmark/scripts/execution/profuzzbench_exec_all.sh`

用途：标准模式总调度。

做的事：

- 根据 target/fuzzer 组合拼接参数
- 为每组创建 `results-<target>_<timestamp>`
- 后台调用 `profuzzbench_exec_common.sh`

### 14. `benchmark/scripts/execution/profuzzbench_exec_all_dev.sh`

用途：开发模式总调度。

做的事：

- 与标准版类似
- 但底层走 dev common 脚本
- 收尾时还会做 recovery pass / summary 生成等开发期友好逻辑

### 15. `benchmark/scripts/execution/profuzzbench_exec_all.sh.backup`

用途：旧版备份脚本。

说明：

- 不是主执行入口
- 用于保留旧实现，便于对照或回滚参考

### 16. `benchmark/scripts/execution/profuzzbench_exec_common.sh`

用途：标准模式单组容器执行器。

做的事：

- 根据 `RUNS` 启多个容器
- 对 MQTT 自动建网络、起稳定 broker、注入 broker list
- 对 `chatafl-opt` 自动加 `CHATAFL_HYPOTHESIS=1`
- 等待容器结束
- 记录 `.result_manifest.tsv`
- 调 recovery helper 收集结果

### 17. `benchmark/scripts/execution/profuzzbench_exec_common_dev.sh`

用途：开发模式单组容器执行器。

做的事：

- 与标准版类似
- 额外挂载本地源码目录
- trap 时尽量等待容器完成，避免覆盖数据缺失
- 收尾时补生成 `run_summary.csv`

### 18. `benchmark/scripts/execution/recover_result_archives.sh`

用途：结果恢复与完整性补救。

做的事：

- 根据 `.result_manifest.tsv` 找每个容器
- 优先从容器内复制最终 tar.gz
- 若失败，则复制 raw out-dir 本地重打包
- 检查 tar 是否包含关键文件：
  - `fuzzer_stats`
  - `cov_over_time.csv`
- 必要时尝试单文件补丁式修复

适用场景：

- 容器异常退出、trap 中断、tar 不完整时。

---

## 9.3 benchmark 分析脚本

### 19. `benchmark/scripts/analysis/profuzzbench_generate_all.sh`

用途：批量分析当前目录下所有 `results-*` 目录。

做的事：

- 遍历 `results-*`
- 对每个目录提取 fuzzer 与 run 数量
- 调 `profuzzbench_generate_csv.sh`
- 生成覆盖图和状态图

### 20. `benchmark/scripts/analysis/profuzzbench_generate_csv.sh`

用途：从 tar 包抽取 coverage/state CSV。

做的事：

- 解开每个 `out-*.tar.gz` 中的 `cov_over_time.csv` 和 `plot_data`
- 转成统一格式：
  - `results.csv`
  - `states.csv`

说明：

- 是 `analyze.sh` 的核心子脚本之一。

---

## 9.4 论文辅助脚本

### 21. `ASE-Paper-Verified-LLM/editor_fix.sh`

用途：自动修改论文 LaTeX 中摘要和关键词。

说明：

- 是论文撰写辅助脚本，不参与 fuzzing / benchmark 主流程。
- 其中路径写死为另一台机器/目录，更多像临时编辑工具。

---

## 9.5 AFL/AFLNet 继承类脚本：5 组目录、同类用途

下面这些脚本在以下 5 个目录中分别存在同类版本：

- `aflnet/`
- `ChatAFL/`
- `ChatAFL-CL1/`
- `ChatAFL-CL2/`
- `ChatAFL-Opt/`

也就是说，同类脚本一共有 5 份（或更多同构副本），用途基本一致。

### A 类：QEMU 构建脚本

路径：

- `aflnet/qemu_mode/build_qemu_support.sh`
- `ChatAFL/qemu_mode/build_qemu_support.sh`
- `ChatAFL-CL1/qemu_mode/build_qemu_support.sh`
- `ChatAFL-CL2/qemu_mode/build_qemu_support.sh`
- `ChatAFL-Opt/qemu_mode/build_qemu_support.sh`

用途：

- 下载、打补丁、构建 `afl-qemu-trace`
- 让 AFL 系列 fuzzer 支持 binary-only instrumentation

适用场景：

- 目标程序无法重新编译插桩时，用 QEMU 模式 fuzz。

### B 类：分布式同步脚本

路径：

- `aflnet/experimental/distributed_fuzzing/sync_script.sh`
- `ChatAFL/experimental/distributed_fuzzing/sync_script.sh`
- `ChatAFL-CL1/experimental/distributed_fuzzing/sync_script.sh`
- `ChatAFL-CL2/experimental/distributed_fuzzing/sync_script.sh`
- `ChatAFL-Opt/experimental/distributed_fuzzing/sync_script.sh`

用途：

- 通过 SSH 在多台机器之间同步 AFL 输出目录
- 适合分布式 fuzzing

适用场景：

- 多主机协同跑 AFL / AFLNet。

### C 类：崩溃归因脚本

路径：

- `aflnet/experimental/crash_triage/triage_crashes.sh`
- `ChatAFL/experimental/crash_triage/triage_crashes.sh`
- `ChatAFL-CL1/experimental/crash_triage/triage_crashes.sh`
- `ChatAFL-CL2/experimental/crash_triage/triage_crashes.sh`
- `ChatAFL-Opt/experimental/crash_triage/triage_crashes.sh`

用途：

- 遍历 AFL 输出中的 crash 样本
- 用 gdb 批量跑 backtrace / 寄存器信息
- 辅助做 crash triage

适用场景：

- 对崩溃样本做初步分组和分析。

### D 类：cgroup 内存限制脚本

路径：

- `aflnet/experimental/asan_cgroups/limit_memory.sh`
- `ChatAFL/experimental/asan_cgroups/limit_memory.sh`
- `ChatAFL-CL1/experimental/asan_cgroups/limit_memory.sh`
- `ChatAFL-CL2/experimental/asan_cgroups/limit_memory.sh`
- `ChatAFL-Opt/experimental/asan_cgroups/limit_memory.sh`

用途：

- 用 cgroups 而不是传统 `setrlimit` 为 fuzzing job 限制实际内存
- 尤其适合 ASAN/MSAN 场景

适用场景：

- Sanitizer 模式下避免地址空间限制带来的误伤。

### E 类：LightFTP 教程清理脚本

路径：

- `aflnet/tutorials/lightftp/ftpclean.sh`
- `ChatAFL/tutorials/lightftp/ftpclean.sh`
- `ChatAFL-CL1/tutorials/lightftp/ftpclean.sh`
- `ChatAFL-CL2/tutorials/lightftp/ftpclean.sh`
- `ChatAFL-Opt/tutorials/lightftp/ftpclean.sh`

用途：

- 清空 `~/ftpshare/*`
- 删除 `~/fftplog`

适用场景：

- fuzz LightFTP 教程环境前，清理服务端状态。

### F 类：IPP sample 教程清理脚本

路径：

- `aflnet/tutorials/ippsample/ippcleanup.sh`
- `ChatAFL/tutorials/ippsample/ippcleanup.sh`
- `ChatAFL-CL1/tutorials/ippsample/ippcleanup.sh`
- `ChatAFL-CL2/tutorials/ippsample/ippcleanup.sh`
- `ChatAFL-Opt/tutorials/ippsample/ippcleanup.sh`

用途：

- 清空 `/tmp/spool/*`

适用场景：

- fuzz IPP sample 服务前清理打印 spool。

---

## 10. “所有脚本”与“主流程脚本”的区别

不是所有 `.sh` 都属于主实验链路。

### 真正属于主链路的脚本

高频主流程建议重点掌握这 12 个：

1. `setup.sh`
2. `run.sh`
3. `run_dev.sh`
4. `run_ablation.sh`
5. `analyze.sh`
6. `monitor.sh`
7. `run_summary.sh`
8. `benchmark/scripts/execution/profuzzbench_build_all.sh`
9. `benchmark/scripts/execution/profuzzbench_exec_all.sh`
10. `benchmark/scripts/execution/profuzzbench_exec_all_dev.sh`
11. `benchmark/scripts/execution/profuzzbench_exec_common.sh`
12. `benchmark/scripts/execution/profuzzbench_exec_common_dev.sh`
13. `benchmark/scripts/execution/recover_result_archives.sh`
14. `benchmark/scripts/analysis/profuzzbench_generate_csv.sh`

### 不属于主链路但有辅助价值的脚本

- `clean.sh`
- `live_cov.sh`
- `ablation/merge_tar.sh`
- `benchmark/scripts/analysis/profuzzbench_generate_all.sh`

### 主要属于继承/实验/教程资产的脚本

- 所有 `qemu_mode/build_qemu_support.sh`
- 所有 `experimental/*/*.sh`
- 所有 `tutorials/*/*.sh`
- `ASE-Paper-Verified-LLM/editor_fix.sh`

---

## 11. 实际开发与实验时，最关键的理解框架

## 11.1 如果你在改 fuzzing 核心逻辑

主要看：

- `ChatAFL-Opt/afl-fuzz.c`
- `ChatAFL-Opt/chat-llm.c`
- `ChatAFL-Opt/llm-validator.c`
- `ChatAFL-Opt/grammar-hypothesis.*`
- `ChatAFL-Opt/mqtt-*`
- `ChatAFL-Opt/mp-driver-*`

## 11.2 如果你在改实验编排 / 结果收集

主要看：

- `run_dev.sh`
- `run.sh`
- `run_ablation.sh`
- `benchmark/scripts/execution/profuzzbench_exec_all*.sh`
- `benchmark/scripts/execution/profuzzbench_exec_common*.sh`
- `benchmark/scripts/execution/recover_result_archives.sh`

## 11.3 如果你在改结果分析

主要看：

- `analyze.sh`
- `run_summary.sh`
- `benchmark/scripts/analysis/profuzzbench_generate_csv.sh`
- `benchmark/scripts/analysis/run_summary.py`
- plotting 相关 Python 脚本

## 11.4 如果你在做在线观测

主要看：

- `monitor.sh`
- `live_cov.sh`

---

## 12. 一个完整实验的最简 mental model

可以把一次 `chatafl-opt` 实验理解成下面这条链：

1. **准备镜像**：`setup.sh`
2. **启动实验**：`run_dev.sh` / `run.sh`
3. **展开矩阵**：`profuzzbench_exec_all*.sh`
4. **启动容器**：`profuzzbench_exec_common*.sh`
5. **容器内执行**：subject `run` → `ChatAFL-Opt/afl-fuzz`
6. **启动期知识构建**：grammar + enrichment + MQTT seed prep
7. **主循环 fuzzing**：state select → mutate → send → feedback
8. **停滞处理**：plateau → rich prompt → strict JSON → validator → actions/request
9. **闭环修正**：sampled validation → counterexample → refinement
10. **MQTT 专项增强**：bridge + multi-party + differential + scheduler
11. **落盘打包**：`fuzzer_stats` / `plot_data` / `cov_over_time.csv`
12. **外层恢复与汇总**：recovery helper + `run_summary.csv`
13. **分析成图**：`analyze.sh`

这就是 ChatAFL-Opt 的完整工作链。

---

## 13. 最终结论

### 对“本质区别”的最终回答

- ChatAFL 是：**AFLNet + 三段式 LLM 辅助**。
- ChatAFL-Opt 是：**AFLNet 内核之上，加入 state-aware 调度、结构化 LLM 接口、validator / hypothesis / refinement 闭环，以及 MQTT 专项执行/差分/调度能力的完整 framework**。

### 对“调用链路”的最终回答

- 用户入口：`run_dev.sh` / `run.sh` / `run_ablation.sh`
- 实验调度：`profuzzbench_exec_all*.sh`
- 单组执行：`profuzzbench_exec_common*.sh`
- 容器内运行：subject `run` + `ChatAFL-Opt/afl-fuzz`
- 收尾恢复：`recover_result_archives.sh`
- 分析汇总：`analyze.sh` / `run_summary.sh` / analysis scripts

### 对“工作流与数据流”的最终回答

- 工作流是：**准备 → 启动 → 主循环 → plateau → refinement → 落盘 → 汇总 → 分析**。
- 数据流是：**初始 seeds / 环境变量 / 历史响应 → state_ctx / hypothesis / differential signals → queue / plot_data / stats / tar.gz / summary / plots**。

### 对“所有脚本”的最终回答

- 主流程脚本负责：**构建、运行、收集、分析、监控**。
- 继承脚本负责：**QEMU、分布式同步、崩溃 triage、ASAN cgroup、教程清理**。
- 论文脚本与主实验链无关。

---

## 14. 建议阅读顺序

如果要最快理解系统，推荐按这个顺序读：

1. `run_dev.sh`
2. `benchmark/scripts/execution/profuzzbench_exec_all_dev.sh`
3. `benchmark/scripts/execution/profuzzbench_exec_common_dev.sh`
4. `ChatAFL-Opt/Makefile`
5. `ChatAFL-Opt/afl-fuzz.c`
6. `ChatAFL-Opt/chat-llm.c`
7. `ChatAFL-Opt/llm-validator.c`
8. `ChatAFL-Opt/grammar-hypothesis.*`
9. `ChatAFL-Opt/mqtt-builder.*`
10. `ChatAFL-Opt/mp-driver-mqtt.c`
11. `ChatAFL-Opt/mqtt-differential.*`
12. `analyze.sh`
13. `benchmark/scripts/analysis/profuzzbench_generate_csv.sh`

这样最容易从“外层工程链”一路走到“内核算法链”。

## 15. ChatAFL-Opt核心思想

ChatAFL-Opt与ChatAFL在同一个目录下，它是将ChatAFL 这类“LLM帮你生成/变异协议消息”的方法，升级为【LLM提出结构/状态假设 → 运行时验证与反例驱动修正 → 形成可复现、可度量的状态探索闭环】。从而解决当前 LLM-fuzzing 最大的审稿痛点：幻觉、不可控、不可复现。ChatAFL 已证明LLM能从RFC抽出语法/状态信息并融入fuzz loop，但“验证与纠错机制”仍是强缺口。以下是工程扩展要求，请先严谨地结合【work_and_data_flow.txt】工作流和数据流判断要求是否已经主流程中实现并起作用：

1. LLM语法/消息模板生成（Hypothesis）
o 输入：RFC片段/抓包样例/服务端响应码与错误信息
o 输出：每类 message 的 grammar（ABNF风格或自定义CFG/JSON schema）+ 字段约束（长度、枚举、依赖关系）


2. 验证器（Verifier，核心创新点）
不需要形式化证明，可用且“工程上强有效”的验证：
o 可解析性：生成消息能被本地parser解析（CFG/正则/字段拆解）
o 可接受性：发送给SUT后得到“非拒绝类响应”（比如非400/非error）
o 状态可达性：消息序列触发新响应码/新状态节点（可用 State Transition Tree 思路）USENIX’22 的 Stateful Greybox Fuzzing
o 覆盖增益：覆盖/状态覆盖提升才将该grammar片段“入库”

3. 反例驱动修正（Counterexample-guided Refinement）
o 当验证失败：把失败样例（最小化后的请求+响应+差分）回喂给LLM，让它只修一个字段/一条产生式
o 关键：限制LLM自由度（只允许局部patch），降低幻觉

4. 状态导向调度（State-aware Scheduling）
o 把“状态节点/转移”作为 fuzz feedback（类似 stateful greybox fuzzing 的 STT）
o 目标：优先探索“低覆盖状态/稀有转移”，并在 plateau(停滞) 时触发LLM生成“到某状态的序列建议”USENIX’22 的 Stateful Greybox Fuzzing


注：ChatAFL来源于【Large Language Model guided Protocol Fuzzing.pdf】，SST来源于【Stateful Greybox Fuzzing.pdf】

