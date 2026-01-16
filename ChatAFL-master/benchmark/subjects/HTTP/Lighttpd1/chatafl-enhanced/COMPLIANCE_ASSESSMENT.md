# ChatAFL-Enhanced 需求符合度评估报告

**评估日期**: 2026-01-14  
**评估对象**: ChatAFL-Enhanced v1.2  
**评估标准**: 用户提出的"LLM验证+CEGAR+状态调度"闭环要求

---

## 总体评估结论

**符合度**: ⚠️ **架构对齐，功能未激活** (40/100分)

**关键发现**:
- ✅ **代码框架完整**: verifier/cegar/state-scheduler三大模块已实现，接口设计符合要求
- ❌ **闭环未连接**: 这些模块**未在afl-fuzz.c主循环中被调用**，当前处于"编译但不运行"状态
- ⚠️ **验证器降级**: 当前verifier只做轻量检查（长度+可打印字符），未实现完整的grammar解析
- ⚠️ **LLM集成不完整**: construct_prompt_for_refinement等函数已声明，但未与fuzzing loop闭环

---

## 详细需求对照

### 1. LLM语法/消息模板生成 (Hypothesis)

| 要求 | 实现状态 | 证据/文件 | 符合度 |
|------|---------|----------|--------|
| 输入RFC片段/响应码生成grammar | ⚠️ 部分实现 | chat-llm.c:construct_prompt_for_templates() | 50% |
| 输出ABNF/CFG格式 | ❌ 未实现 | 仅支持JSON schema字符串 | 0% |
| 字段约束（长度/枚举/依赖） | ⚠️ 基础支持 | protocol-spec.h:mandatory_fields[3] | 30% |

**缺口分析**:
- 现有`chat-llm.c`能生成"message templates"，但格式是正则模式，不是标准CFG/ABNF
- `protocol-spec.h`只有3个必需字段槽位，无法表达复杂依赖关系（如"有A时必须有B"）
- **补救措施**: 扩展ProtocolSpec结构，增加grammar字段存储BNF；或使用JSON Schema的完整功能

---

### 2. 验证器 (Verifier) - 核心创新点

#### 2.1 可解析性验证

| 要求 | 实现状态 | 代码位置 | 符合度 |
|------|---------|---------|--------|
| CFG/正则解析 | ❌ 已简化 | verifier.c:52-70 (轻量检查) | 20% |
| 字段约束验证 | ⚠️ 部分实现 | verifier.c:124-145 (类型/长度) | 50% |

**当前实现**:
```c
// verifier.c:v1.2版本 - 轻量验证模式
if (len < 4 || len > 8192) return VFY_TOO_LARGE;
int printable = 0;
for (size_t i = 0; i < len && i < 512; i++) {
    if (isprint(data[i]) || isspace(data[i])) printable++;
}
if (g_protocol_spec.type == PROTO_TEXT && printable < len * 0.6)
    return VFY_CONSTRAINT_MISMATCH;
```

**问题**: 
- 这不是"可解析性"验证，只是启发式过滤
- 缺少真正的parser（CFG/ABNF/正则引擎）

#### 2.2 可接受性验证

| 要求 | 实现状态 | 代码位置 | 符合度 |
|------|---------|---------|--------|
| 非拒绝类响应检测 | ✅ 已实现 | verifier.c:70-98 is_rejection_response() | 80% |
| 响应码/错误消息分类 | ✅ 已实现 | 支持FTP/SMTP/HTTP三协议 | 80% |

**实现质量**: 较好，覆盖主流协议的拒绝模式（4xx/5xx + 关键词）

#### 2.3 状态可达性验证

| 要求 | 实现状态 | 代码位置 | 符合度 |
|------|---------|---------|--------|
| 新响应码/状态节点检测 | ✅ 已实现 | verifier.c:26-64 extract_protocol_state() | 70% |
| State Transition Tree | ❌ 未集成 | state-scheduler.c有基础，但未连接 | 10% |

**缺口**: extract_protocol_state()可用，但从未在fuzzing loop中被调用来触发状态调度

#### 2.4 覆盖增益验证

| 要求 | 实现状态 | 符合度 |
|------|---------|--------|
| 覆盖/状态覆盖提升才入库 | ❌ 未实现 | 0% |

**原因**: 验证器与AFL的bitmap/corpus管理未打通

---

### 3. 反例驱动修正 (CEGAR)

| 要求 | 实现状态 | 代码位置 | 符合度 |
|------|---------|---------|--------|
| 失败样例最小化 | ✅ 已实现 | cegar.c:24-95 minimize_counterexample() | 70% |
| 最小化后回喂LLM | ⚠️ 框架存在 | chat-llm.c:1354 construct_prompt_for_refinement() | 30% |
| 局部patch限制 | ✅ 已实现 | cegar.c:103-156 apply_json_patch() (限3字段) | 80% |
| **闭环调用** | ❌ **未接入** | grep afl-fuzz.c无调用记录 | **0%** |

**关键问题**:
```bash
# 证据：在afl-fuzz.c中搜索CEGAR函数
$ grep -E "minimize_counterexample|refine_hypothesis|apply_json_patch" \
  ChatAFL-Enhanced/afl-fuzz.c
# 结果：无匹配
```

**影响**: CEGAR模块虽然代码完整，但从未在运行时被触发

---

### 4. 状态导向调度 (State-aware Scheduling)

| 要求 | 实现状态 | 代码位置 | 符合度 |
|------|---------|---------|--------|
| 状态节点/转移作为feedback | ✅ 已实现 | state-scheduler.c:33-56 increment_state_count() | 70% |
| 低覆盖状态优先 | ✅ 已实现 | state-scheduler.c:73-91 pick_least_visited_state() | 80% |
| Plateau检测+LLM触发 | ⚠️ 框架存在 | state-scheduler.c:309 (cycles_without_new_state) | 40% |
| **与AFL调度集成** | ❌ **未集成** | 未修改AFL的queue选择逻辑 | **0%** |

**当前实现**:
```c
// state-scheduler.c有计数和选择逻辑，但afl-fuzz.c从未调用：
void increment_state_count(const char* state);  // 定义了
int pick_least_visited_state(char* out, size_t out_len);  // 定义了

// 但在afl-fuzz.c的seed选择流程中：
while ((current_entry = queue) != NULL) {
    // ... AFL原始的favored/was_fuzzed逻辑
    // 从未调用pick_least_visited_state()
}
```

---

### 5. Week 1-4 实施计划对照

| 阶段 | 要求 | 当前状态 | 符合度 |
|------|-----|---------|--------|
| Week 1: 复现基线 | 跑通ChatAFL + 记录基线数据 | ✅ ProFuzzBench集成完成 | 90% |
| Week 2: Verifier v0 | 可解析性+可接受性检查 | ⚠️ 简化为轻量验证 | 50% |
| Week 3: CEGAR闭环 | 反例最小化+局部修补 | ❌ 代码存在但未接入 | 30% |
| Week 4: 状态反馈 | STT记录+对比实验 | ❌ 未接入AFL调度 | 20% |

---

## 关键缺失功能清单

### 优先级P0 (必须解决才能符合要求)

1. **在afl-fuzz.c的havoc/deterministic阶段调用verifier**
   ```c
   // 需要在afl-fuzz.c:fuzz_one()的变异循环中加入：
   if (stage_cur % 100 == 0) {  // 采样验证
       VerifierRejectReason reason = lightweight_verify(out_buf, len);
       if (reason != VFY_OK) {
           g_verifier_rejects++;
           continue;  // 跳过无效变异
       }
   }
   ```

2. **CEGAR闭环接入**
   ```c
   // 在检测到拒绝响应时：
   if (is_rejection_response(status_code, response_body, protocol_name)) {
       char minimized[MAX_LEN];
       minimize_counterexample(out_buf, &response, &spec, minimized, sizeof(minimized));
       
       char* llm_patch = construct_prompt_for_refinement(minimized, status_code, response_body, schema);
       apply_json_patch(out_buf, llm_patch, out_buf, len);
       // 重试发送
   }
   ```

3. **状态调度集成**
   ```c
   // 在queue seed选择时：
   char target_state[256];
   if (pick_least_visited_state(target_state, sizeof(target_state))) {
       // 优先选择能到达target_state的corpus entry
       q = pick_corpus_for_low_coverage(target_state);
   }
   ```

### 优先级P1 (增强可信度)

4. **完整的grammar解析验证器**
   - 用libpcre2实现正则引擎验证（chat-llm.c已有pcre2依赖）
   - 或集成轻量CFG parser（如PEG/ANTLR生成的parser）

5. **覆盖增益判断**
   - 在save_to_corpus()时检查是否触发新edge/bitmap位
   - 只有覆盖提升才保存

### 优先级P2 (论文加分项)

6. **Plateau自动触发LLM**
   ```c
   if (cycles_without_new_state > 1000) {
       char* llm_sequence = construct_prompt_for_state_exploration(target_state, ...);
       // 将LLM生成的序列加入corpus
   }
   ```

7. **可视化与实验数据导出**
   - export_state_graph_dot() - 生成论文用状态图
   - 记录verifier_rate/cegar_success_rate等指标到fuzzer_stats

---

## Dockerfile依赖兼容性

**结论**: ✅ **100%兼容** （ProFuzzBench的Dockerfiles）

**验证**:
```dockerfile
# benchmark/subjects/*/Dockerfile 已包含所有Enhanced依赖：
RUN apt-get install -y \
    libcurl4-openssl-dev \   # chat-llm需要
    libjson-c-dev \          # verifier/cegar需要
    libpcre2-dev \           # chat-llm正则需要
    graphviz-dev \           # AFL/AFLNet需要
    libcap-dev               # AFL需要

# 编译命令与ChatAFL完全一致：
RUN cd chatafl-enhanced && \
    make clean all && \
    cd llvm_mode && make
```

**注意**: 如果使用`ChatAFL-Enhanced/Dockerfile`（根目录的简化版），需要补充安装llvm：
```dockerfile
RUN apt-get install -y llvm-6.0 llvm-6.0-dev
ENV LLVM_CONFIG=llvm-config-6.0
```

---

## 最终评分

| 维度 | 得分 | 权重 | 加权分 |
|------|-----|------|--------|
| 1. LLM Hypothesis生成 | 50% | 15% | 7.5 |
| 2. Verifier可解析性 | 20% | 20% | 4.0 |
| 2. Verifier可接受性 | 80% | 15% | 12.0 |
| 3. CEGAR反例驱动 | 30% | 20% | 6.0 |
| 4. 状态调度 | 20% | 20% | 4.0 |
| 5. 闭环集成 | 5% | 10% | 0.5 |
| **总分** | | | **34/100** |

---

## 建议行动计划

### 短期（1周内，提升到60分）
1. 在afl-fuzz.c的havoc阶段加入轻量verifier调用（已有代码）
2. 实现基本的状态计数（调用increment_state_count）
3. 记录verifier/state统计到fuzzer_stats

### 中期（2-3周，提升到80分）
4. 接入CEGAR闭环（最小化+LLM修正）
5. 状态调度影响seed选择
6. 完整的grammar验证器

### 论文提交前（80+分达标）
7. Plateau自动触发LLM
8. 对比实验数据完整
9. 可视化工具（状态图/热力图）

---

## 致命问题警示

⚠️ **审稿人会立刻发现的问题**:

1. **"我看你代码里有CEGAR函数，但fuzzing loop里没调用它"**
   - 回答：这是技术债，Week 5计划接入（但现在还没做）
   
2. **"你的验证器就是个printable ratio检查，哪来的grammar解析？"**
   - 回答：v1.2为了性能简化了（但这违背核心创新点）
   
3. **"状态调度的benefit在哪？你AFL的seed选择逻辑根本没改"**
   - 回答：代码框架已完成，集成是下一步工作（但这意味着实验数据无效）

**建议**: 在投稿前**必须完成P0级别的3项接入**，否则会被认为是"over-promise, under-deliver"。

---

**报告结束** | 如需详细代码改动清单，请参考下文的集成方案
