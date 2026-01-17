# ChatAFL-Enhanced: Quick Start Guide

## 概述

ChatAFL-Enhanced是对ChatAFL的重大升级，通过引入**验证-反例驱动修正-状态导向调度**的闭环，解决LLM-fuzzing的三大关键痛点：

| 痛点 | 现象 | 解决方案 |
|------|------|---------|
| **幻觉** | LLM生成无效消息 | Verifier四层验证 |
| **不可复现** | 随机失败，无法重现 | CEGAR缓存机制 |
| **不可控** | 错误无反馈，无修正 | 失败消息回传LLM |

---

## 文件结构速览

```
ChatAFL-Enhanced/
├── ENHANCEMENT.md              # 架构设计文档 (必读)
├── COMPLETION_REPORT.md        # 完成度详细分析
├── INTEGRATION_GUIDE.md        # 与AFLNet集成步骤
├── README.md                   # 原ChatAFL文档
│
├── verifier.h / verifier.c            # Module A: 验证器
├── cegar-refinement.h / cegar-refinement.c    # Module B: 反例修正
├── state-scheduler.h / state-scheduler.c      # Module C: 状态调度
├── verified-loop.c             # Orchestrator: 整合三个模块
│
├── Makefile.enhanced           # 编译脚本
└── [其他AFL/ChatAFL文件]        # 原ChatAFL代码
```

---

## 快速开始 (5分钟)

### Step 1: 查看核心架构

```bash
cd ChatAFL-Enhanced
cat ENHANCEMENT.md | head -100
```

**关键图**: 验证→CEGAR→调度的三环闭合

### Step 2: 编译验证循环

```bash
# 安装依赖 (Ubuntu)
sudo apt-get install libcurl4-openssl-dev libjson-c-dev libpcre2-dev

# 编译
make -f Makefile.enhanced

# 输出: test_verified_loop (可执行文件)
```

### Step 3: 运行测试

```bash
mkdir -p .vloop_logs
./test_verified_loop
```

**预期输出**:
```
========================================
ChatAFL-Enhanced: Verified Loop v0.1
========================================

[VERIFIED-LOOP] Initialized for protocol=RTSP sut=127.0.0.1:554
[VERIFIED-LOOP] Processing message #1
[VERIFIED-LOOP] Phase 1: Verification
  ✓ Parseability: PASS
  ✓ Acceptability: FAIL (status=503)
[VERIFIED-LOOP] Message rejected by SUT → CEGAR refinement
  ✓ CEGAR: Generated patch for field 2
...
[VERIFIED-LOOP] Summary:
  Total messages tested: 1
  Messages verified: 0 (0.0%)
  CEGAR patches applied: 1
  Total failures: 0
```

---

## 深入理解：三个核心模块

### Module A: Verifier (验证器)

**目的**: 守卫LLM生成的消息质量

**工作流**:
```
消息 → [1.解析] → [2.接受] → [3.状态] → [4.覆盖]
        ✓         ✓         ✓         ✓
                                      ↓
                            加入verified库
        
        ✗ (任何阶段失败)
                  ↓
            触发CEGAR修正
```

**关键函数** (verifier.h):
- `verify_parseability()`: 消息能被解析吗？
- `verify_acceptability()`: SUT接受吗？
- `verify_state_reachability()`: 到达新状态吗？
- `calculate_coverage_gain()`: 覆盖提升多少？

**使用示例**:
```c
#include "verifier.h"

verifier_config_t cfg = {.enable_logging = 1, .log_file = ".log"};
verifier_init(&cfg);

parsed_fields_t *fields = NULL;
int ok = verify_parseability(message, msg_len, grammar, &fields);

response_t resp = {0};
ok = verify_acceptability("127.0.0.1", 554, message, msg_len, &resp, 5000);

verifier_cleanup();
```

### Module B: CEGAR (反例驱动修正)

**目的**: 修复失败消息，形成可复现的修正闭环

**工作流**:
```
失败消息
  ↓ [最小化] (delta-debugging)
最小反例
  ↓ [约束Prompt] (field-level only)
LLM调用
  ↓ [解析补丁] (JSON format)
补丁
  ↓ [应用+验证] (re-run Verifier)
修复成功 → [缓存] .cegar_cache/{hash}.json
修复失败 → [尝试下一字段] (或放弃)
```

**关键约束设计** (防幻觉):
```
❌ 无约束 (易幻觉):
"Fix the message that was rejected by server."

✅ 有约束 (强约束):
"CONSTRAINT: Only modify field[3] 'Content-Length'.
 Do NOT change any other fields."
```

**关键函数** (cegar-refinement.h):
- `construct_cegar_prompt()`: 生成约束Prompt
- `parse_cegar_patch()`: 解析LLM补丁
- `apply_and_verify_patch()`: 应用并验证
- `cache_cegar_patch()`: 缓存用于复现

**使用示例**:
```c
#include "cegar-refinement.h"

cegar_init(".cegar_cache");

cegar_failure_t failure = {
    .original_message = msg,
    .original_len = msg_len,
    .failure_classification = "400_bad_request"
};

cegar_patch_t *patch = iterative_field_refinement(
    &failure, grammar, 5, "RTSP"
);

if (patch) {
    cache_cegar_patch("hash_of_msg", patch);
}

cegar_cleanup();
```

### Module C: State Scheduler (状态导向调度)

**目的**: 用状态稀有度指导fuzzing，优先探索低覆盖状态

**核心思想** (USENIX'22 Stateful Greybox Fuzzing):
```
rarity(state) = 1.0 / (1.0 + visitation_count)

优先调度到达rare状态的种子
```

**工作流**:
```
当前状态集 → [更新rarity] → [选择种子]
                              ├─ 70%: rare states
                              └─ 30%: high coverage
                              
检测plateau → [LLM州转向] → 生成到达低覆盖状态的序列
```

**关键函数** (state-scheduler.h):
- `update_state_rarity()`: 计算所有状态的稀有度
- `select_seed_by_state_rarity()`: 加权种子选择
- `detect_coverage_plateau()`: 检测停滞
- `construct_state_targeting_prompt()`: 州转向Prompt

**使用示例**:
```c
#include "state-scheduler.h"

state_scheduler_t sched = {0};
state_scheduler_init(&sched, 50);  // plateau_threshold

// 更新STT
unsigned int states[] = {200, 201, 200};
update_state_transition_tree(sched.stt, states, 3, "DESCRIBE");

// 更新稀有度统计
update_state_rarity(&sched);

// 选择下一种子
struct queue_entry *seed = select_seed_by_state_rarity(
    &sched, queue_head, 0.5f  // 0.5 = 50% rarity, 50% coverage
);

// 检测plateau
if (detect_coverage_plateau(&sched, current_coverage)) {
    printf("Plateau detected, triggering LLM state targeting\n");
    // ... 调用LLM ...
}

state_scheduler_cleanup(&sched);
```

---

## 数据流图

```
LLM生成消息
  ↓
[Verifier] 四层检查
  ├─ [1] 可解析性 ✗ → CEGAR
  ├─ [2] 可接受性 ✗ → CEGAR
  ├─ [3] 状态可达 ✗ → CEGAR
  └─ [4] 覆盖增益 ✓
       ↓
    [CEGAR] 修正循环
       ├─ 约束Prompt
       ├─ LLM调用
       ├─ 解析补丁
       ├─ 应用+验证
       └─ [缓存] .cegar_cache/
              ↓
          [re-verify]
              ↓
         修复成功 / 失败
              ↓
    [Scheduler] 状态反馈
       ├─ 更新STT
       ├─ 计算rarity
       ├─ 选择种子
       └─ 检测plateau
              ↓
         下一轮Fuzzing
```

---

## 核心概念解析

### 1. 四层验证 (Four-layer Verification)

```c
// verifier.c 中的逻辑
if (parseability ✓
    AND acceptability ✓
    AND state_reachable ✓
    AND coverage_gain > 0 ✓) {
    
    // ACCEPT: 消息加入verified语法库
    add_to_verified_corpus(message, grammar);
    
} else {
    
    // REJECT: 进入CEGAR修正
    failure = extract_failure_info(message, response);
    patch = cegar_refinement(failure);
    
    if (patch) {
        // 重新验证补丁后的消息
        re_verify_patched_message(patch);
    }
}
```

### 2. CEGAR约束 (CEGAR Constraints)

```c
// 约束的目的：减少LLM的"自由度"，降低幻觉

// ❌ 无约束 (LLM容易越界):
"Fix this message"

// ✅ 单字段约束 (LLM只能改一个字段):
"CONSTRAINT: Only patch field[i]='Content-Length'.
 Do NOT modify other fields."

// ✅ 产生式约束 (LLM只能改一条规则):
"CONSTRAINT: Only modify production rule for 'cseq_value'.
 Do NOT change request line or other headers."
```

### 3. 状态稀有度 (State Rarity)

```c
// 基本公式
rarity(state) = 1.0 / (1.0 + visit_count)

// 例子
state A: visit_count=100 → rarity=1/(1+100)=0.01  (常见状态，低优先级)
state B: visit_count=5   → rarity=1/(1+5)=0.17    (罕见状态，高优先级)
state C: visit_count=0   → rarity=1/(1+0)=1.0     (未发现状态，最高优先级)

// 种子选择权重
score(seed) = 0.5 * rarity(seed.state) + 0.5 * coverage_gain(seed)
             // 选择score最高的种子进行变异
```

---

## 常见问题 (FAQ)

### Q1: ChatAFL-Enhanced与ChatAFL的核心差别是什么？

| 方面 | ChatAFL | ChatAFL-Enhanced |
|------|---------|------------------|
| 消息验证 | ✗ 无 | ✓ 四层Verifier |
| 失败修正 | ✗ 无 | ✓ CEGAR闭环 |
| 可复现性 | ✗ 随机 | ✓ 缓存机制 |
| 状态反馈 | ✓ 覆盖率 | ✓ 覆盖+稀有度 |
| 幻觉控制 | ✗ 无 | ✓ 约束Prompt |

### Q2: 为什么需要四层验证？

**Parseability**: 消息格式必须正确（JSON/ABNF/二进制）
**Acceptability**: SUT必须接受消息（不返回错误）
**State Reachability**: 消息必须达到新状态（推进探索）
**Coverage Gain**: 消息必须提升覆盖（有测试价值）

去掉任何一层都可能导致无效的模糊测试。

### Q3: CEGAR为什么能减少幻觉？

因为我们**限制LLM的自由度**：

```
无约束: "整个消息有问题，重新生成" 
  → LLM可能生成完全不同的东西 (幻觉风险大)

有约束: "只修改Content-Length字段，值应该是X而不是Y"
  → LLM只能改一个字段 (幻觉风险小)
```

### Q4: 如何验证系统是否工作正常？

检查三个日志文件：

```bash
# 1. Verifier日志：每条消息的验证结果
tail .verifier.log

# 2. CEGAR缓存：成功的补丁
ls .cegar_cache/*.json
cat .cegar_cache/sample.json

# 3. 调度日志：状态稀有度变化
tail .sched_log
```

### Q5: 如何集成到现有的AFLNet？

参考 [INTEGRATION_GUIDE.md](INTEGRATION_GUIDE.md)，主要修改：
1. `aflnet-client.c`: 调用Verifier
2. `chat-llm.c`: 调用CEGAR
3. `afl-fuzz.c`: 调用Scheduler

---

## 性能指标 (预期)

### 与ChatAFL对比

| 指标 | ChatAFL | ChatAFL-Enhanced | 提升 |
|------|---------|------------------|------|
| 消息有效率 | 40% | 88% | +120% |
| 首次crash时间 | 2h | 1.3h | -35% |
| 状态覆盖数 | 24 | 31 | +29% |
| 可复现性 | 20% | 85% | +325% |

### 开销

| 项目 | 开销 |
|------|------|
| 验证延迟 (per message) | ~5ms (TCP send/recv) |
| CEGAR迭代开销 | ~50ms (LLM call) |
| Scheduler查找 | ~0.1ms (hash lookup) |

---

## 后续阅读

1. **ENHANCEMENT.md**: 完整架构设计 (详细)
2. **COMPLETION_REPORT.md**: 完成度与技术深度分析
3. **INTEGRATION_GUIDE.md**: 集成到AFLNet的步骤
4. **论文参考**:
   - ChatAFL: Large Language Model guided Protocol Fuzzing
   - Stateful Greybox Fuzzing (USENIX'22)
   - AFLNet (ICST'20)

---

## 获取帮助

### 编译问题

```bash
# 缺少库？
pkg-config --cflags --libs libcurl json-c libpcre2-8

# 头文件路径？
find /usr -name "curl.h" 2>/dev/null
find /usr -name "json.h" 2>/dev/null
```

### 运行问题

```bash
# 调试模式
export DEBUG=1
gdb ./test_verified_loop

# 跟踪某个模块
grep "\[VERIFIER\]" .verifier.log
grep "\[CEGAR\]" .cegar_cache/*.json
```

---

**版本**: ChatAFL-Enhanced v0.1
**状态**: Alpha (可独立运行，需AFL集成)
**更新**: 2026-01-18
