# ChatAFL 增强集成方案

## 概述
将 test.c 中的"假设-验证-反例驱动修正-状态导向调度"机制集成到 ChatAFL 框架中。

## 🎯 核心目标
解决 LLM-fuzzing 的审稿痛点：
1. **幻觉控制**: 通过验证器强制约束
2. **可复现性**: 状态追踪 + 反例日志
3. **可度量性**: 覆盖增益 + 状态转移指标

---

## 📂 方案一：模块化扩展（推荐）⭐

### 架构设计
```
ChatAFL/
├── afl-fuzz.c           (主循环 - 需要修改)
├── aflnet.c             (网络层 - 已存在)
├── chat-llm.c/.h        (LLM API - 已存在)
├── verifier.c/.h        (新增) ← 验证器模块
├── cegar.c/.h           (新增) ← 反例驱动修正
├── state-scheduler.c/.h (新增) ← 状态导向调度
└── protocol-spec.h      (新增) ← 协议规范定义
```

### 实施步骤

#### 步骤1: 创建核心数据结构 (protocol-spec.h)
```c
#ifndef __PROTOCOL_SPEC_H
#define __PROTOCOL_SPEC_H

// 从 test.c 迁移过来的核心结构
typedef struct {
    char name[32];
    int default_port;
    char json_schema[2048];
    char template_str[1024];
    char mandatory_fields[3][32];
    bool recv_banner_first;
    // ... 其他字段
} ProtocolSpec;

typedef struct {
    int status_code;
    char body[1024];
    char state_hash[256];
} RealResponse;

#endif
```

#### 步骤2: 实现验证器模块 (verifier.c/.h)
**新文件**: `verifier.h`
```c
#ifndef __VERIFIER_H
#define __VERIFIER_H

#include "protocol-spec.h"

typedef enum {
    VFY_OK = 0,
    VFY_EMPTY_INPUT,
    VFY_TOO_LARGE,
    VFY_NO_JSON_OBJECT,
    VFY_MISSING_MANDATORY,
    VFY_CONSTRAINT_MISMATCH,
    VFY_EXCESSIVE_FIELDS,
    VFY_NESTING_TOO_DEEP
} VerifierRejectReason;

// 核心API
bool verify_json_grammar(const char* json_input, ProtocolSpec* spec);
const char* verifier_reason_str(VerifierRejectReason r);
VerifierRejectReason get_last_verifier_reason();

// 辅助函数
bool is_rejection_response(int status_code, const char* body, const char* proto_name);
ProtoSemanticState extract_protocol_state(const char* proto_name, int status_code, const char* body);

#endif
```

**新文件**: `verifier.c`
- 从 test.c Lines 1240-1400 迁移验证器逻辑
- 从 test.c Lines 139-195 迁移拒绝分类器

#### 步骤3: 实现CEGAR模块 (cegar.c/.h)
**新文件**: `cegar.h`
```c
#ifndef __CEGAR_H
#define __CEGAR_H

#include "protocol-spec.h"

// 反例最小化
int minimize_counterexample(const char* original_json, RealResponse* orig_res, 
                             ProtocolSpec* spec, char* out, size_t max_len);

// JSON patch应用
int apply_json_patch(const char* orig, const char* patch, char* out, size_t max_len);

// 反例驱动修正（调用LLM）
char* refine_hypothesis_with_cegar(const char* failed_json, RealResponse* failure, 
                                   ProtocolSpec* spec);

#endif
```

**新文件**: `cegar.c`
- 从 test.c Lines 480-660 迁移 minimize/patch 逻辑
- 新增函数与 chat-llm.c 接口

#### 步骤4: 实现状态调度器 (state-scheduler.c/.h)
**新文件**: `state-scheduler.h`
```c
#ifndef __STATE_SCHEDULER_H
#define __STATE_SCHEDULER_H

#define MAX_STATES 256
#define MAX_CORPUS 256

typedef struct { 
    char json[4096]; 
    char edge[512]; 
    char target_state[256]; 
    bool occupied; 
} CorpusEntry;

typedef struct { 
    char state[256]; 
    int count; 
} StateCount;

// 状态管理
void increment_state_count(const char* state);
int get_state_count(const char* state);
int pick_least_visited_state(char* out, size_t out_len);

// Corpus管理
void save_to_corpus(const char* json, const char* edge_info);
int pick_corpus_for_low_coverage(char* out, size_t out_len);

#endif
```

**新文件**: `state-scheduler.c`
- 从 test.c Lines 206-290 迁移状态管理逻辑
- 集成到 AFL queue 调度

#### 步骤5: 修改 afl-fuzz.c 主循环
**关键修改点**:

1. **引入头文件** (在顶部添加):
```c
#include "verifier.h"
#include "cegar.h"
#include "state-scheduler.h"
#include "protocol-spec.h"
```

2. **在 `fuzz_one()` 函数中集成验证器**:
```c
// 在发送测试用例前验证
if (!verify_json_grammar(test_case_json, &protocol_spec)) {
    VerifierRejectReason reason = get_last_verifier_reason();
    fprintf(plot_file, "[%llu] VERIFIER_REJECT: %s\n", 
            total_execs, verifier_reason_str(reason));
    goto abandon_entry;  // AFL的existing机制
}
```

3. **在响应处理中集成CEGAR**:
```c
// 检测到拒绝响应时触发CEGAR
if (is_rejection_response(status_code, response_body, protocol_spec.name)) {
    char* refined = refine_hypothesis_with_cegar(queue_cur->fname, 
                                                  &response, 
                                                  &protocol_spec);
    if (refined) {
        add_to_queue(refined, len, 0);  // 添加修正后的用例
        free(refined);
    }
}
```

4. **集成状态调度**:
```c
// 在 cull_queue() 或选择下一个用例时
if (queued_discovered == 0 && cycles_wo_finds > 10) {
    // Plateau检测
    char low_coverage_case[4096];
    if (pick_corpus_for_low_coverage(low_coverage_case, sizeof(low_coverage_case))) {
        add_to_queue(low_coverage_case, strlen(low_coverage_case), 0);
    }
}
```

#### 步骤6: 扩展 chat-llm.c
在 `chat-llm.c` 中添加新的 prompt 构造函数:

```c
// 新增函数
char* construct_prompt_for_refinement(const char* failed_json, 
                                      int error_code, 
                                      const char* error_body,
                                      const char* schema);

char* construct_prompt_for_patch(const char* minimized_json,
                                 int error_code,
                                 const char* error_body);

char* construct_prompt_for_state_exploration(const char* target_state,
                                             const char* current_state,
                                             const char* schema);
```

#### 步骤7: 更新 Makefile
```makefile
# 添加新的源文件
SRCS += verifier.c cegar.c state-scheduler.c

# 添加头文件依赖
afl-fuzz: afl-fuzz.c verifier.h cegar.h state-scheduler.h protocol-spec.h
	$(CC) $(CFLAGS) $^ -o $@ -lcurl -ljson-c -lpcre2-8
```

---

## 📂 方案二：独立工具链（备选）

### 架构
```
test.c (独立fuzzer) ←→ seed_dir ←→ afl-fuzz (ChatAFL主程序)
                      ↑           ↓
                   refined    原始seeds
```

### 工作流程
1. **初始阶段**: test.c 基于LLM生成初始语法和种子
2. **验证阶段**: test.c 运行验证器，过滤无效输入
3. **传递阶段**: 验证通过的用例写入 `seeds/` 目录
4. **主fuzzing**: ChatAFL (afl-fuzz) 读取并变异这些种子
5. **反馈阶段**: ChatAFL发现的新状态/崩溃反馈给test.c进行CEGAR修正

### 优点
- 最小侵入性
- 可以独立演进
- 易于调试

### 缺点
- 反馈延迟较大
- 无法实时利用状态信息
- 性能开销（需要文件IO）

---

## 🎯 推荐实施路线

### 第1-2周: 基础架构
- [ ] 创建 4 个新模块（verifier/cegar/state-scheduler/protocol-spec）
- [ ] 迁移 test.c 的核心函数到新模块
- [ ] 编写单元测试（验证器、patch应用等）

### 第3-4周: AFL集成
- [ ] 修改 afl-fuzz.c 集成验证器
- [ ] 实现状态追踪和corpus管理
- [ ] 扩展 chat-llm.c 的 prompt 函数

### 第5周: CEGAR闭环
- [ ] 实现反例最小化
- [ ] 集成patch-based修正
- [ ] 添加plateau检测和LLM触发逻辑

### 第6周: 评估与优化
- [ ] 对比实验（原始ChatAFL vs 增强版）
- [ ] 性能优化（缓存、并行化）
- [ ] 撰写实验日志和可复现脚本

---

## 📊 可度量性增强

### 新增指标
1. **验证器指标**:
   - `verifier_reject_count`: 被验证器拒绝的用例数
   - `reject_reasons_histogram`: 各类拒绝原因的分布

2. **CEGAR指标**:
   - `refinement_success_rate`: 修正成功率
   - `patch_size_avg`: 平均patch大小（衡量局部性）
   - `minimization_ratio`: 反例最小化压缩率

3. **状态探索指标**:
   - `unique_states`: 发现的唯一状态数
   - `state_transition_coverage`: 状态转移边覆盖率
   - `plateau_count`: 停滞次数
   - `llm_triggered_breakthroughs`: LLM触发的突破次数

### 日志格式
```json
{
  "timestamp": 1234567890,
  "event": "verifier_reject",
  "reason": "MISSING_MANDATORY",
  "test_case_id": 42
}
{
  "timestamp": 1234567891,
  "event": "cegar_refinement",
  "original_size": 256,
  "minimized_size": 128,
  "patch_fields": ["command", "args"]
}
{
  "timestamp": 1234567892,
  "event": "new_state",
  "state_hash": "S_230_authenticated",
  "transition": "S_220_connected -> S_230_authenticated"
}
```

---

## 🔍 关键差异点总结

| 特性 | test.c (独立) | ChatAFL集成后 |
|------|--------------|---------------|
| 网络层 | 自己实现TCP连接 | 复用aflnet.c的状态机 |
| 变异策略 | 纯LLM生成 | AFL变异 + LLM补充 |
| 覆盖反馈 | 基于状态码 | 基于代码覆盖率(bitmap) |
| 执行速度 | ~10 exec/s (LLM限制) | ~1000 exec/s (AFL主导) |
| 适用场景 | 冷启动、协议探索 | 高效漏洞挖掘 |

**建议**: 采用**方案一（模块化扩展）**，让 test.c 的创新机制与 AFL 的高效引擎结合。

---

## 📝 实施检查清单

- [ ] 确认所有依赖库已安装 (libcurl, libjson-c, libpcre2-8)
- [ ] 创建 4 个新的 .c/.h 文件
- [ ] 修改 Makefile 添加编译规则
- [ ] 在 afl-fuzz.c 中添加 3 个集成点
- [ ] 扩展 chat-llm.c 添加 3 个新 prompt 函数
- [ ] 编写测试脚本验证各模块独立功能
- [ ] 端到端测试：FTP/SMTP/HTTP 协议
- [ ] 准备对比实验脚本 (原始ChatAFL vs 增强版)
- [ ] 生成可复现的日志和指标

---

## 🚀 快速开始命令

```bash
# 1. 创建新分支
cd /home/ckt/Documents/000_2026_dev/research_laboratory/ChatAFL-master/ChatAFL
git checkout -b feature/hypothesis-verification

# 2. 创建新模块
touch verifier.c verifier.h cegar.c cegar.h state-scheduler.c state-scheduler.h protocol-spec.h

# 3. 迁移代码 (从test.c复制核心函数)
# ... (手动或使用脚本)

# 4. 编译测试
make clean
make

# 5. 单元测试
./test_verifier   # 测试验证器
./test_cegar      # 测试CEGAR
./test_scheduler  # 测试调度器

# 6. 集成测试
./afl-fuzz -i seeds/ -o output/ -N tcp://127.0.0.1/21 -P FTP -D 10000 -K -R -c cleanup.sh -- /path/to/ftp-server
```

---

## 📚 参考文献引用

在论文中引用以下工作以支撑创新性：

1. **Stateful Greybox Fuzzing** (USENIX Security '22)
   - 状态转移树 (STT) 概念
   - 状态导向调度策略

2. **CEGAR** (Counterexample-Guided Abstraction Refinement)
   - 形式化方法的经典技术
   - 应用于fuzzing的新颖性

3. **ChatAFL** (原论文)
   - LLM与fuzzing结合的基础
   - 本工作作为扩展和增强

---

## ❓ FAQ

**Q: 为什么不直接用test.c替换afl-fuzz?**
A: AFL的变异引擎和覆盖反馈机制经过多年优化，性能远超纯LLM方法。应该是"LLM辅助AFL"而非"LLM替代AFL"。

**Q: 验证器会不会降低fuzzing速度?**
A: 验证器是轻量级的纯C实现，每次检查 < 1ms。相比发现一个崩溃节省的调试时间，开销可以忽略。

**Q: CEGAR会不会过度依赖LLM导致不可复现?**
A: 通过强制要求patch-based修正（最多3个字段）、记录完整的refinement日志、使用固定seed，可以保证复现性。

**Q: 如何验证状态探索的有效性?**
A: 对比指标：
  - 状态覆盖率 vs 基线
  - 到达稀有状态的时间
  - 发现漏洞的状态分布
