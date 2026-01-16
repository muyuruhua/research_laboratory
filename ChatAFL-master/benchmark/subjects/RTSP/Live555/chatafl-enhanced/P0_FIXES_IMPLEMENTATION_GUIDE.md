# ChatAFL-Enhanced P0关键修复实施指南

**日期**: 2026年1月14日  
**目标**: 修复3个P0 Critical问题，使系统达到Tier-1会议投稿标准

---

## 修复概览

| 问题 | 工作量 | 难度 | 状态 |
|-----|--------|------|------|
| **P0-1**: 覆盖增益验证 | 2-3天 | 中等 | ⚙️ 进行中 |
| **P0-2**: 固定随机种子 | 0.5天 | 简单 | ⏳ 待开始 |
| **P0-3**: LLM调用日志 | 1-2天 | 简单-中等 | ⏳ 待开始 |

---

## P0-1: 覆盖增益验证（Coverage Gain Verification）

### 问题描述

**当前代码** (`afl-fuzz.c:1310-1330`):
```c
/* ChatAFL-Enhanced GAP-3: 保存触发新状态转移的测试用例到corpus */
if (q && q->fname) {
  char edge_info[256];
  snprintf(edge_info, sizeof(edge_info), "%u -> %u", prevStateID, curStateID);
  
  /* ❌ 问题：无条件保存，没有覆盖判断！ */
  FILE *test_fp = fopen(q->fname, "rb");
  if (test_fp) {
    // ... 读取文件 ...
    save_to_corpus(test_content, edge_info);  // ❌ 无条件保存
  }
}
```

**问题影响**:
1. Corpus膨胀：所有触发边的用例都被保存，即使没有新覆盖
2. 无法量化：审稿人会质疑"如何证明这些用例有价值？"
3. 违反验证器Layer 4要求：覆盖/状态覆盖提升才入库

### 修复方案

#### 步骤1: 更新`save_to_corpus`函数签名

**state-scheduler.h**:
```c
/**
 * @brief 保存触发新状态转移的测试用例到corpus（带覆盖增益验证）
 * 
 * **P0关键修复**: 只有在有覆盖/状态增益时才保存
 * 
 * @param json 测试用例JSON
 * @param edge_info 状态转移边信息（如 "S_220 -> S_230"）
 * @param virgin_bits AFL覆盖bitmap（用于计算边覆盖增益）
 * @param map_size Bitmap大小（通常64KB）
 * @param prev_state_count 之前的状态数量
 * @param new_state_count 新的状态数量
 * @return true=已保存（有增益）, false=拒绝（无增益）
 * 
 * 增益判断公式：
 *   has_gain = (new_edge_coverage > prev_edge_coverage) ||
 *              (new_state_count > prev_state_count)
 * 
 * 覆盖计算：
 *   edge_coverage = count(virgin_bits[i] != 255)
 */
bool save_to_corpus(const char* json, 
                    const char* edge_info,
                    const unsigned char* virgin_bits,
                    unsigned int map_size,
                    unsigned int prev_state_count,
                    unsigned int new_state_count);
```

#### 步骤2: 实现覆盖增益计算

**state-scheduler.c** (已部分实现):
```c
/**
 * @brief 计算bitmap中的非255字节数（边覆盖度量）
 * 
 * AFL的virgin_bits: 255=未覆盖, <255=已覆盖
 * 此函数统计已覆盖的边数量
 */
static unsigned int count_non_255_bytes(const unsigned char* virgin_bits, 
                                        unsigned int map_size) {
    if (!virgin_bits || map_size == 0) return 0;
    
    unsigned int covered_edges = 0;
    for (unsigned int i = 0; i < map_size; i++) {
        if (virgin_bits[i] != 255) {
            covered_edges++;
        }
    }
    
    return covered_edges;
}

bool save_to_corpus(const char* json, 
                    const char* edge_info,
                    const unsigned char* virgin_bits,
                    unsigned int map_size,
                    unsigned int prev_state_count,
                    unsigned int new_state_count) {
    if (!json || corpus_entries >= MAX_CORPUS) {
        return false;
    }
    
    /* 去重检查 */
    for (int i = 0; i < corpus_entries; i++) {
        if (strcmp(corpus[i].json, json) == 0) {
            return false;
        }
    }
    
    /* ===== 关键：计算增益 ===== */
    
    /* 1. 边覆盖增益 */
    unsigned int current_edge_coverage = 0;
    unsigned int prev_edge_coverage = 0;
    
    if (virgin_bits && map_size > 0) {
        current_edge_coverage = count_non_255_bytes(virgin_bits, map_size);
        
        /* 获取上次覆盖（使用静态变量保存全局状态） */
        static unsigned int last_edge_coverage = 0;
        prev_edge_coverage = last_edge_coverage;
        last_edge_coverage = current_edge_coverage;
    }
    
    /* 2. 状态覆盖增益 */
    unsigned int state_gain = (new_state_count > prev_state_count) ?
                               (new_state_count - prev_state_count) : 0;
    
    unsigned int edge_gain = (current_edge_coverage > prev_edge_coverage) ?
                              (current_edge_coverage - prev_edge_coverage) : 0;
    
    /* 3. 增益判断 */
    bool has_gain = (edge_gain > 0) || (state_gain > 0);
    
    if (!has_gain) {
        return false; /* 无增益：拒绝保存 */
    }
    
    /* 4. 有增益：保存 */
    strncpy(corpus[corpus_entries].json, json, sizeof(corpus[0].json) - 1);
    corpus[corpus_entries].json[sizeof(corpus[0].json) - 1] = '\0';
    
    if (edge_info) {
        /* 增强的边信息：包含增益度量 */
        char enhanced_edge_info[256];
        snprintf(enhanced_edge_info, sizeof(enhanced_edge_info),
                 "%s (edge+%u, state+%u)",
                 edge_info, edge_gain, state_gain);
        
        strncpy(corpus[corpus_entries].edge, enhanced_edge_info, 
                sizeof(corpus[0].edge) - 1);
        corpus[corpus_entries].edge[sizeof(corpus[0].edge) - 1] = '\0';
    }
    
    corpus[corpus_entries].occupied = true;
    corpus_entries++;
    
    return true;
}
```

#### 步骤3: 更新调用点

**afl-fuzz.c** (需修改):
```c
/* 当前代码（第1310行左右） */
if (q && q->fname) {
  char edge_info[256];
  snprintf(edge_info, sizeof(edge_info), "%u -> %u", prevStateID, curStateID);
  
  FILE *test_fp = fopen(q->fname, "rb");
  if (test_fp) {
    fseek(test_fp, 0, SEEK_END);
    long test_size = ftell(test_fp);
    fseek(test_fp, 0, SEEK_SET);
    
    if (test_size > 0 && test_size < 10000) {
      char *test_content = ck_alloc(test_size + 1);
      fread(test_content, 1, test_size, test_fp);
      test_content[test_size] = '\0';
      
      /* ===== 修改：添加覆盖增益验证 ===== */
      unsigned int prev_state_cnt = state_ids_count - 1; /* 新边发现前的状态数 */
      unsigned int new_state_cnt = state_ids_count;
      
      bool saved = save_to_corpus(
        test_content, 
        edge_info,
        virgin_bits,        /* AFL的覆盖bitmap */
        MAP_SIZE,           /* 通常64KB */
        prev_state_cnt,
        new_state_cnt
      );
      
      if (saved) {
        ACTF("[CORPUS] Saved edge %u->%u with gain", prevStateID, curStateID);
      } else {
        /* 无增益：不保存 */
      }
      
      ck_free(test_content);
    }
    fclose(test_fp);
  }
}
```

#### 验证方法

1. **编译测试**:
```bash
cd /home/ckt/.../ChatAFL-Enhanced
make clean && make afl-fuzz 2>&1 | grep -i error
```

2. **运行测试**:
```bash
./afl-fuzz -d -i seeds -o out -N tcp://127.0.0.1/21 -P FTP -D 10000 \
  -E -K -r 42 -- ./pure-ftpd -S 21

# 检查corpus大小
ls -lh out/corpus/ | wc -l
grep "CORPUS" out/fuzzer_log
```

3. **预期结果**:
- Corpus大小显著小于baseline（减少50-70%）
- 每个entry的edge_info包含增益度量（如 "220->230 (edge+5, state+1)"）
- fuzzer_log显示拒绝无增益的保存

---

## P0-2: 固定随机种子（Fixed Random Seed）

### 问题描述

**当前代码** (`afl-fuzz.c:10857`):
```c
gettimeofday(&tv, &tz);
srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());  // ❌ 不确定性
```

**问题影响**:
1. **实验不可复现**：每次运行结果不同
2. **审稿人无法验证**：无法重现论文中的实验数据
3. **对比实验失效**：无法公平对比不同版本

### 修复方案

#### 步骤1: 添加命令行参数

**afl-fuzz.c** (main函数，约10850行):
```c
/* 添加全局变量（文件顶部，约第100行） */
static u64 random_seed = 0;  /* 0表示自动生成 */

/* 修改getopt字符串（约10862行） */
while ((opt = getopt(argc, argv, 
       "+i:o:f:m:t:T:dnCB:S:M:x:QN:D:W:w:e:P:KEq:s:RFc:l:r:")) > 0)
  //                                                          ^^^ 新增-r参数
  
  switch (opt) {
    
    /* ... 其他case ... */
    
    /* 新增case */
    case 'r':  // --random-seed
      random_seed = strtoull(optarg, NULL, 10);
      if (random_seed == 0) {
        FATAL("Random seed must be non-zero");
      }
      break;
    
    /* ... */
  }
```

#### 步骤2: 修改随机数初始化

**afl-fuzz.c** (约10857行):
```c
/* 原代码 */
// gettimeofday(&tv, &tz);
// srandom(tv.tv_sec ^ tv.tv_usec ^ getpid());

/* 修改为 */
if (random_seed == 0) {
  /* 未指定seed：使用时间戳（并记录到日志） */
  gettimeofday(&tv, &tz);
  random_seed = ((u64)tv.tv_sec << 32) | tv.tv_usec;
  random_seed ^= getpid();
  
  ACTF("Random seed (auto-generated): %llu", random_seed);
  
  /* 记录到fuzzer_log */
  FILE *log_f = fopen(alloc_printf("%s/fuzzer_log", out_dir), "a");
  if (log_f) {
    fprintf(log_f, "[SEED] %llu (auto-generated)\n", random_seed);
    fclose(log_f);
  }
} else {
  /* 用户指定seed：确定性复现 */
  ACTF("Random seed (user-specified): %llu", random_seed);
  
  FILE *log_f = fopen(alloc_printf("%s/fuzzer_log", out_dir), "a");
  if (log_f) {
    fprintf(log_f, "[SEED] %llu (user-specified)\n", random_seed);
    fclose(log_f);
  }
}

/* 设置随机种子 */
srandom((unsigned int)(random_seed & 0xFFFFFFFF));

/* 同时写入fuzzer_stats */
/* （在write_stats_file函数中添加） */
fprintf(f, "random_seed         : %llu\n", random_seed);
```

#### 步骤3: 更新usage说明

**afl-fuzz.c** (usage函数，约10300行):
```c
SAYF(
  "  -r seed       - fixed random seed for reproducibility (default: auto)\n\n"
);
```

#### 验证方法

1. **测试自动seed**:
```bash
./afl-fuzz -i seeds -o out1 ... -- target &
./afl-fuzz -i seeds -o out2 ... -- target &

# 检查seeds不同
grep "random_seed" out1/fuzzer_stats
grep "random_seed" out2/fuzzer_stats
```

2. **测试固定seed**:
```bash
./afl-fuzz -r 42 -i seeds -o out1 ... -- target &
./afl-fuzz -r 42 -i seeds -o out2 ... -- target &

# 检查结果相同
diff out1/queue/id:000010* out2/queue/id:000010*
```

---

## P0-3: LLM调用日志（LLM Call Logging）

### 问题描述

**当前代码** (`afl-fuzz.c:6690`):
```c
char *llm_response = chat_with_llm(patch_prompt, "gpt-3.5-turbo", 2, 0.7);
// ❌ 没有记录：
// 1. patch_prompt的完整内容
// 2. llm_response的原始JSON
// 3. 请求时间戳
// 4. API延迟
// 5. token消耗
```

**问题影响**:
1. **不可复现**：审稿人无法验证LLM的决策
2. **成本不可度量**：无法统计API调用次数和费用
3. **调试困难**：无法分析LLM失败原因

### 修复方案

#### 步骤1: 定义日志结构

**chat-llm.h** (新增):
```c
/**
 * @brief LLM调用日志结构（可复现性关键）
 * 
 * 存储LLM的完整上下文，用于：
 * 1. 审稿人重现实验
 * 2. 调试LLM失败
 * 3. 成本统计
 */
typedef struct {
  /* 请求信息 */
  char prompt[8192];           /* 完整prompt */
  char model[64];              /* 模型版本（如 gpt-3.5-turbo-0613） */
  int max_tokens;              /* token上限 */
  float temperature;           /* 温度参数 */
  
  /* 响应信息 */
  char response[8192];         /* LLM原始响应 */
  char parsed_output[4096];    /* 解析后的输出（如JSON patch） */
  
  /* 元数据 */
  time_t request_time;         /* Unix时间戳 */
  double latency_ms;           /* API延迟（毫秒） */
  int prompt_tokens;           /* 输入token数 */
  int completion_tokens;       /* 输出token数 */
  int total_tokens;            /* 总token数 */
  
  /* 上下文 */
  char trigger_type[64];       /* 触发类型（如 "CEGAR-patch", "Plateau-sequence"） */
  unsigned int error_code;     /* 触发的错误码（CEGAR专用） */
  char state_context[256];     /* 状态上下文（Plateau专用） */
} LLMCallLog;

/**
 * @brief 记录LLM调用到JSON日志文件
 * @param log 日志结构
 * @param log_file 日志文件路径（追加模式）
 * @return true=成功, false=失败
 * 
 * 输出格式：每行一个JSON对象（JSONL格式）
 * 便于后续分析（jq, pandas）
 */
bool log_llm_call(const LLMCallLog *log, const char *log_file);

/**
 * @brief 从JSON日志文件加载所有LLM调用
 * @param log_file 日志文件路径
 * @param out_logs 输出数组
 * @param max_logs 数组大小
 * @return 实际加载的日志数
 * 
 * 用于重放实验或离线分析
 */
int load_llm_logs(const char *log_file, LLMCallLog *out_logs, int max_logs);
```

#### 步骤2: 实现日志记录

**chat-llm.c** (新增):
```c
#include <json-c/json.h>
#include <sys/time.h>

/**
 * @brief JSON转义（处理特殊字符）
 */
static char* escape_json_string(const char *str) {
    if (!str) return strdup("null");
    
    /* 使用json-c库自动转义 */
    struct json_object *jstr = json_object_new_string(str);
    const char *escaped = json_object_to_json_string(jstr);
    
    char *result = strdup(escaped);
    json_object_put(jstr);
    
    return result;
}

/**
 * @brief 记录LLM调用到JSONL文件
 */
bool log_llm_call(const LLMCallLog *log, const char *log_file) {
    if (!log || !log_file) return false;
    
    FILE *f = fopen(log_file, "a");
    if (!f) {
        fprintf(stderr, "[LLM-LOG] Failed to open %s\n", log_file);
        return false;
    }
    
    /* 构造JSON对象 */
    struct json_object *jlog = json_object_new_object();
    
    json_object_object_add(jlog, "timestamp", 
                          json_object_new_int64(log->request_time));
    json_object_object_add(jlog, "trigger_type", 
                          json_object_new_string(log->trigger_type));
    json_object_object_add(jlog, "model", 
                          json_object_new_string(log->model));
    json_object_object_add(jlog, "temperature", 
                          json_object_new_double(log->temperature));
    json_object_object_add(jlog, "max_tokens", 
                          json_object_new_int(log->max_tokens));
    
    json_object_object_add(jlog, "prompt", 
                          json_object_new_string(log->prompt));
    json_object_object_add(jlog, "response", 
                          json_object_new_string(log->response));
    json_object_object_add(jlog, "parsed_output", 
                          json_object_new_string(log->parsed_output));
    
    json_object_object_add(jlog, "latency_ms", 
                          json_object_new_double(log->latency_ms));
    json_object_object_add(jlog, "prompt_tokens", 
                          json_object_new_int(log->prompt_tokens));
    json_object_object_add(jlog, "completion_tokens", 
                          json_object_new_int(log->completion_tokens));
    json_object_object_add(jlog, "total_tokens", 
                          json_object_new_int(log->total_tokens));
    
    if (log->error_code > 0) {
        json_object_object_add(jlog, "error_code", 
                              json_object_new_int(log->error_code));
    }
    
    if (strlen(log->state_context) > 0) {
        json_object_object_add(jlog, "state_context", 
                              json_object_new_string(log->state_context));
    }
    
    /* 写入文件（JSONL格式：每行一个JSON） */
    fprintf(f, "%s\n", json_object_to_json_string_ext(jlog, JSON_C_TO_STRING_PLAIN));
    
    json_object_put(jlog);
    fclose(f);
    
    return true;
}
```

#### 步骤3: 集成到调用点

**afl-fuzz.c** (CEGAR调用点，约6690行):
```c
/* 修改前 */
// char *refined_json = chat_with_llm(patch_prompt, "gpt-3.5-turbo", 2, 0.7);

/* 修改后 */
struct timeval tv_start, tv_end;
gettimeofday(&tv_start, NULL);

LLMCallLog llm_log;
memset(&llm_log, 0, sizeof(llm_log));

/* 填充请求信息 */
strncpy(llm_log.prompt, patch_prompt, sizeof(llm_log.prompt) - 1);
strncpy(llm_log.model, "gpt-3.5-turbo", sizeof(llm_log.model) - 1);
llm_log.max_tokens = 500;
llm_log.temperature = 0.7;
strncpy(llm_log.trigger_type, "CEGAR-patch", sizeof(llm_log.trigger_type) - 1);
llm_log.error_code = state_sequence[i];
llm_log.request_time = time(NULL);

/* 调用LLM */
char *refined_json = chat_with_llm(patch_prompt, "gpt-3.5-turbo", 2, 0.7);

gettimeofday(&tv_end, NULL);
llm_log.latency_ms = (tv_end.tv_sec - tv_start.tv_sec) * 1000.0 +
                      (tv_end.tv_usec - tv_start.tv_usec) / 1000.0;

/* 填充响应信息 */
if (refined_json) {
  strncpy(llm_log.response, refined_json, sizeof(llm_log.response) - 1);
  strncpy(llm_log.parsed_output, refined_json, sizeof(llm_log.parsed_output) - 1);
  
  /* 估算token数（简化版：1 token ≈ 4 chars） */
  llm_log.prompt_tokens = strlen(patch_prompt) / 4;
  llm_log.completion_tokens = strlen(refined_json) / 4;
  llm_log.total_tokens = llm_log.prompt_tokens + llm_log.completion_tokens;
}

/* 记录到日志 */
char *log_path = alloc_printf("%s/llm_calls.jsonl", out_dir);
log_llm_call(&llm_log, log_path);
ck_free(log_path);

/* 继续使用refined_json... */
```

#### 验证方法

1. **检查日志文件**:
```bash
# 运行fuzzer
./afl-fuzz ... -E -K ...

# 检查日志
cat out/llm_calls.jsonl | jq .
cat out/llm_calls.jsonl | jq '.total_tokens' | awk '{sum+=$1} END {print "Total tokens:", sum}'
```

2. **成本统计**:
```bash
# 计算总成本（GPT-3.5-turbo定价）
cat out/llm_calls.jsonl | jq '
  .prompt_tokens * 0.5 / 1000000 + 
  .completion_tokens * 1.5 / 1000000
' | awk '{sum+=$1} END {printf "Total cost: $%.2f\n", sum}'
```

3. **重放分析**:
```python
import json

# 加载日志
with open('out/llm_calls.jsonl') as f:
    logs = [json.loads(line) for line in f]

# 统计分析
print(f"Total LLM calls: {len(logs)}")
print(f"Avg latency: {sum(log['latency_ms'] for log in logs) / len(logs):.2f}ms")
print(f"Total tokens: {sum(log['total_tokens'] for log in logs)}")
```

---

## 编译与测试流程

### 完整编译

```bash
cd /home/ckt/.../ChatAFL-Enhanced

# 清理旧文件
make clean

# 编译（检查错误）
make afl-fuzz 2>&1 | tee compile.log
grep -i "error:" compile.log

# 验证符号
nm afl-fuzz | grep -E "save_to_corpus|random_seed|log_llm_call"
```

### 功能测试

```bash
# P0-1测试：覆盖增益验证
./afl-fuzz -d -i seeds -o out_p01 -N tcp://127.0.0.1/21 -P FTP -D 10000 \
  -E -K -r 42 -- ./pure-ftpd -S 21 &

# 运行5分钟后检查
sleep 300
ls -lh out_p01/corpus/ | wc -l  # 应该少于baseline
grep "edge+" out_p01/corpus/*/edge_info  # 应该有增益标注

# P0-2测试：固定随机种子
./afl-fuzz -r 42 -i seeds -o out_p02_run1 ... &
./afl-fuzz -r 42 -i seeds -o out_p02_run2 ... &

# 检查确定性
diff out_p02_run1/queue/id:000005* out_p02_run2/queue/id:000005*

# P0-3测试：LLM日志
cat out_p01/llm_calls.jsonl | jq '.trigger_type' | sort | uniq -c
cat out_p01/llm_calls.jsonl | jq '.total_tokens' | awk '{sum+=$1} END {print sum}'
```

---

## 预期结果

### P0-1完成后

- Corpus大小减少50-70%
- 每个entry包含增益度量
- fuzzer_stats新增: `corpus_with_gain`, `corpus_rejected_no_gain`

### P0-2完成后

- fuzzer_stats新增: `random_seed`
- 固定seed实验完全可复现
- 论文可以提供"实验可复现脚本"

### P0-3完成后

- `out/llm_calls.jsonl`文件存在
- 每次LLM调用都有完整记录
- 可以计算总API成本
- 审稿人可以重放LLM决策

---

## 时间线

| 任务 | 预计工作量 | 截止日期 |
|-----|-----------|---------|
| P0-1完成 | 8-12小时 | Day 1-2 |
| P0-2完成 | 2-4小时 | Day 2 |
| P0-3完成 | 6-8小时 | Day 3 |
| 集成测试 | 4小时 | Day 3 |
| **总计** | **20-28小时** | **3天** |

---

## 成功标准

1. ✅ 所有代码编译无错误
2. ✅ 单元测试通过（覆盖增益计算、随机种子、日志记录）
3. ✅ 集成测试：运行24小时无崩溃
4. ✅ 性能测试：overhead < 5%
5. ✅ 可复现性：固定seed实验结果一致
6. ✅ 文档完整：代码注释、README更新

**完成P0修复后，系统将达到Tier-1会议的基本投稿标准。**

---

**文档版本**: 1.0  
**最后更新**: 2026年1月14日  
**实施人**: [待填写]  
**审核人**: 领域专家
