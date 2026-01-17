# ChatAFL-Enhanced: Integration Guide

## 目标

本指南说明如何将ChatAFL-Enhanced的三个核心模块集成到现有的AFLNet/ChatAFL系统中。

---

## 第一部分：架构集成概述

### 系统架构

```
┌──────────────────────────────┐
│      afl-fuzz.c              │  (主模糊循环)
│   ├─ select seed             │
│   ├─ mutate seed             │
│   ├─ execute target          │
│   └─ collect feedback        │
└────────┬─────────────────────┘
         │
         ├─→ [EXISTING] aflnet.c (protocol-aware feedback)
         │
         └─→ [NEW] ChatAFL-Enhanced Verified Loop
                ├─ verifier.c      (4-layer validation)
                ├─ cegar-refinement.c  (counterexample repair)
                └─ state-scheduler.c   (state-aware seed selection)
```

### 集成点

| 模块 | 集成点 | 类型 | 优先级 |
|------|--------|------|--------|
| Verifier | `aflnet_client.c` send/recv | 函数调用 | 🔴 高 |
| CEGAR | `chat-llm.c` LLM interface | 函数调用 | 🟡 中 |
| Scheduler | `afl-fuzz.c` queue selection | 权重调整 | 🔴 高 |

---

## 第二部分：分阶段集成步骤

### Phase 1: Verifier集成 (Week 1)

#### 1.1 修改 `aflnet-client.c`

**目标**: 在发送请求后，立即验证响应

**当前流程**:
```c
// 原aflnet-client.c
send(sock, message, msg_len, 0);
recv(sock, response, sizeof(response), 0);
```

**修改后**:
```c
// 在aflnet-client.c中添加
#include "verifier.h"

// 在main()中初始化
verifier_config_t vcfg;
vcfg.enable_logging = 1;
vcfg.log_file = ".verifier.log";
verifier_init(&vcfg);

// 在发送消息后调用
response_t resp;
if (verify_acceptability(host, port, message, msg_len, &resp, 5000)) {
    // 消息被接受
    update_state_transition_tree(stt, response_codes, count, msg_type);
} else {
    // 消息被拒绝 → 触发CEGAR
    trigger_cegar_refinement(message, msg_len, &resp);
}
```

**代码修改点** (aflnet-client.c):

```diff
+ #include "verifier.h"

  int main(int argc, char **argv) {
    // ... 现有初始化代码 ...
    
+   // 初始化Verifier
+   verifier_config_t vcfg;
+   vcfg.enable_logging = 1;
+   vcfg.debug_mode = 0;
+   vcfg.log_file = ".verifier.log";
+   vcfg.stt = (state_transition_tree_t *)calloc(...);
+   verifier_init(&vcfg);
    
    // ... 接收响应的地方 ...
    
+   // 验证可接受性
+   response_t resp = {0};
+   int acceptable = verify_acceptability(
+       target_host, target_port, 
+       send_buf, send_len, 
+       &resp, 5000
+   );
+   
+   if (!acceptable) {
+       // 失败：记录反例
+       log_verification_result(message_hex, 0, 0, 0, &resp);
+   } else {
+       // 成功：更新STT
+       unsigned int state_seq[] = {resp.status_code};
+       update_state_transition_tree(vcfg.stt, state_seq, 1, "message");
+   }
  }
```

---

### Phase 2: CEGAR集成 (Week 1-2)

#### 2.1 修改 `chat-llm.c`

**目标**: 在语法生成失败时，调用CEGAR修正

**集成点**:
```c
// 在chat-llm.c中添加
#include "cegar-refinement.h"

// 初始化CEGAR
void initialize_chatafl_enhanced() {
    cegar_init(".cegar_cache");  // 缓存目录
}

// 修改extract_message_grammars()
void extract_message_grammars(char *answers, klist_t(gram) * grammar_set) {
    // ... 原有解析代码 ...
    
    // [NEW] 验证生成的grammar是否有效
    for (kl_iter_t(gram) it = kl_begin(grammar_set); it != kl_end(grammar_set); 
         it = kl_next(it)) {
        json_object *grammar = kl_val(it);
        
        // 尝试用该grammar生成一条消息
        unsigned char test_msg[1024];
        int msg_len = generate_message_from_grammar(grammar, test_msg, sizeof(test_msg));
        
        // 验证这条消息
        if (!verify_parseability(test_msg, msg_len, grammar, NULL)) {
            // [NEW] Grammar验证失败 → CEGAR修正
            cegar_failure_t failure = {
                .original_message = test_msg,
                .original_len = msg_len,
                .failure_classification = strdup("grammar_generation_failed")
            };
            
            cegar_patch_t *patch = iterative_field_refinement(
                &failure, grammar, 5, protocol_name
            );
            
            if (patch) {
                // 更新grammar
                update_grammar_with_patch(grammar, patch);
            }
        }
    }
}
```

#### 2.2 CEGAR Prompt设计

**ChatAFL-Enhanced CEGAR Prompt模板**:

```
[系统消息]
你是协议专家，帮助修复失败的消息生成规则。

[上下文]
协议: {protocol_name}
服务器响应: {status_code} {message}

[约束]
CONSTRAINT: Only fix field #{field_index}: "{field_name}"
Do NOT modify other fields.
Do NOT change message structure.

[当前字段值]
{current_field_value}

[预期修正]
Response格式：
{
  "field_index": <int>,
  "new_value": "<string>",
  "reason": "<why this fixes the error>"
}
```

---

### Phase 3: State-aware Scheduler集成 (Week 2-3)

#### 3.1 修改 `afl-fuzz.c`

**目标**: 在种子选择时考虑状态稀有度

**当前算法** (AFL原生):
```c
// afl-fuzz.c: choose_block_legacy()
entry = queue;  // Round-robin or random selection
```

**修改后** (加入状态反馈):
```c
// 在afl-fuzz.c中添加
#include "state-scheduler.h"

// 全局变量
state_scheduler_t g_state_scheduler;

// 初始化 (在main()中)
state_scheduler_init(&g_state_scheduler, 50);  // plateau_threshold=50

// 修改种子选择逻辑
struct queue_entry *choose_next_seed_enhanced() {
    // 计算当前覆盖率
    float current_coverage = count_bits(virgin_bits) / 
                           (sizeof(virgin_bits) * 8.0f);
    
    // 检测plateau
    if (detect_coverage_plateau(&g_state_scheduler, current_coverage)) {
        // 触发状态导向生成
        unsigned int target_state = get_lowest_coverage_state(&g_state_scheduler);
        
        // 调用LLM生成序列
        char *prompt = construct_state_targeting_prompt(
            protocol_name, target_state,
            g_state_scheduler.stt, verified_grammars
        );
        
        char *llm_response = chat_with_llm(prompt, "gpt-4", 1, 0.7f);
        
        // 处理LLM响应，加入种子库
        process_llm_sequence(llm_response);
    }
    
    // 按状态稀有度选择种子
    struct queue_entry *chosen = select_seed_by_state_rarity(
        &g_state_scheduler, queue, 0.5f  // 50% rarity, 50% coverage
    );
    
    return chosen;
}
```

#### 3.2 AFLNet State反馈集成

**修改** `aflnet.c` 的 `extract_response_codes()`:

```c
// 原aflnet.c
unsigned int *extract_response_codes(
    unsigned char *buf, unsigned int buf_size, 
    unsigned int *state_count_ref) {
    // ... 提取响应码 ...
}

// 修改为调用Scheduler
void update_state_feedback(unsigned char *buf, unsigned int buf_size) {
    unsigned int state_count;
    unsigned int *state_seq = extract_response_codes(buf, buf_size, &state_count);
    
    // [NEW] 更新STT
    update_state_transition_tree(
        g_state_scheduler.stt,
        state_seq, 
        state_count, 
        current_message_type
    );
    
    // [NEW] 更新rarity统计
    update_state_rarity(&g_state_scheduler);
    
    free(state_seq);
}
```

---

## 第三部分：协议特定集成

### MQTT 协议集成示例

#### 配置文件: `mqtt_config.h`

```c
#ifndef __MQTT_CONFIG_H
#define __MQTT_CONFIG_H

// MQTT特定的状态定义
enum mqtt_state {
    MQTT_IDLE = 0,
    MQTT_CONNECT_SENT = 1,
    MQTT_CONNACK_RECEIVED = 2,
    MQTT_SUBSCRIBE_SENT = 3,
    MQTT_SUBACK_RECEIVED = 4,
    MQTT_PUBLISH_SENT = 5,
    MQTT_DISCONNECT_SENT = 6
};

// 状态映射（从MQTT控制码→状态ID）
static unsigned int mqtt_status_to_state(unsigned char first_byte) {
    unsigned char pkt_type = first_byte >> 4;
    
    switch (pkt_type) {
        case 1: return MQTT_CONNECT_SENT;
        case 2: return MQTT_CONNACK_RECEIVED;
        case 8: return MQTT_SUBSCRIBE_SENT;
        case 9: return MQTT_SUBACK_RECEIVED;
        case 3: return MQTT_PUBLISH_SENT;
        case 14: return MQTT_DISCONNECT_SENT;
        default: return MQTT_IDLE;
    }
}

#endif
```

#### Protocol Hook: `mqtt_verifier_hook.c`

```c
#include "mqtt_config.h"
#include "verifier.h"

// MQTT特定的验证器扩展
int mqtt_verify_protocol_compliance(
    const unsigned char *message,
    size_t msg_len) {
    
    if (msg_len < 2) return 0;
    
    // MQTT消息格式检查
    unsigned char pkt_type = message[0] >> 4;
    unsigned char remaining_len_byte = message[1];
    
    // 验证剩余长度编码
    int remaining_len = 0;
    if (remaining_len_byte & 0x80) {
        // 多字节编码（v0简化：不支持）
        return 0;
    } else {
        remaining_len = remaining_len_byte;
    }
    
    // 检查整体长度
    if (msg_len != 2 + remaining_len) {
        return 0;
    }
    
    return 1;
}
```

---

## 第四部分：编译与部署

### 编译步骤

```bash
# 1. 进入ChatAFL-Enhanced目录
cd ChatAFL-Enhanced

# 2. 编译增强模块
make -f Makefile.enhanced

# 3. 测试独立验证循环
./test_verified_loop

# 4. 集成到AFLNet
cp verifier.o cegar-refinement.o state-scheduler.o ../aflnet-master/ChatAFL/
cd ../aflnet-master/ChatAFL
make clean all

# 5. 使用集成版本
./afl-fuzz -i in -o out -N tcp://127.0.0.1:1883 -x mqtt.dict \
           -P MQTT -E -K ./mqtt_server
```

### 依赖安装

```bash
# Ubuntu/Debian
sudo apt-get install \
    libcurl4-openssl-dev \
    libjson-c-dev \
    libpcre2-dev \
    clang \
    graphviz-dev \
    libcap-dev

# macOS
brew install curl json-c pcre2 graphviz
```

---

## 第五部分：验证与调试

### 日志检查

```bash
# Verifier日志
tail -f .verifier.log

# CEGAR缓存检查
ls -la .cegar_cache/
cat .cegar_cache/<hash>.json | jq .

# 状态调度日志
tail -f .sched_log

# STT可视化
dot -Tpng stt_graph.dot -o stt_graph.png
```

### 性能分析

```bash
# 编译时启用profiling
gcc -pg -o test_verified_loop ...
./test_verified_loop
gprof test_verified_loop gmon.out > profile.txt

# 检查各模块耗时
grep "\[VERIFIER\]\|\[CEGAR\]\|\[SCHEDULER\]" .verifier.log | wc -l
```

---

## 第六部分：常见问题与排查

### Q1: Verifier拒绝所有消息

**原因**: Grammar太严格或消息格式不对

**排查**:
```bash
# 打开调试日志
export DEBUG=1
./test_verified_loop

# 检查生成的消息
hexdump -C generated_message.bin
```

### Q2: CEGAR无法收敛

**原因**: LLM回应格式不对或字段依赖复杂

**解决**:
- 检查LLM Prompt (见CEGAR_REFINEMENT.md)
- 增加MAX_PATCH_ATTEMPTS
- 手动调整field_to_fix约束

### Q3: 状态爆炸 (STT节点过多)

**原因**: 状态ID碰撞或粒度太细

**调整**:
```c
// 在state-scheduler.c中修改hash函数粗粒度
unsigned int compute_state_id(...) {
    // 只取响应码的高4位 (而不是完整32位)
    return (response_sequence[count-1] >> 4) & 0x0F;  // 最多16个状态
}
```

---

## 第七部分：扩展与优化

### 扩展Point 1: 自定义检查点

在`verifier.h`中添加新的检查函数:

```c
/**
 * 协议特定的语义验证
 * 例如: MQTT QoS等级、RTSP方法合法性等
 */
int verify_protocol_semantics(
    const unsigned char *message,
    size_t msg_len,
    protocol_context_t *protocol_ctx
);
```

### 扩展Point 2: 多语言LLM支持

修改`cegar-refinement.c`中的Prompt:

```c
// 支持多语言Prompt
char *construct_cegar_prompt_multilang(
    const char *protocol_name,
    const cegar_failure_t *counterexample,
    const char *language  // "en", "zh", "ja"
);
```

### 扩展Point 3: 增量学习

添加到`cegar-refinement.c`:

```c
/**
 * 从成功的补丁中学习规则
 * 用于改进未来的LLM Prompt
 */
void extract_repair_patterns(const cegar_patch_t **patches, int count);
```

---

## 附录：完整集成清单

- [ ] 编译ChatAFL-Enhanced核心模块
- [ ] 修改aflnet-client.c集成Verifier
- [ ] 修改chat-llm.c集成CEGAR
- [ ] 修改afl-fuzz.c集成State Scheduler
- [ ] 部署目标协议(MQTT/FTP/RTSP)
- [ ] 单元测试各模块
- [ ] 集成测试完整系统
- [ ] 性能基准测试
- [ ] 对标AFLNet/ChatAFL

---

**更新时间**: 2026-01-18
**版本**: ChatAFL-Enhanced v0.1
**状态**: Integration Guide (Alpha)
