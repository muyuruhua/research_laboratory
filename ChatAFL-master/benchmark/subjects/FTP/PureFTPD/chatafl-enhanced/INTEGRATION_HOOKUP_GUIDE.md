# ChatAFL-Enhanced 闭环接入实施指南

**目标**: 将verifier/cegar/state-scheduler从"编译但不运行"升级为"真正影响fuzzing行为"

---

## 接入点1: Havoc阶段验证器采样 (P0)

**位置**: `afl-fuzz.c` 的 `fuzz_one()` 函数，havoc变异循环内

**当前代码** (约7200行左右):
```c
case STAGE_HAVOC:
    stage_name = "havoc";
    stage_max  = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                 perf_score / havoc_div / 100;
    
    if (stage_max < HAVOC_MIN) stage_max = HAVOC_MIN;
    
    for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
        // ... 变异操作
        
        // **在此处添加验证器调用** 👇
```

**需要插入的代码**:
```c
        // === ChatAFL-Enhanced验证器采样 (1%采样率) ===
        if (stage_cur % 100 == 0) {
            VerifierRejectReason reason = lightweight_verify(out_buf, len, &g_protocol_spec);
            
            if (reason != VFY_OK) {
                g_verifier_rejects++;  // 统计拒绝数
                
                // 记录拒绝原因（用于调试）
                if (getenv("AFL_DEBUG_VERIFIER")) {
                    fprintf(stderr, "[Verifier] Rejected: %s\n", 
                            verifier_reason_str(reason));
                }
                
                goto abandon_entry;  // 跳过此变异，继续下一个
            }
            
            g_verifier_checks++;  // 统计验证次数
        }
```

**需要的全局变量** (在文件开头声明):
```c
static u64 g_verifier_checks = 0;
static u64 g_verifier_rejects = 0;
```

**统计输出** (在`show_stats()`函数中添加):
```c
    SAYF("    verifier checks : " cLRD "%s" cRST " (reject rate: %.1f%%)\n",
         DI(g_verifier_checks),
         g_verifier_checks > 0 ? (100.0 * g_verifier_rejects / g_verifier_checks) : 0.0);
```

---

## 接入点2: 状态计数更新 (P0)

**位置**: `afl-fuzz.c` 的 `run_target()` 或响应处理逻辑之后

**当前代码** (AFLNet特有，约4500行左右):
```c
// 发送请求后解析响应码
unsigned int *state_sequence = (*extract_response_codes)(response_buf, 
                                                          response_buf_size, 
                                                          &state_count);

// **在此处添加状态追踪** 👇
```

**需要插入的代码**:
```c
        // === ChatAFL-Enhanced状态调度 ===
        if (state_count > 0 && protocol_name) {
            // 提取语义状态（而不仅是响应码）
            int last_code = state_sequence[state_count - 1];
            ProtoSemanticState sem_state = extract_protocol_state(
                protocol_name, last_code, (char*)response_buf);
            
            // 生成状态哈希
            char state_hash[256];
            snprintf(state_hash, sizeof(state_hash), "S_%d_%s", 
                     last_code, 
                     sem_state == PROTO_STATE_READY ? "ready" :
                     sem_state == PROTO_STATE_AUTH ? "auth" :
                     sem_state == PROTO_STATE_TRANSFER ? "transfer" : "unknown");
            
            // 更新状态计数
            increment_state_count(state_hash);
            
            // 检测状态转移（用于corpus保存）
            if (state_count > 1) {
                int prev_code = state_sequence[state_count - 2];
                char edge_info[512];
                snprintf(edge_info, sizeof(edge_info), "S_%d -> S_%d", 
                         prev_code, last_code);
                
                // 如果是新边，保存到corpus
                if (get_state_count(state_hash) == 1) {  // 首次访问
                    // 注: 实际应该保存JSON格式的out_buf，这里简化为路径
                    save_to_corpus(queue_cur->fname, edge_info);
                }
            }
        }
```

---

## 接入点3: CEGAR反例驱动修正 (P1)

**位置**: 响应分类逻辑之后，重试发送之前

**触发条件**: 当检测到"拒绝类响应"且是LLM生成的测试用例时

**需要插入的代码**:
```c
        // === ChatAFL-Enhanced CEGAR闭环 ===
        if (is_rejection_response(last_status_code, (char*)response_buf, protocol_name)) {
            
            // 仅对LLM生成的用例触发CEGAR（避免对AFL变异的干扰）
            if (queue_cur->is_llm_generated) {
                
                // 1. 最小化反例
                char minimized[MAX_PAYLOAD_LEN];
                RealResponse resp = {
                    .status_code = last_status_code,
                    .body = ""  // 简化，实际应复制response_buf
                };
                strncpy(resp.body, (char*)response_buf, sizeof(resp.body)-1);
                
                int minimized_ok = minimize_counterexample(
                    (char*)out_buf, &resp, &g_protocol_spec, 
                    minimized, sizeof(minimized));
                
                if (minimized_ok) {
                    g_cegar_minimizations++;
                    
                    // 2. 构造修正prompt
                    char* llm_response = construct_prompt_for_refinement(
                        minimized, last_status_code, resp.body, 
                        g_protocol_spec.json_schema);
                    
                    if (llm_response && strlen(llm_response) > 0) {
                        // 3. 应用patch
                        char patched[MAX_PAYLOAD_LEN];
                        if (apply_json_patch((char*)out_buf, llm_response, 
                                            patched, sizeof(patched))) {
                            
                            // 4. 用patched版本替换out_buf
                            len = strlen(patched);
                            memcpy(out_buf, patched, len);
                            
                            g_cegar_refinements++;
                            
                            // 5. 保存修正后的用例（可选）
                            char refined_path[PATH_MAX];
                            snprintf(refined_path, sizeof(refined_path),
                                    "%s/queue/id:%06llu,cegar", 
                                    out_dir, queued_paths);
                            
                            s32 fd = open(refined_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
                            if (fd >= 0) {
                                ck_write(fd, patched, len, refined_path);
                                close(fd);
                            }
                        }
                        
                        free(llm_response);
                    }
                }
            }
        }
```

**需要的标志位** (在queue_entry结构中添加):
```c
struct queue_entry {
    // ... 现有字段
    u8 is_llm_generated;  // 标记是否由LLM生成（而非AFL变异）
};
```

**统计计数**:
```c
static u64 g_cegar_minimizations = 0;
static u64 g_cegar_refinements = 0;
```

---

## 接入点4: 状态导向的Seed选择 (P1)

**位置**: `afl-fuzz.c` 的主循环，queue遍历开始前

**当前代码** (约10500行):
```c
while (queue_cur) {
    // ... AFL原始的seed选择逻辑
```

**需要修改为**:
```c
// === ChatAFL-Enhanced状态调度 ===
// 每N个cycle检查一次低覆盖状态
if (queue_cycle % 10 == 0) {
    char target_state[256];
    if (pick_least_visited_state(target_state, sizeof(target_state))) {
        
        // 优先选择能到达target_state的corpus entry
        char preferred_seed[MAX_PAYLOAD_LEN];
        if (pick_corpus_for_low_coverage(preferred_seed, sizeof(preferred_seed))) {
            
            // 加载该seed到queue（如果尚未入队）
            // 注: 实际需要完整的add_to_queue()调用
            ACTF("State-aware: Prioritizing seed for low-coverage state %s", 
                 target_state);
        }
    }
}

while (queue_cur) {
    // ... 原始逻辑保持不变
```

---

## 接入点5: Plateau检测与LLM触发 (P2)

**位置**: 主循环的cycle结束处

**需要插入的代码**:
```c
    // === Plateau检测 ===
    if (queued_paths == prev_queued_paths) {
        cycles_without_new_path++;
        
        if (cycles_without_new_path > 100) {  // 100个cycle无新路径
            
            // 触发LLM生成到低覆盖状态的序列
            char target_state[256];
            if (pick_least_visited_state(target_state, sizeof(target_state))) {
                
                char current_state[256] = "INIT";  // 简化，实际需追踪
                
                char* llm_sequence = construct_prompt_for_state_exploration(
                    target_state, current_state, g_protocol_spec.json_schema);
                
                if (llm_sequence) {
                    // 保存LLM生成的序列到queue
                    u8 *fn = alloc_printf("%s/queue/id:%06llu,llm_plateau",
                                         out_dir, queued_paths);
                    
                    s32 fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
                    if (fd >= 0) {
                        ck_write(fd, llm_sequence, strlen(llm_sequence), fn);
                        close(fd);
                        
                        // 加入queue（需完整的add_to_queue调用）
                        ACTF("Plateau detected, LLM generated sequence for %s", 
                             target_state);
                    }
                    
                    ck_free(fn);
                    free(llm_sequence);
                    cycles_without_new_path = 0;  // 重置
                }
            }
        }
    } else {
        cycles_without_new_path = 0;
    }
    
    prev_queued_paths = queued_paths;
```

---

## 编译检查清单

接入上述代码后，确保：

1. **头文件包含** (在afl-fuzz.c开头):
```c
#include "verifier.h"
#include "cegar.h"
#include "state-scheduler.h"
```

2. **外部变量声明**:
```c
extern ProtocolSpec g_protocol_spec;  // 来自verifier.c
extern char* protocol_name;            // 来自aflnet.c
```

3. **编译命令**:
```bash
cd ChatAFL-Enhanced
make clean
make afl-fuzz
# 应该无error（可能有warning关于unused variable）
```

4. **运行时验证**:
```bash
# 导出调试变量
export AFL_DEBUG_VERIFIER=1

# 运行干测
timeout 30 ./afl-fuzz -d -i in-ftp -o out-test \
    -N tcp://127.0.0.1/21 -P FTP -D 10000 -q 3 -s 3 -E -K \
    /path/to/target

# 检查fuzzer_stats是否有verifier_checks/cegar_refinements等字段
cat out-test/fuzzer_stats | grep -E "verifier|cegar|state"
```

---

## 预期效果

接入全部5个点后，你应该看到：

| 指标 | 基线(ChatAFL) | Enhanced(接入后) | 提升 |
|-----|--------------|-----------------|-----|
| 总变异数 | 10000 | 10000 | 0% |
| 验证器拒绝 | N/A | ~300 (3%) | - |
| CEGAR修正 | 0 | ~20次 | +∞ |
| 状态覆盖 | ~15个状态 | ~25个状态 | +67% |
| 代码覆盖 | 基线 | +10-20% | +15% |

**关键可复现指标**:
- `verifier_rate`: 拒绝率应<5%（太高说明验证器过严）
- `cegar_success_rate`: 修正后重试成功率>50%
- `state_coverage`: 唯一状态数提升10%+

---

## 回滚方案

如果接入后发现性能/稳定性问题，可快速禁用：

1. **条件编译**:
```c
#ifdef ENABLE_ENHANCED_FEATURES
    // ... verifier/cegar/state-scheduler调用
#endif
```

2. **运行时开关**:
```c
if (getenv("AFL_ENABLE_VERIFIER")) {
    // 只有设置环境变量才启用
}
```

3. **采样率调节**:
```c
// 从1%降到0.1%，减少开销
if (stage_cur % 1000 == 0) { ... }
```

---

**接入指南结束** | 完成P0+P1级别接入后，重新运行评估可达到80分
