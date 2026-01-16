/*
 * 文件: afl-fuzz-integration-example.c
 * 描述: 展示如何在afl-fuzz.c中集成验证器、CEGAR和状态调度器
 * 注意: 这是示例代码片段，需要根据实际的afl-fuzz.c结构调整
 */

// ==================== 步骤1: 添加头文件引用 ====================
#include "verifier.h"
#include "cegar.h"
#include "state-scheduler.h"
#include "protocol-spec.h"

// ==================== 步骤2: 全局变量声明 ====================
static ProtocolSpec g_protocol_spec;  // 协议规范（从LLM生成或配置文件加载）
static char g_prev_state[256] = "S_INIT";  // 前一个状态（用于状态转移追踪）
static int g_consecutive_no_new_states = 0;  // 连续无新状态的轮数（plateau检测）

// ==================== 步骤3: 修改 fuzz_one() 函数 ====================

/* 
 * 原始 afl-fuzz.c 的 fuzz_one() 大致结构：
 * 
 * u8 fuzz_one(char** argv) {
 *   ... 选择queue entry ...
 *   ... 变异 ...
 *   ... 执行目标程序 ...
 *   ... 检查覆盖和崩溃 ...
 *   return 0;
 * }
 */

u8 fuzz_one_enhanced(char** argv) {
    struct queue_entry *q = queue_cur;  // AFL的当前测试用例
    
    // ======== 集成点1: 验证器前置检查 ========
    /* 
     * 在执行前验证测试用例是否符合协议语法
     * 优点：避免无效输入浪费执行时间
     */
    if (g_protocol_spec.name[0] != '\0') {  // 如果已加载协议规范
        // 读取测试用例内容（假设是JSON格式）
        char test_case_json[MAX_PAYLOAD_LEN];
        read_test_case(q->fname, test_case_json, sizeof(test_case_json));
        
        // 调用验证器
        if (!verify_json_grammar(test_case_json, &g_protocol_spec)) {
            VerifierRejectReason reason = get_last_verifier_reason();
            
            // 记录拒绝信息（用于分析和论文数据）
            fprintf(plot_file, "[%llu] VERIFIER_REJECT: %s, case_id=%d\n", 
                    total_execs, verifier_reason_str(reason), q->id);
            
            // 标记为invalid，不执行
            q->was_fuzzed = 1;
            pending_favored--;
            
            // AFL的abandon机制
            goto abandon_entry;
        }
    }
    
    // ======== 原始AFL逻辑：变异、执行、检查覆盖 ========
    /* ... AFL原有的变异策略 ... */
    /* ... 执行目标程序 ... */
    /* ... 收集覆盖信息 ... */
    
    // 假设执行后得到响应（需要从aflnet.c的网络层获取）
    int status_code = get_last_response_code();  // 需实现：从aflnet获取
    char response_body[1024];
    get_last_response_body(response_body, sizeof(response_body));  // 需实现
    
    // ======== 集成点2: 状态转移追踪 ========
    /*
     * 计算当前状态哈希并记录状态转移
     */
    char current_state[256];
    snprintf(current_state, sizeof(current_state), "S_%d_%.32s", 
             status_code, response_body);
    
    // 构造状态转移边
    char edge_info[512];
    snprintf(edge_info, sizeof(edge_info), "%s -> %s", g_prev_state, current_state);
    
    // 检查是否为新边
    bool is_new_edge = !has_seen_edge(edge_info);  // 需实现：边表查找
    
    if (is_new_edge) {
        // 保存到corpus（状态调度器）
        save_to_corpus(test_case_json, edge_info);
        
        // 增加状态计数
        increment_state_count(current_state);
        
        // 重置plateau计数器
        g_consecutive_no_new_states = 0;
        
        // AFL原有的queue添加逻辑
        /* ... add_to_queue() ... */
        
        fprintf(plot_file, "[%llu] NEW_STATE_EDGE: %s\n", total_execs, edge_info);
    } else {
        // 已见过的边，仍然更新访问计数
        increment_state_count(current_state);
    }
    
    // 更新前一个状态
    strncpy(g_prev_state, current_state, sizeof(g_prev_state) - 1);
    
    // ======== 集成点3: CEGAR反例驱动修正 ========
    /*
     * 如果检测到拒绝响应，触发CEGAR修正
     */
    if (is_rejection_response(status_code, response_body, g_protocol_spec.name)) {
        fprintf(plot_file, "[%llu] REJECTION_DETECTED: code=%d, body=%.50s\n", 
                total_execs, status_code, response_body);
        
        // 检查是否应该停止修正（防止循环）
        if (!should_backoff_refinement(edge_info, 3)) {
            // 构造RealResponse结构
            RealResponse failure;
            failure.status_code = status_code;
            strncpy(failure.body, response_body, sizeof(failure.body) - 1);
            strncpy(failure.state_hash, current_state, sizeof(failure.state_hash) - 1);
            
            // 调用CEGAR修正
            char* refined_json = refine_hypothesis_with_cegar(test_case_json, 
                                                              &failure, 
                                                              &g_protocol_spec);
            
            if (refined_json) {
                // 将修正后的用例添加到queue
                char refined_fname[256];
                snprintf(refined_fname, sizeof(refined_fname), 
                         "%s/queue/id:%06d,cegar", out_dir, queued_paths + 1);
                
                FILE* f = fopen(refined_fname, "w");
                if (f) {
                    fwrite(refined_json, 1, strlen(refined_json), f);
                    fclose(f);
                    
                    // 添加到AFL queue
                    add_to_queue(refined_fname, strlen(refined_json), 0);
                    
                    fprintf(plot_file, "[%llu] CEGAR_REFINED: %s\n", 
                            total_execs, refined_fname);
                }
                
                free(refined_json);
            }
        } else {
            fprintf(plot_file, "[%llu] CEGAR_BACKOFF: edge=%s\n", 
                    total_execs, edge_info);
        }
    }
    
abandon_entry:
    return 0;
}

// ==================== 步骤4: 在 cull_queue() 中集成状态调度 ====================

/*
 * AFL的 cull_queue() 用于选择下一个要fuzz的用例
 * 我们在这里集成plateau检测和LLM触发逻辑
 */
void cull_queue_enhanced(void) {
    // ... AFL原有的queue筛选逻辑 ...
    
    // ======== 集成点4: Plateau检测 ========
    /*
     * 如果连续多轮没有新发现，触发LLM生成新假设
     */
    if (queued_discovered == 0) {  // AFL的新发现队列为空
        g_consecutive_no_new_states++;
    } else {
        g_consecutive_no_new_states = 0;
    }
    
    if (is_plateau(g_consecutive_no_new_states, 5)) {  // 连续5轮停滞
        fprintf(plot_file, "[%llu] PLATEAU_DETECTED: triggering LLM\n", total_execs);
        
        // 策略1: 从corpus中选择低覆盖状态的用例
        char low_coverage_case[MAX_PAYLOAD_LEN];
        if (pick_corpus_for_low_coverage(low_coverage_case, sizeof(low_coverage_case))) {
            // 添加到queue前端（优先执行）
            char fname[256];
            snprintf(fname, sizeof(fname), "%s/queue/id:%06d,low_cov", 
                     out_dir, queued_paths + 1);
            
            FILE* f = fopen(fname, "w");
            if (f) {
                fwrite(low_coverage_case, 1, strlen(low_coverage_case), f);
                fclose(f);
                add_to_queue(fname, strlen(low_coverage_case), 0);
                
                fprintf(plot_file, "[%llu] INJECTED_LOW_COV_CASE\n", total_execs);
            }
        } else {
            // 策略2: 请求LLM生成到达特定状态的序列
            char target_state[256];
            if (pick_least_visited_state(target_state, sizeof(target_state))) {
                char* llm_sequence = request_llm_for_state_sequence(target_state, 
                                                                    g_prev_state, 
                                                                    &g_protocol_spec);
                
                if (llm_sequence) {
                    char fname[256];
                    snprintf(fname, sizeof(fname), "%s/queue/id:%06d,llm_seq", 
                             out_dir, queued_paths + 1);
                    
                    FILE* f = fopen(fname, "w");
                    if (f) {
                        fwrite(llm_sequence, 1, strlen(llm_sequence), f);
                        fclose(f);
                        add_to_queue(fname, strlen(llm_sequence), 0);
                        
                        fprintf(plot_file, "[%llu] INJECTED_LLM_SEQUENCE: target=%s\n", 
                                total_execs, target_state);
                    }
                    
                    free(llm_sequence);
                }
            }
        }
        
        // 重置计数器
        g_consecutive_no_new_states = 0;
    }
}

// ==================== 步骤5: 初始化协议规范（在main中） ====================

int main(int argc, char** argv) {
    // ... AFL原有的初始化 ...
    
    // ======== 集成点5: 加载协议规范 ========
    /*
     * 方式1: 从命令行参数加载（推荐）
     * ./afl-fuzz -i in -o out -P FTP -S protocol_spec.json -- ./target @@
     */
    if (protocol_spec_file) {
        load_protocol_spec_from_file(protocol_spec_file, &g_protocol_spec);
    } else if (protocol_name) {
        // 方式2: 使用LLM自动生成（与test.c一致）
        auto_generate_protocol_spec(protocol_name, &g_protocol_spec);
    }
    
    // 初始化状态调度器
    clear_corpus();
    
    fprintf(plot_file, "[INIT] Protocol: %s, Port: %d\n", 
            g_protocol_spec.name, g_protocol_spec.default_port);
    
    // ... AFL原有的fuzzing循环 ...
    
    // 程序结束时导出状态图（用于论文可视化）
    export_state_graph_dot("output/state_graph.dot");
    export_state_heatmap_csv("output/state_heatmap.csv");
    
    return 0;
}

// ==================== 辅助函数实现（需要补充） ====================

static void read_test_case(const char* fname, char* buffer, size_t max_len) {
    FILE* f = fopen(fname, "r");
    if (!f) { buffer[0] = '\0'; return; }
    
    size_t len = fread(buffer, 1, max_len - 1, f);
    buffer[len] = '\0';
    fclose(f);
}

static bool has_seen_edge(const char* edge_info) {
    // 实现：在全局的边表中查找
    // 可以使用哈希表 (khash) 或简单的字符串数组
    // 示例略
    return false;
}

static int get_last_response_code(void) {
    // 实现：从aflnet的网络层获取最后一次响应的状态码
    // 需要修改 aflnet.c 暴露此接口
    // 示例略
    return 200;
}

static void get_last_response_body(char* buffer, size_t max_len) {
    // 实现：从aflnet获取响应正文
    // 示例略
    buffer[0] = '\0';
}

// ==================== 编译说明 ====================
/*
 * 修改 Makefile：
 * 
 * SRCS += verifier.c cegar.c state-scheduler.c
 * HEADERS += verifier.h cegar.h state-scheduler.h protocol-spec.h
 * 
 * afl-fuzz: afl-fuzz.c $(SRCS) $(HEADERS) chat-llm.c
 *     $(CC) $(CFLAGS) afl-fuzz.c $(SRCS) chat-llm.c \
 *         -o afl-fuzz -lcurl -ljson-c -lpcre2-8
 */
