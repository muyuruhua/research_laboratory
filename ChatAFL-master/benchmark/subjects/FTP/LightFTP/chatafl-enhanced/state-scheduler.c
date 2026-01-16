/*
 * state-scheduler.c - 状态导向调度器实现
 * 灵感: USENIX Security '22 "Stateful Greybox Fuzzing"
 * 功能: 基于状态转移树(STT)的测试用例选择
 * Week 4: 状态反馈与优先调度
 */

#include "state-scheduler.h"
#include "chat-llm.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* ============================================
 * P1-1修复: RFC理论状态机定义
 * ============================================ */

/* FTP协议状态机（RFC 959） */
static ProtocolStateMachine g_ftp_sm = {
  .protocol_name = "FTP",
  .states = {
    {"S_INIT",    0, false},
    {"S_USER",  220, false},  /* 220 Service ready */
    {"S_PASS",  331, false},  /* 331 Username OK, need password */
    {"S_AUTH",  230, false},  /* 230 User logged in */
    {"S_CWD",   250, false},  /* 250 Directory changed */
    {"S_PORT",  200, false},  /* 200 PORT command successful */
    {"S_RETR",  150, false},  /* 150 File status okay, opening data */
    {"S_QUIT",  221, false},  /* 221 Service closing */
  },
  .state_count = 8,
  .discovered_count = 0
};

/* SMTP协议状态机（RFC 5321） */
static ProtocolStateMachine g_smtp_sm = {
  .protocol_name = "SMTP",
  .states = {
    {"S_INIT",   0, false},
    {"S_HELO", 220, false},  /* 220 Service ready */
    {"S_MAIL", 250, false},  /* 250 OK */
    {"S_RCPT", 250, false},  /* 250 Recipient OK */
    {"S_DATA", 354, false},  /* 354 Start mail input */
    {"S_QUIT", 221, false},  /* 221 Closing connection */
  },
  .state_count = 6,
  .discovered_count = 0
};

/* HTTP协议状态机（简化版，基于RFC 7230） */
static ProtocolStateMachine g_http_sm = {
  .protocol_name = "HTTP",
  .states = {
    {"S_INIT",    0, false},
    {"S_REQ",   200, false},  /* 200 OK */
    {"S_AUTH",  401, false},  /* 401 Unauthorized */
    {"S_REDIR", 302, false},  /* 302 Found */
    {"S_NOTF",  404, false},  /* 404 Not Found */
    {"S_ERROR", 500, false},  /* 500 Internal Server Error */
  },
  .state_count = 6,
  .discovered_count = 0
};

/* 全局状态表 */
static StateCount state_table[MAX_STATES];
static int state_count_entries = 0;

/* 全局Corpus */
static CorpusEntry corpus[MAX_CORPUS];
static int corpus_entries = 0;

/* Plateau检测 */
static int cycles_without_new_state = 0;
static int total_unique_states = 0;

/* ============================================
 * 状态管理 API
 * ============================================ */

/**
 * @brief 增加状态访问计数
 */
void increment_state_count(const char* state) {
    if (!state || strlen(state) == 0) return;
    
    /* 查找是否已存在 */
    for (int i = 0; i < state_count_entries; i++) {
        if (strcmp(state_table[i].state, state) == 0) {
            state_table[i].count++;
            return;
        }
    }
    
    /* 新状态：添加到表中 */
    if (state_count_entries < MAX_STATES) {
        strncpy(state_table[state_count_entries].state, state, 
                sizeof(state_table[0].state) - 1);
        state_table[state_count_entries].state[sizeof(state_table[0].state) - 1] = '\0';
        state_table[state_count_entries].count = 1;
        state_count_entries++;
        total_unique_states++;
        cycles_without_new_state = 0;  // 重置plateau计数
    }
}

/**
 * @brief 获取状态访问次数
 */
int get_state_count(const char* state) {
    if (!state) return 0;
    
    for (int i = 0; i < state_count_entries; i++) {
        if (strcmp(state_table[i].state, state) == 0) {
            return state_table[i].count;
        }
    }
    return 0;
}

/**
 * @brief 选择访问次数最少的状态（优先探索低覆盖）
 */
int pick_least_visited_state(char* out, size_t out_len) {
    if (state_count_entries == 0) return 0;
    
    int min_count = state_table[0].count;
    int min_index = 0;
    
    for (int i = 1; i < state_count_entries; i++) {
        if (state_table[i].count < min_count) {
            min_count = state_table[i].count;
            min_index = i;
        }
    }
    
    strncpy(out, state_table[min_index].state, out_len - 1);
    out[out_len - 1] = '\0';  /* 确保字符串终止 */
    out[out_len - 1] = '\0';
    
    return 1;
}

/**
 * @brief 获取所有状态列表（用于LLM prompt）
 */
int get_all_states(char* out, size_t out_len) {
    if (state_count_entries == 0) {
        out[0] = '\0';
        return 0;
    }
    
    out[0] = '\0';
    for (int i = 0; i < state_count_entries && i < 20; i++) {  // 限制输出数量
        char entry[256];  /* 扩大缓冲区避免截断警告 */
        snprintf(entry, sizeof(entry), "%s (visited: %d), ", 
                 state_table[i].state, state_table[i].count);
        strncat(out, entry, out_len - strlen(out) - 1);
    }
    
    return state_count_entries;
}

/* ============================================
 * Corpus管理（保存高价值测试用例）
 * ============================================ */

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

/**
 * @brief 保存到corpus（带覆盖增益验证）
 * 
 * **P0关键修复**: 只有在有覆盖/状态增益时才保存
 * 
 * 验证逻辑：
 * 1. 计算当前边覆盖：count_non_255_bytes(virgin_bits)
 * 2. 与之前的覆盖对比
 * 3. 同时检查状态数量增益
 * 4. 任一维度有增益 → 保存
 * 5. 无增益 → 拒绝（避免corpus膨胀）
 */
bool save_to_corpus(const char* json, 
                    const char* edge_info,
                    const unsigned char* virgin_bits,
                    unsigned int map_size,
                    unsigned int prev_state_count,
                    unsigned int new_state_count) {
    if (!json || corpus_entries >= MAX_CORPUS) {
        return false; /* Corpus已满或输入无效 */
    }
    
    /* 检查是否已存在（去重） */
    for (int i = 0; i < corpus_entries; i++) {
        if (strcmp(corpus[i].json, json) == 0) {
            return false;  // 已存在，跳过
        }
    }
    
    /* ===== 步骤1: 计算边覆盖增益 ===== */
    unsigned int current_edge_coverage = 0;
    unsigned int prev_edge_coverage = 0;
    
    if (virgin_bits && map_size > 0) {
        current_edge_coverage = count_non_255_bytes(virgin_bits, map_size);
        
        /* 获取之前的覆盖（从全局状态） */
        static unsigned int last_edge_coverage = 0;
        prev_edge_coverage = last_edge_coverage;
        last_edge_coverage = current_edge_coverage;
    }
    
    /* ===== 步骤2: 计算状态覆盖增益 ===== */
    unsigned int state_gain = 0;
    if (new_state_count > prev_state_count) {
        state_gain = new_state_count - prev_state_count;
    }
    
    unsigned int edge_gain = 0;
    if (current_edge_coverage > prev_edge_coverage) {
        edge_gain = current_edge_coverage - prev_edge_coverage;
    }
    
    /* ===== 步骤3: 增益判断 ===== */
    bool has_gain = (edge_gain > 0) || (state_gain > 0);
    
    if (!has_gain) {
        /* 无增益：拒绝保存，避免corpus膨胀 */
        return false;
    }
    
    /* ===== 步骤4: 有增益，保存到corpus ===== */
    
    /* 添加新条目 */
    strncpy(corpus[corpus_entries].json, json, sizeof(corpus[0].json) - 1);
    corpus[corpus_entries].json[sizeof(corpus[0].json) - 1] = '\0';
    corpus[corpus_entries].json[sizeof(corpus[0].json) - 1] = '\0';
    
    if (edge_info) {
        char enhanced_edge_info[256];
        snprintf(enhanced_edge_info, sizeof(enhanced_edge_info),
                 "%s (edge+%u, state+%u)",
                 edge_info, edge_gain, state_gain);
        
        strncpy(corpus[corpus_entries].edge, enhanced_edge_info, sizeof(corpus[0].edge) - 1);
        corpus[corpus_entries].edge[sizeof(corpus[0].edge) - 1] = '\0';
        corpus[corpus_entries].edge[sizeof(corpus[0].edge) - 1] = '\0';
    }
    
    corpus[corpus_entries].occupied = true;
    corpus_entries++;
    
    return true; /* 保存成功 */
}

/**
 * @brief 从corpus中选择到达低覆盖状态的测试用例
 */
int pick_corpus_for_low_coverage(char* out, size_t out_len) {
    if (corpus_entries == 0) return 0;
    
    /* 简单策略：随机选择一个corpus条目 */
    int index = rand() % corpus_entries;
    
    strncpy(out, corpus[index].json, out_len - 1);
    out[out_len - 1] = '\0';  /* 确保字符串终止 */
    out[out_len - 1] = '\0';
    
    return 1;
}

/**
 * @brief 根据目标状态从corpus筛选相关用例
 */
int pick_corpus_by_target_state(const char* target_state, char* out, size_t out_len) {
    if (!target_state || corpus_entries == 0) return 0;
    
    /* 查找到达该状态的用例 */
    for (int i = 0; i < corpus_entries; i++) {
        if (strlen(corpus[i].target_state) > 0 && 
            strcmp(corpus[i].target_state, target_state) == 0) {
            strncpy(out, corpus[i].json, out_len - 1);
            out[out_len - 1] = '\0';  /* 确保字符串终止 */
            out[out_len - 1] = '\0';
            return 1;
        }
    }
    
    /* 未找到：返回任意一个 */
    return pick_corpus_for_low_coverage(out, out_len);
}

/* ============================================
 * P1-1修复：RFC理论状态覆盖率计算
 * ============================================ */

/**
 * @brief 获取协议的理论状态机
 */
static ProtocolStateMachine* get_protocol_state_machine(const char *protocol_name) {
    if (!protocol_name) return NULL;
    
    if (strcasecmp(protocol_name, "FTP") == 0) {
        return &g_ftp_sm;
    } else if (strcasecmp(protocol_name, "SMTP") == 0) {
        return &g_smtp_sm;
    } else if (strcasecmp(protocol_name, "HTTP") == 0) {
        return &g_http_sm;
    }
    
    return NULL;
}

/* compute_state_coverage()的完整实现在文件后面（避免重复定义） */

/* ============================================
 * Plateau检测（停滞检测）
 * ============================================ */

/**
 * @brief 更新plateau计数
 */
void update_plateau_counter() {
    cycles_without_new_state++;
}

/**
 * @brief 检测是否处于plateau（停滞状态）
 */
bool is_plateau(int recent_cycles, double threshold) {
    if (recent_cycles <= 0) recent_cycles = 100;  // 默认值
    
    /* 简单策略：连续N轮没有新状态 */
    if (cycles_without_new_state > recent_cycles) {
        return true;
    }
    
    return false;
}

/**
 * @brief 重置plateau计数器（发现新状态时调用）
 */
void reset_plateau_counter() {
    cycles_without_new_state = 0;
}

/* ============================================
 * 状态转移边管理
 * ============================================ */

/**
 * @brief 记录状态转移边
 */
void record_state_transition(const char* from_state, const char* to_state) {
    if (!from_state || !to_state) return;
    
    char edge[512];
    snprintf(edge, sizeof(edge), "%s -> %s", from_state, to_state);
    
    /* 简化实现：仅增加目标状态计数 */
    increment_state_count(to_state);
}

/* ============================================
 * 统计与日志
 * ============================================ */

/**
 * @brief 获取状态覆盖统计
 */
void get_state_coverage_stats(int* unique_states, int* total_transitions) {
    if (unique_states) *unique_states = total_unique_states;
    if (total_transitions) {
        int sum = 0;
        for (int i = 0; i < state_count_entries; i++) {
            sum += state_table[i].count;
        }
        *total_transitions = sum;
    }
}

/**
 * @brief 打印状态表（调试用）
 */
void print_state_table() {
    printf("[STATE TABLE] Total unique states: %d\n", total_unique_states);
    for (int i = 0; i < state_count_entries && i < 20; i++) {
        printf("  %s: %d visits\n", state_table[i].state, state_table[i].count);
    }
}

/**
 * @brief 保存状态表到文件（用于可复现性）
 */
void save_state_table_to_file(const char* filename) {
    if (!filename) return;
    
    FILE* fp = fopen(filename, "w");
    if (!fp) return;
    
    fprintf(fp, "# State Coverage Table\n");
    fprintf(fp, "# Format: state,visit_count\n");
    
    for (int i = 0; i < state_count_entries; i++) {
        fprintf(fp, "%s,%d\n", state_table[i].state, state_table[i].count);
    }
    
    fclose(fp);
}

/* ============================================
 * P1-1修复: 状态覆盖率计算
 * ============================================ */

/**
 * @brief 获取协议状态机（根据协议名称）
 */
static ProtocolStateMachine* get_protocol_sm(const char *protocol_name) {
    if (!protocol_name) return NULL;
    
    if (strcasecmp(protocol_name, "FTP") == 0) {
        return &g_ftp_sm;
    } else if (strcasecmp(protocol_name, "SMTP") == 0) {
        return &g_smtp_sm;
    } else if (strcasecmp(protocol_name, "HTTP") == 0) {
        return &g_http_sm;
    }
    
    return NULL;
}

/* ============================================
 * P1-1修复：完整的RFC理论状态覆盖率计算实现
 * ============================================ */

/**
 * @brief 计算协议状态覆盖率（P0-Critical完整实现）
 */
int compute_state_coverage(const char *protocol_name,
                          unsigned int *state_ids,
                          unsigned int state_count,
                          double *out_coverage,
                          const char **out_missing,
                          unsigned int max_missing) {
    if (!protocol_name || !state_ids || state_count == 0) {
        if (out_coverage) *out_coverage = 0.0;
        return 0;
    }
    
    ProtocolStateMachine *sm = get_protocol_state_machine(protocol_name);
    if (!sm) {
        if (out_coverage) *out_coverage = 0.0;
        return 0;
    }
    
    /* 重置discovered标志 */
    for (unsigned int i = 0; i < sm->state_count; i++) {
        sm->states[i].is_discovered = false;
    }
    sm->discovered_count = 0;
    
    /* 标记已发现的状态 */
    for (unsigned int i = 0; i < state_count; i++) {
        unsigned int state_id = state_ids[i];
        
        /* 在理论状态机中查找匹配的状态 */
        for (unsigned int j = 0; j < sm->state_count; j++) {
            if (sm->states[j].state_id == state_id) {
                if (!sm->states[j].is_discovered) {
                    sm->states[j].is_discovered = true;
                    sm->discovered_count++;
                }
                break;
            }
        }
    }
    
    /* 计算覆盖率 */
    double coverage = (sm->state_count > 0) ?
                     (100.0 * sm->discovered_count / sm->state_count) : 0.0;
    if (out_coverage) {
        *out_coverage = coverage;
    }
    
    /* 收集缺失状态 */
    unsigned int missing_count = 0;
    if (out_missing && max_missing > 0) {
        for (unsigned int i = 0; i < sm->state_count && missing_count < max_missing; i++) {
            if (!sm->states[i].is_discovered) {
                out_missing[missing_count++] = sm->states[i].state_name;
            }
        }
    }
    
    return missing_count;
}

/**
 * @brief 从文件加载状态表（恢复fuzzing会话）
 */
int load_state_table_from_file(const char* filename) {
    if (!filename) return 0;
    
    FILE* fp = fopen(filename, "r");
    if (!fp) return 0;
    
    char line[512];
    state_count_entries = 0;
    
    while (fgets(line, sizeof(line), fp) && state_count_entries < MAX_STATES) {
        if (line[0] == '#') continue;  // 跳过注释
        
        char state[256];
        int count;
        if (sscanf(line, "%255[^,],%d", state, &count) == 2) {
            strncpy(state_table[state_count_entries].state, state, 
                    sizeof(state_table[0].state) - 1);
            state_table[state_count_entries].state[sizeof(state_table[0].state) - 1] = '\0';
            state_table[state_count_entries].count = count;
            state_count_entries++;
        }
    }
    
    fclose(fp);
    total_unique_states = state_count_entries;
    
    return state_count_entries;
}

/* ============================================
 * LLM集成：Plateau突破
 * ============================================ */

/**
 * @brief 请求LLM生成到达目标状态的测试序列
 */
char* request_llm_for_state_sequence(const char* target_state, 
                                     const char* current_state, 
                                     ProtocolSpec* spec) {
    if (!target_state || !spec) return NULL;
    
    /* 调用chat-llm.c中的prompt构造函数 */
    char* prompt = construct_prompt_for_state_exploration(target_state, 
                                                          current_state ? current_state : "unknown", 
                                                          spec->json_schema);
    if (!prompt) return NULL;
    
    /* 调用LLM */
    char* llm_response = chat_with_llm(prompt, "gpt-3.5-turbo", 3, 0.7);
    
    /* 释放prompt内存，由asprintf分配 */
    free(prompt);
    return llm_response;  // 调用者负责free
}
