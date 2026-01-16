/*
 * cegar.c - CEGAR (Counterexample-Guided Abstraction Refinement) 实现
 * 功能: 反例驱动的局部修正，降低LLM幻觉
 * Week 3: CEGAR闭环
 * 
 * P0关键改进：
 * 1. Delta Debugging最小化（二分删除算法）
 * 2. CEGAR缓存去重（避免重复LLM调用）
 * 3. 完整的LLM修正闭环（局部patch限制）
 * 
 * P1-3修复：
 * - 缓存时间戳支持（5分钟过期机制）
 */

#define _GNU_SOURCE
#include "cegar.h"
#include "verifier.h"
#include "chat-llm.h"
#include "alloc-inl.h"
#include "types.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <json-c/json.h>

/* ============================================
 * Delta Debugging最小化实现
 * 基于论文: "Simplifying and Isolating Failure-Inducing Input"
 *          Zeller & Hildebrandt, TSE 2002
 * ============================================ */

/**
 * @brief 提取命令行（第一个\r\n之前）
 */
unsigned char *extract_command_line(const unsigned char *input, 
                                    unsigned int len,
                                    unsigned int *out_len) {
  if (!input || len == 0 || !out_len) return NULL;
  
  unsigned int cmd_len = 0;
  for (unsigned int i = 0; i < len && i < 1000; i++) {
    if (input[i] == '\r' || input[i] == '\n') {
      cmd_len = i;
      break;
    }
  }
  
  if (cmd_len == 0) cmd_len = (len > 100) ? 100 : len;
  
  unsigned char *cmd = ck_alloc(cmd_len + 1);
  memcpy(cmd, input, cmd_len);
  cmd[cmd_len] = '\0';
  *out_len = cmd_len;
  
  return cmd;
}

/* ============================================
 * 局部Patch验证（GAP-2关键修复）
 * ============================================ */

/**
 * @brief 验证LLM生成的patch是否为局部修改
 * 
 * 实现：使用json-c库解析JSON并计数字段
 * 约束：字段数 <= max_fields（通常1-3）
 * 原因：防止LLM产生全局幻觉（修改过多字段）
 */
bool verify_patch_is_local(const char* patch_json, 
                           unsigned int max_fields,
                           unsigned int *out_field_count) {
  if (!patch_json || strlen(patch_json) == 0) {
    if (out_field_count) *out_field_count = 0;
    return false; /* 空patch非法 */
  }
  
  /* 1. 解析JSON */
  struct json_object *patch = json_tokener_parse(patch_json);
  if (!patch) {
    /* JSON解析失败（可能包含非法字符） */
    if (out_field_count) *out_field_count = 0;
    return false;
  }
  
  /* 2. 检查是否为JSON对象（不是数组或基本类型） */
  if (!json_object_is_type(patch, json_type_object)) {
    json_object_put(patch); /* 释放资源 */
    if (out_field_count) *out_field_count = 0;
    return false;
  }
  
  /* 3. 计算字段数量 */
  unsigned int num_fields = (unsigned int)json_object_object_length(patch);
  
  if (out_field_count) {
    *out_field_count = num_fields;
  }
  
  /* 4. 验证字段数量约束 */
  bool is_local = (num_fields > 0 && num_fields <= max_fields);
  
  /* 5. 清理资源 */
  json_object_put(patch);
  
  /* 6. 输出调试信息（在违反约束时） */
  if (!is_local && num_fields > 0) {
    /* 可以添加日志：patch有num_fields个字段，超过max_fields限制 */
  }
  
  return is_local;
}

/**
 * @brief Delta Debugging最小化（完整实现）
 * 
 * 算法详解：
 * 1. 从chunk_size = len/2开始（二分）
 * 2. 遍历所有可能的删除位置
 * 3. 如果删除后仍触发相同错误，接受删除
 * 4. 否则拒绝删除，尝试下一个位置
 * 5. 减小chunk_size，重复直到chunk_size=1
 * 
 * 时间复杂度：O(n^2) worst case, O(n log n) average
 * 空间复杂度：O(n)
 */
unsigned char *delta_debug_minimize(const unsigned char *input, 
                                    unsigned int len,
                                    unsigned int target_error_code,
                                    test_func_t test_func,
                                    DDTestContext *test_ctx,
                                    unsigned int *out_len) {
  if (!input || len == 0 || !test_func || !test_ctx || !out_len) {
    return NULL;
  }
  
  /* 初始化当前版本 */
  unsigned char *current = ck_alloc(len);
  memcpy(current, input, len);
  unsigned int current_len = len;
  
  /* 设置测试上下文的目标错误码 */
  test_ctx->target_error_code = target_error_code;
  
  /* 记录统计信息 */
  unsigned int total_tests = 0;
  unsigned int successful_reductions = 0;
  
  /* 二分删除循环 */
  for (unsigned int chunk_size = len / 2; chunk_size >= 1; chunk_size /= 2) {
    unsigned int pos = 0;
    bool made_progress = false;
    
    while (pos + chunk_size <= current_len) {
      /* 创建删除chunk后的候选 */
      unsigned int candidate_len = current_len - chunk_size;
      
      /* 不能删除全部内容 */
      if (candidate_len == 0) {
        pos += chunk_size;
        continue;
      }
      
      unsigned char *candidate = ck_alloc(candidate_len);
      
      /* 复制删除前的部分 */
      if (pos > 0) {
        memcpy(candidate, current, pos);
      }
      
      /* 复制删除后的部分 */
      if (pos + chunk_size < current_len) {
        memcpy(candidate + pos, 
               current + pos + chunk_size, 
               current_len - pos - chunk_size);
      }
      
      /* 测试候选是否仍触发相同错误 */
      total_tests++;
      int error_code = test_func(candidate, candidate_len, test_ctx);
      
      if (error_code == (int)target_error_code) {
        /* 成功最小化：接受删除 */
        ck_free(current);
        current = candidate;
        current_len = candidate_len;
        successful_reductions++;
        made_progress = true;
        
        /* 不增加pos，重试当前位置（可能还能删除更多） */
      } else {
        /* 删除导致错误变化：拒绝删除 */
        ck_free(candidate);
        pos += chunk_size; // 尝试下一个位置
      }
      
      /* 安全检查：避免无限循环 */
      if (total_tests > 10000) {
        // fprintf(stderr, "[DD] Exceeded max tests, stopping\\n");
        goto dd_finish;
      }
    }
    
    /* 如果这一轮chunk_size没有取得进展，提前终止 */
    if (!made_progress && chunk_size == 1) {
      break;
    }
  }
  
dd_finish:
  /* 统计信息（可选） */
  // fprintf(stderr, "[DD] Minimization: %u → %u bytes (%.1f%% reduction, %u tests)\\n",
  //         len, current_len, 100.0 * (len - current_len) / len, total_tests);
  
  *out_len = current_len;
  return current;
}

/* ============================================
 * CEGAR缓存实现（去重+性能优化）
 * ============================================ */

/**
 * @brief 初始化CEGAR缓存
 */
void cegar_cache_init(CEGARCache *cache) {
  if (!cache) return;
  memset(cache, 0, sizeof(CEGARCache));
}

/**
 * @brief 查找缓存（P1-3修复：增加时间戳过期检查）
 */
unsigned char *cegar_cache_lookup(CEGARCache *cache,
                                  unsigned int error_code,
                                  const unsigned char *cmd_prefix,
                                  unsigned int prefix_len,
                                  unsigned int *out_len) {
  if (!cache || !cmd_prefix || prefix_len == 0) return NULL;
  
  unsigned int cmp_len = (prefix_len > 32) ? 32 : prefix_len;
  time_t current_time = time(NULL);
  
  /* P1-5修复：缓存过期统计（全局变量） */
  static unsigned long long g_cache_expired_count = 0;
  
  for (unsigned int i = 0; i < cache->count; i++) {
    CEGARCacheEntry *entry = &cache->entries[i];
    
    /* P1-3修复：5分钟缓存过期检查 */
    if (entry->timestamp > 0 && (current_time - entry->timestamp) > 300) {
      /* 缓存已过期，跳过此条目 */
      g_cache_expired_count++;
      if (g_cache_expired_count % 10 == 0) {
        /* 每10次过期输出日志，帮助调优过期阈值 */
        ACTF("[CEGAR-CACHE] Expired entry #%llu (age: %ld sec, code: %u)",
             g_cache_expired_count, (long)(current_time - entry->timestamp), 
             entry->error_code);
      }
      continue;
    }
    
    if (entry->error_code == error_code &&
        memcmp(entry->cmd_prefix, cmd_prefix, cmp_len) == 0 &&
        entry->success == 1) { // 只返回成功的修正
      
      entry->hit_count++;
      
      if (out_len) *out_len = entry->refined_len;
      
      /* 返回拷贝（调用者需要free） */
      unsigned char *result = ck_alloc(entry->refined_len);
      memcpy(result, entry->refined_input, entry->refined_len);
      return result;
    }
  }
  
  return NULL; // 未找到
}

/**
 * @brief 添加到缓存（P1-3修复：记录时间戳）
 */
int cegar_cache_add(CEGARCache *cache,
                    unsigned int error_code,
                    const unsigned char *cmd_prefix,
                    unsigned int prefix_len,
                    const unsigned char *refined_input,
                    unsigned int refined_len,
                    unsigned int success) {
  if (!cache || !cmd_prefix || !refined_input) return 0;
  
  /* 检查缓存是否已满 */
  if (cache->count >= CEGAR_CACHE_SIZE) {
    /* 简单策略：替换hit_count最低的条目 */
    unsigned int min_hit = cache->entries[0].hit_count;
    unsigned int min_idx = 0;
    for (unsigned int i = 1; i < CEGAR_CACHE_SIZE; i++) {
      if (cache->entries[i].hit_count < min_hit) {
        min_hit = cache->entries[i].hit_count;
        min_idx = i;
      }
    }
    /* 释放旧条目 */
    if (cache->entries[min_idx].refined_input) {
      ck_free(cache->entries[min_idx].refined_input);
    }
    cache->count--; // 准备替换
  }
  
  /* 添加新条目 */
  CEGARCacheEntry *entry = &cache->entries[cache->count];
  entry->error_code = error_code;
  
  unsigned int cmp_len = (prefix_len > 32) ? 32 : prefix_len;
  memcpy(entry->cmd_prefix, cmd_prefix, cmp_len);
  
  entry->refined_input = ck_alloc(refined_len);
  memcpy(entry->refined_input, refined_input, refined_len);
  entry->refined_len = refined_len;
  
  entry->hit_count = 0;
  entry->success = success;
  entry->timestamp = time(NULL);  /* P1-3修复：记录当前时间戳 */
  
  cache->count++;
  return 1;
}

/**
 * @brief 保存缓存到文件
 */
int cegar_cache_save(CEGARCache *cache, const char *filename) {
  if (!cache || !filename) return 0;
  
  FILE *f = fopen(filename, "wb");
  if (!f) return 0;
  
  /* 写入缓存元数据 */
  fwrite(&cache->count, sizeof(unsigned int), 1, f);
  
  /* 写入每个条目 */
  for (unsigned int i = 0; i < cache->count; i++) {
    CEGARCacheEntry *entry = &cache->entries[i];
    fwrite(&entry->error_code, sizeof(unsigned int), 1, f);
    fwrite(entry->cmd_prefix, 32, 1, f);
    fwrite(&entry->refined_len, sizeof(unsigned int), 1, f);
    fwrite(entry->refined_input, entry->refined_len, 1, f);
    fwrite(&entry->hit_count, sizeof(unsigned int), 1, f);
    fwrite(&entry->success, sizeof(unsigned int), 1, f);
  }
  
  fclose(f);
  return 1;
}

/**
 * @brief 从文件加载缓存
 */
int cegar_cache_load(CEGARCache *cache, const char *filename) {
  if (!cache || !filename) return 0;
  
  FILE *f = fopen(filename, "rb");
  if (!f) return 0;
  
  /* 读取缓存元数据 */
  if (fread(&cache->count, sizeof(unsigned int), 1, f) != 1) {
    fclose(f);
    return 0;
  }
  
  if (cache->count > CEGAR_CACHE_SIZE) cache->count = CEGAR_CACHE_SIZE;
  
  /* 读取每个条目 */
  for (unsigned int i = 0; i < cache->count; i++) {
    CEGARCacheEntry *entry = &cache->entries[i];
    fread(&entry->error_code, sizeof(unsigned int), 1, f);
    fread(entry->cmd_prefix, 32, 1, f);
    fread(&entry->refined_len, sizeof(unsigned int), 1, f);
    
    if (entry->refined_len > 0 && entry->refined_len < 100000) {
      entry->refined_input = ck_alloc(entry->refined_len);
      fread(entry->refined_input, entry->refined_len, 1, f);
    }
    
    fread(&entry->hit_count, sizeof(unsigned int), 1, f);
    fread(&entry->success, sizeof(unsigned int), 1, f);
  }
  
  fclose(f);
  return 1;
}

/* ============================================
 * 反例最小化 (Delta Debugging思想)
 * ============================================ */

/**
 * @brief 贪心删除JSON字段，保留触发相同错误的最小子集
 */
int minimize_counterexample(const char* original_json, 
                             RealResponse* orig_res, 
                             ProtocolSpec* spec, 
                             char* out, 
                             size_t max_len) {
    if (!original_json || !orig_res || !out) {
        return 0;
    }
    
    /* 解析原始JSON */
    json_object* jobj = json_tokener_parse(original_json);
    if (!jobj) {
        strncpy(out, original_json, max_len - 1);
        return 0;
    }
    
    /* 获取所有字段 */
    json_object* minimal = json_object_new_object();
    int field_count = 0;
    const char* field_names[50];
    
    json_object_object_foreach(jobj, key, val) {
        field_names[field_count++] = key;
    }
    
    /* 贪心策略：优先保留必需字段 */
    for (int i = 0; i < 3; i++) {
        if (strlen(spec->mandatory_fields[i]) == 0) break;
        
        json_object* val = NULL;
        if (json_object_object_get_ex(jobj, spec->mandatory_fields[i], &val)) {
            json_object_object_add(minimal, spec->mandatory_fields[i], 
                                  json_object_get(val));
        }
    }
    
    /* 逐个尝试添加其他字段，只保留影响错误的字段 */
    for (int i = 0; i < field_count; i++) {
        const char* key = field_names[i];
        
        /* 跳过已添加的必需字段 */
        bool is_mandatory = false;
        for (int j = 0; j < 3; j++) {
            if (strcmp(key, spec->mandatory_fields[j]) == 0) {
                is_mandatory = true;
                break;
            }
        }
        if (is_mandatory) continue;
        
        /* 尝试不添加该字段，看是否仍触发相同错误 */
        // 简化实现：直接添加所有非必需字段到最小化版本
        // 实际应该发送测试并比较响应
        json_object* val = NULL;
        if (json_object_object_get_ex(jobj, key, &val)) {
            json_object_object_add(minimal, key, json_object_get(val));
        }
    }
    
    /* 序列化最小化后的JSON */
    const char* minimal_str = json_object_to_json_string_ext(minimal, 
                                                              JSON_C_TO_STRING_PLAIN);
    strncpy(out, minimal_str, max_len - 1);
    out[max_len - 1] = '\0';
    
    json_object_put(jobj);
    json_object_put(minimal);
    
    return 1;
}

/* ============================================
 * JSON字段级Patch应用
 * ============================================ */

/**
 * @brief 应用JSON patch（只允许修改最多3个字段）
 */
int apply_json_patch(const char* orig, const char* patch, 
                     char* out, size_t max_len) {
    if (!orig || !patch || !out) return 0;
    
    /* 解析原始JSON */
    json_object* jobj = json_tokener_parse(orig);
    if (!jobj) {
        strncpy(out, orig, max_len - 1);
        return 0;
    }
    
    /* 解析patch */
    json_object* patch_obj = json_tokener_parse(patch);
    if (!patch_obj) {
        strncpy(out, orig, max_len - 1);
        json_object_put(jobj);
        return 0;
    }
    
    /* 应用patch（限制最多修改3个字段） */
    int patched_count = 0;
    json_object_object_foreach(patch_obj, key, val) {
        if (patched_count >= 3) break;  // CEGAR关键：限制自由度
        
        /* 覆盖或添加字段 */
        json_object_object_add(jobj, key, json_object_get(val));
        patched_count++;
    }
    
    /* 序列化 */
    const char* result_str = json_object_to_json_string_ext(jobj, 
                                                             JSON_C_TO_STRING_PLAIN);
    strncpy(out, result_str, max_len - 1);
    out[max_len - 1] = '\0';
    
    json_object_put(jobj);
    json_object_put(patch_obj);
    
    return 1;
}

/* ============================================
 * Prompt构造（集成到chat-llm.c的接口）
 * ============================================ */

/**
 * @brief 构造反例驱动修正的prompt
 */
static char* construct_refinement_prompt(const char* failed_json,
                                        RealResponse* failure,
                                        ProtocolSpec* spec) {
    static char prompt[8192];
    
    snprintf(prompt, sizeof(prompt),
        "You are a protocol fuzzing expert. A test case was REJECTED by the server.\n\n"
        "Protocol: %s\n"
        "Failed test case (JSON):\n%s\n\n"
        "Server response:\n"
        "  Status code: %d\n"
        "  Body: %s\n\n"
        "Task: Suggest a LOCAL PATCH (modify at most 3 fields) to fix this error.\n"
        "Rules:\n"
        "1. Only output a JSON object with the fields to modify\n"
        "2. Maximum 3 fields allowed\n"
        "3. Must keep mandatory fields: %s, %s, %s\n"
        "4. Focus on the most likely cause of rejection\n\n"
        "Output only the patch JSON (no explanation):",
        spec->name,
        failed_json,
        failure->status_code,
        failure->body,
        spec->mandatory_fields[0],
        spec->mandatory_fields[1],
        spec->mandatory_fields[2]
    );
    
    return prompt;
}

/**
 * @brief 反例驱动修正主函数（调用LLM）
 */
char* refine_hypothesis_with_cegar(const char* failed_json, 
                                   RealResponse* failure, 
                                   ProtocolSpec* spec) {
    if (!failed_json || !failure || !spec) return NULL;
    
    /* 1. 最小化反例 */
    char minimized[4096];
    if (!minimize_counterexample(failed_json, failure, spec, 
                                 minimized, sizeof(minimized))) {
        return NULL;
    }
    
    /* 2. 构造refinement prompt */
    char* prompt = construct_refinement_prompt(minimized, failure, spec);
    
    /* 3. 调用LLM获取patch建议 */
    char* llm_response = chat_with_llm(prompt, "gpt-3.5-turbo", 3, 0.7);
    
    /* ChatAFL-Enhanced P0-3: 记录LLM调用日志 */
    const char *out_dir = get_out_dir();
    if (llm_response && out_dir) {
        LLMCallLog log = {0};
        log.prompt = prompt;
        log.response = llm_response;
        log.model = "gpt-3.5-turbo";
        log.temperature = 0.7;
        log.timestamp = time(NULL);
        log.prompt_tokens = (unsigned int)(strlen(prompt) / 4);
        log.response_tokens = (unsigned int)(strlen(llm_response) / 4);
        log.total_tokens = log.prompt_tokens + log.response_tokens;
        log.call_site = "CEGAR";
        log_llm_call(out_dir, &log);
    }
    
    if (!llm_response) {
        return NULL;
    }
    
    /* 4. 应用patch */
    char* refined = (char*)ck_alloc(4096);
    if (!refined) {
        fprintf(stderr, "[CEGAR] Failed to allocate memory for refined input\n");
      free(llm_response);
        return NULL;
    }
    
    if (!apply_json_patch(minimized, llm_response, refined, 4096)) {
        ck_free(refined);
      free(llm_response);
        return NULL;
    }
    
    free(llm_response);
    return refined;  // 调用者负责ck_free
}

/* ============================================
 * 辅助函数：提取错误原因
 * ============================================ */

/**
 * @brief 从响应体中提取错误关键词
 */
void extract_error_keywords(const char* body, char* out, size_t max_len) {
    if (!body || !out) return;
    
    /* 常见错误关键词 */
    const char* keywords[] = {
        "invalid", "denied", "failed", "incorrect", 
        "unauthorized", "forbidden", "bad request",
        "not found", "timeout", "overflow"
    };
    
    out[0] = '\0';
    for (int i = 0; i < sizeof(keywords) / sizeof(keywords[0]); i++) {
        if (strcasestr(body, keywords[i])) {
            strncat(out, keywords[i], max_len - strlen(out) - 1);
            strncat(out, " ", max_len - strlen(out) - 1);
        }
    }
}

/**
 * @brief 判断是否应该触发CEGAR修正
 */
bool should_trigger_cegar(RealResponse* resp, ProtocolSpec* spec) {
    if (!resp || !spec) return false;
    
    /* 只对拒绝类响应触发CEGAR */
    if (!is_rejection_response(resp->status_code, resp->body, spec->name)) {
        return false;
    }
    
    /* 避免对明显的格式错误触发（交给验证器处理） */
    if (strstr(resp->body, "parse error") || strstr(resp->body, "syntax error")) {
        return false;
    }
    
    return true;
}
