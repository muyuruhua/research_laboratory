/*
 * 文件: cegar.h
 * 描述: CEGAR (Counterexample-Guided Abstraction Refinement) 模块
 * 创新点: 将形式化方法的经典技术应用于LLM-fuzzing
 * 
 * 核心思想：
 * 1. LLM生成假设 (Hypothesis)
 * 2. 验证器检测错误 (Counterexample)
 * 3. 最小化反例 (Minimization)
 * 4. 局部修正 (Patch-based Refinement) - 限制LLM自由度，降低幻觉
 * 
 * P1-3修复：缓存时间戳支持
 */

#ifndef __CEGAR_H
#define __CEGAR_H

#include <stddef.h>
#include <time.h>
#include "protocol-spec.h"

/* ============================================
 * 反例最小化 API
 * ============================================ */

/**
 * @brief Delta Debugging最小化（简化版）
 * 
 * 策略：二分删除字节块，保留触发相同错误的最小子集
 * 实现：基于Delta Debugging论文（Zeller & Hildebrandt 2002）
 * 
 * @param input 原始失败的输入
 * @param len 输入长度
 * @param target_error_code 目标错误码（用于验证仍触发相同错误）
 * @param test_func 测试函数指针（返回错误码，0表示成功）
 * @param test_func_arg 测试函数的额外参数
 * @param out_len 输出：最小化后的长度
 * @return 动态分配的最小化输入（调用者需free），失败返回NULL
 */
/* Delta Debugging测试函数类型 */
typedef int (*test_func_t)(const unsigned char*, unsigned int, void*);

/* Delta Debugging测试上下文（传递给test_func） */
typedef struct {
  char **argv;                     // 目标程序参数
  unsigned int exec_tmout;         // 执行超时
  unsigned int target_error_code;  // 目标错误码
  void *extract_codes_func;        // extract_response_codes函数指针
  unsigned char **response_buf_ptr; // 响应缓冲区指针的指针
  unsigned int *response_size_ptr; // 响应大小指针
  void (*write_to_testcase_func)(void*, unsigned int); // write_to_testcase函数
  unsigned char (*run_target_func)(char**, unsigned int); // run_target函数
} DDTestContext;

/**
 * @brief Delta Debugging最小化（完整实现）
 * 
 * 算法：基于Zeller & Hildebrandt (TSE 2002)
 * 复杂度：O(n^2) worst case, O(n log n) average
 * 
 * @param input 原始输入
 * @param len 输入长度
 * @param target_error_code 目标错误码
 * @param test_func 测试函数（返回错误码）
 * @param test_ctx 测试上下文
 * @param out_len 输出：最小化后的长度
 * @return 最小化后的输入（调用者需free），失败返回NULL
 */
unsigned char *delta_debug_minimize(const unsigned char *input, 
                                    unsigned int len,
                                    unsigned int target_error_code,
                                    test_func_t test_func,
                                    DDTestContext *test_ctx,
                                    unsigned int *out_len);

/**
 * @brief 提取命令行（第一个\r\n之前的内容）
 * @param input 输入缓冲区
 * @param len 输入长度
 * @param out_len 输出：命令长度
 * @return 动态分配的命令字符串（调用者需free）
 */
unsigned char *extract_command_line(const unsigned char *input, 
                                    unsigned int len,
                                    unsigned int *out_len);

/**
 * @brief 验证LLM生成的patch是否为局部修改（关键约束）
 * 
 * 功能：解析patch JSON并验证修改字段数量不超过阈值
 * 目的：降低LLM幻觉风险，确保只做局部修正
 * 
 * @param patch_json LLM返回的patch JSON字符串
 * @param max_fields 允许的最大字段数（建议1-3）
 * @param out_field_count 输出：实际字段数（可选，传NULL忽略）
 * @return true=patch合法, false=patch违反约束
 * 
 * 示例合法patch: {"Content-Length": "123"}
 * 示例非法patch: {"f1":"v1", "f2":"v2", "f3":"v3", "f4":"v4"}
 */
bool verify_patch_is_local(const char* patch_json, 
                           unsigned int max_fields,
                           unsigned int *out_field_count);

/**
 * @brief 验证LLM生成的patch是否为局部修改（关键约束）
 * 
 * 功能：解析patch JSON并验证修改字段数量不超过阈值
 * 目的：降低LLM幻觉风险，确保只做局部修正
 * 
 * @param patch_json LLM返回的patch JSON字符串
 * @param max_fields 允许的最大字段数（建议1-3）
 * @param out_field_count 输出：实际字段数（可选，传NULL忽略）
 * @return true=patch合法, false=patch违反约束
 * 
 * 示例合法patch: {"Content-Length": "123"}
 * 示例非法patch: {"f1":"v1", "f2":"v2", "f3":"v3", "f4":"v4"}
 */
bool verify_patch_is_local(const char* patch_json, 
                           unsigned int max_fields,
                           unsigned int *out_field_count);

/**
 * @brief 最小化反例（JSON版本，保留用于兼容）
 */
int minimize_counterexample(const char* original_json, 
                             RealResponse* orig_res, 
                             ProtocolSpec* spec, 
                             char* out, 
                             size_t max_len);

/* ============================================
 * CEGAR缓存去重 API
 * ============================================ */

#define CEGAR_CACHE_SIZE 1024

typedef struct {
  unsigned int error_code;          // 错误码
  unsigned char cmd_prefix[32];     // 命令前缀（用于匹配）
  unsigned char *refined_input;     // LLM修正后的输入
  unsigned int refined_len;         // 修正输入长度
  unsigned int hit_count;           // 命中次数
  unsigned int success;             // 是否修正成功（1=成功,0=失败）
  time_t timestamp;                 /* P1-3修复: 缓存时间戳（用于5分钟过期检测） */
} CEGARCacheEntry;

typedef struct {
  CEGARCacheEntry entries[CEGAR_CACHE_SIZE];
  unsigned int count;               // 当前缓存条目数
} CEGARCache;

/**
 * @brief 初始化CEGAR缓存
 */
void cegar_cache_init(CEGARCache *cache);

/**
 * @brief 查找缓存（基于错误码+命令前缀）
 * @return 缓存的修正输入，未找到返回NULL
 */
unsigned char *cegar_cache_lookup(CEGARCache *cache,
                                  unsigned int error_code,
                                  const unsigned char *cmd_prefix,
                                  unsigned int prefix_len,
                                  unsigned int *out_len);

/**
 * @brief 添加到缓存
 * @return 1=成功添加, 0=缓存已满或重复
 */
int cegar_cache_add(CEGARCache *cache,
                    unsigned int error_code,
                    const unsigned char *cmd_prefix,
                    unsigned int prefix_len,
                    const unsigned char *refined_input,
                    unsigned int refined_len,
                    unsigned int success);

/**
 * @brief 保存缓存到文件（用于持久化）
 */
int cegar_cache_save(CEGARCache *cache, const char *filename);

/**
 * @brief 从文件加载缓存
 */
int cegar_cache_load(CEGARCache *cache, const char *filename);

/* ============================================
 * JSON操作工具 API
 * ============================================ */

/* remove_json_field() 已集成到 minimize_counterexample() 内部实现 */

/**
 * @brief 应用JSON补丁 (Patch-based Refinement)
 * 
 * 核心创新：限制LLM只能修改少数字段，而非重写整个JSON
 * 
 * 示例：
 * 原始: {"command":"USER","args":"test"}
 * 补丁: {"args":"anonymous"}
 * 结果: {"command":"USER","args":"anonymous"}
 * 
 * @param orig 原始JSON
 * @param patch 补丁JSON（仅包含要修改的字段）
 * @param out 输出缓冲区
 * @param max_len 缓冲区大小
 * @return 1=成功应用, 0=失败
 */
int apply_json_patch(const char* orig, const char* patch, 
                     char* out, size_t max_len);

/**
 * @brief 压缩JSON（去除空白字符）
 * 
 * 用于缓存键生成和日志记录
 * 
 * @param input 原始JSON
 * @param output 输出缓冲区
 */
void compact_json(const char* input, char* output);

/* ============================================
 * CEGAR主循环 API
 * ============================================ */

/**
 * @brief 使用CEGAR策略修正失败的假设
 * 
 * 完整流程：
 * 1. 接收失败的测试用例和错误响应
 * 2. 最小化反例（去除无关字段）
 * 3. 构造严格的prompt：
 *    - 明确错误类型（状态码、错误信息）
 *    - 限制修改范围（"最多修改3个字段"）
 *    - 要求输出格式（[PATCH]...[/PATCH]标签）
 * 4. 调用LLM生成patch
 * 5. 验证patch大小和结构
 * 6. 应用patch到原始JSON
 * 
 * @param failed_json 失败的测试用例JSON
 * @param failure 失败响应
 * @param spec 协议规范
 * @return 修正后的JSON字符串（需调用者free）, NULL=失败
 * 
 * 注意：此函数会调用 chat_with_llm()，需链接 chat-llm.c
 */
char* refine_hypothesis_with_cegar(const char* failed_json, 
                                   RealResponse* failure, 
                                   ProtocolSpec* spec);

/* ============================================
 * 高级特性：自适应修正策略 (Week 6)
 * ============================================ */

/* 注: 以下函数在Week 6补充实现（防止CEGAR循环）
 * - should_backoff_refinement() - 检测修正停滞
 * - reset_refinement_counter() - 重置计数器
 * 当前版本使用简单的固定重试次数策略
 */

#endif /* __CEGAR_H */
