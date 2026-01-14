/*
 * 文件: verifier.h
 * 描述: 可解释验证器模块 - 强制LLM生成的测试用例符合语法和约束
 * 创新点: 替代传统fuzzer的"盲目变异"，提供确定性的拒绝理由
 */

#ifndef __VERIFIER_H
#define __VERIFIER_H

#define PCRE2_CODE_UNIT_WIDTH 8  // 必须在include pcre2.h之前定义

#include <stdbool.h>
#include <stddef.h>
#include <pcre2.h>
#include "protocol-spec.h"

/* 验证器拒绝原因（可解释性关键）*/
typedef enum {
    VFY_OK = 0,                    // 通过验证
    VFY_EMPTY_INPUT,               // 输入为空
    VFY_TOO_LARGE,                 // 超过大小限制
    VFY_NO_JSON_OBJECT,            // 非JSON对象
    VFY_MISSING_MANDATORY,         // 缺少必需字段
    VFY_CONSTRAINT_MISMATCH,       // 约束不匹配 (类型、长度、枚举等)
    VFY_EXCESSIVE_FIELDS,          // 字段数过多 (资源耗尽防护)
    VFY_NESTING_TOO_DEEP          // 嵌套层次过深
} VerifierRejectReason;

/* ============================================
 * 核心验证器 API
 * ============================================ */

/**
 * @brief 验证JSON语法是否符合协议规范
 * @param json_input 待验证的JSON字符串
 * @param spec 协议规范
 * @return true=通过验证, false=被拒绝
 * 
 * 验证逻辑：
 * 1. 必需字段检查 (mandatory_fields)
 * 2. JSON Schema约束验证 (类型、长度、枚举等)
 * 3. 资源限制 (字段数、嵌套深度)
 */
bool verify_json_grammar(const char* json_input, ProtocolSpec* spec);

/**
 * @brief 获取上次验证失败的原因
 * @return 拒绝原因枚举值
 */
VerifierRejectReason get_last_verifier_reason();

/**
 * @brief 将拒绝原因转换为可读字符串
 * @param r 拒绝原因
 * @return 原因描述字符串
 */
const char* verifier_reason_str(VerifierRejectReason r);

/* ============================================
 * 响应分类器 API (可接受性验证)
 * ============================================ */

/**
 * @brief 判断服务端响应是否为拒绝类 (Rejection)
 * @param status_code 响应状态码
 * @param body 响应正文
 * @param proto_name 协议名称 (如 "FTP", "HTTP")
 * @return true=拒绝响应, false=接受响应
 * 
 * 分类依据：
 * - FTP: 5xx错误码, "fail", "error"等关键词
 * - HTTP: 4xx/5xx错误码
 * - SMTP: 5xx错误码
 * - Redis: "-ERR", "-WRONGTYPE"前缀
 */
bool is_rejection_response(int status_code, const char* body, const char* proto_name);

/**
 * @brief 提取协议语义状态
 * @param proto_name 协议名称
 * @param status_code 响应码
 * @param body 响应正文
 * @return 语义状态枚举值
 * 
 * 示例：
 * - FTP 220 -> PROTO_STATE_INIT (欢迎)
 * - FTP 230 -> PROTO_STATE_READY (已登录)
 * - FTP 150 -> PROTO_STATE_TRANSFER (传输中)
 */
ProtoSemanticState extract_protocol_state(const char* proto_name, 
                                           int status_code, 
                                           const char* body);

/* ============================================
 * PCRE2正则验证 API（完整实现）
 * ============================================ */

/**
 * @brief 使用PCRE2正则表达式验证协议命令
 * @param input 输入缓冲区
 * @param len 输入长度
 * @param protocol 协议名称（自动选择对应正则）
 * @param pattern 自定义正则表达式（NULL则使用协议默认）
 * @return true=匹配成功, false=不匹配
 */
bool verify_with_pcre2(const unsigned char *input, 
                       unsigned int len,
                       const char *protocol,
                       const char *pattern);

/**
 * @brief 获取协议的默认正则表达式
 */
const char* get_protocol_regex(const char *protocol);

/* ============================================
 * 状态聚类增强（不仅是响应码）
 * ============================================ */

typedef struct {
  unsigned int response_code;      // 响应码（主要标识）
  char key_headers[256];           // 关键header（如Set-Cookie, Content-Type）
  unsigned char coverage_hash[8];  // 执行路径hash（8字节）
  unsigned int header_count;       // header数量
} StateSignature;

/**
 * @brief 计算增强的状态ID（基于响应码+header+coverage）
 * @param signature 状态签名
 * @return 聚类后的状态ID
 */
unsigned int compute_enhanced_state_id(StateSignature *signature);

/**
 * @brief 提取HTTP/SMTP/FTP关键header
 * @param response_buf 响应缓冲区
 * @param response_len 响应长度
 * @param out_headers 输出header字符串
 * @param max_len 输出缓冲区大小
 * @return 提取的header数量
 */
unsigned int extract_key_headers(const unsigned char *response_buf,
                                 unsigned int response_len,
                                 char *out_headers,
                                 unsigned int max_len);

/* ============================================
 * 辅助工具函数
 * ============================================ */

/* 注: 以下辅助函数在Week 6补充实现（非核心功能）
 * - strcasestr_portable() - 跨平台字符串查找
 * - unwrap_json_root() - JSON解包
 * - extract_json_value_generic() - 智能字段提取
 */

#endif /* __VERIFIER_H */
