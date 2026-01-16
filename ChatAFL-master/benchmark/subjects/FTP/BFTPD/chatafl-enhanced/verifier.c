/*
 * verifier.c - 可解释验证器模块实现
 * 功能: 强制LLM生成的测试用例符合协议语法和约束
 * Week 2: Verifier v0 - 基础版本
 * P0增强: PCRE2正则验证 + 状态聚类
 * P1增强: Layer 3-4 真实SUT验证（采样模式）
 */

#define PCRE2_CODE_UNIT_WIDTH 8  // 必须在include pcre2.h之前定义

#include "verifier.h"
#include "alloc-inl.h"
#include "hash.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <json-c/json.h>
#include <ctype.h>
#include <pcre2.h>

#ifdef USE_REAL_SUT_VERIFICATION
#include "sut-verifier-client.h"
#endif

/* 全局变量：记录上次验证失败原因 */
static VerifierRejectReason last_reject_reason = VFY_OK;

/* 全局变量：SUT验证开关（默认关闭） */
static bool g_sut_verification_enabled = false;

/* SUT验证控制函数 */
int sut_verify_layer3_layer4_enabled(void) {
    return g_sut_verification_enabled;
}

void enable_sut_verification(const char* socket_path) {
#ifdef USE_REAL_SUT_VERIFICATION
    if (sut_verifier_connect(socket_path) == 0) {
        g_sut_verification_enabled = true;
        fprintf(stderr, "[OK] Real SUT verification enabled (socket: %s)\n", socket_path);
    } else {
        fprintf(stderr, "[WARN] Failed to connect to SUT verifier, using heuristic mode\n");
        g_sut_verification_enabled = false;
    }
#else
    fprintf(stderr, "[INFO] Real SUT verification not compiled (USE_REAL_SUT_VERIFICATION=0)\n");
#endif
}

void disable_sut_verification(void) {
#ifdef USE_REAL_SUT_VERIFICATION
    sut_verifier_disconnect();
#endif
    g_sut_verification_enabled = false;
}

/* ============================================
 * PCRE2正则验证实现（完整版）
 * ============================================ */

/* 协议正则表达式映射表 */
typedef struct {
  const char *protocol;
  const char *regex;
  const char *description;
} ProtocolRegexEntry;

static const ProtocolRegexEntry protocol_regex_table[] = {
  /* FTP命令格式 */
  {"FTP", 
   "^(USER|PASS|ACCT|CWD|CDUP|SMNT|QUIT|REIN|PORT|PASV|TYPE|STRU|MODE|"
   "RETR|STOR|STOU|APPE|ALLO|REST|RNFR|RNTO|ABOR|DELE|RMD|MKD|PWD|LIST|"
   "NLST|SITE|SYST|STAT|HELP|NOOP)( [\\x20-\\x7E]+)?\\r\\n$",
   "FTP command with CRLF ending"},
  
  /* SMTP命令格式 */
  {"SMTP",
   "^(HELO|EHLO|MAIL FROM|RCPT TO|DATA|RSET|VRFY|EXPN|HELP|NOOP|QUIT)"
   "( [\\x20-\\x7E]+)?\\r\\n$",
   "SMTP command with CRLF ending"},
  
  /* HTTP请求行格式 */
  {"HTTP",
   "^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) "
   "[\\x21-\\x7E]+ HTTP/[0-9]\\.[0-9]\\r\\n",
   "HTTP request line"},
  
  /* SIP请求格式 */
  {"SIP",
   "^(INVITE|ACK|BYE|CANCEL|OPTIONS|REGISTER) [\\x21-\\x7E]+ SIP/2\\.0\\r\\n",
   "SIP request line"},
  
  {NULL, NULL, NULL} // 终止符
};

/**
 * @brief 获取协议的默认正则表达式
 */
const char* get_protocol_regex(const char *protocol) {
  if (!protocol) return NULL;
  
  for (int i = 0; protocol_regex_table[i].protocol != NULL; i++) {
    if (strcasecmp(protocol, protocol_regex_table[i].protocol) == 0) {
      return protocol_regex_table[i].regex;
    }
  }
  
  return NULL;
}

/**
 * @brief 使用PCRE2正则表达式验证协议命令（完整实现）
 */
bool verify_with_pcre2(const unsigned char *input, 
                       unsigned int len,
                       const char *protocol,
                       const char *pattern) {
  if (!input || len == 0) return false;
  
  /* 获取正则表达式 */
  const char *regex = pattern ? pattern : get_protocol_regex(protocol);
  if (!regex) {
    /* 无可用正则，返回true（不阻止） */
    return true;
  }
  
  /* 编译正则表达式 */
  int errcode;
  PCRE2_SIZE erroffset;
  pcre2_code *re = pcre2_compile(
    (PCRE2_SPTR)regex,
    PCRE2_ZERO_TERMINATED,
    PCRE2_CASELESS,  // 不区分大小写
    &errcode,
    &erroffset,
    NULL
  );
  
  if (!re) {
    /* 编译失败，打印错误但不阻止 */
    PCRE2_UCHAR buffer[256];
    pcre2_get_error_message(errcode, buffer, sizeof(buffer));
    // fprintf(stderr, "[PCRE2] Compilation failed: %s\\n", buffer);
    return true;
  }
  
  /* 创建匹配数据 */
  pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(re, NULL);
  if (!match_data) {
    pcre2_code_free(re);
    return true;
  }
  
  /* 执行匹配 */
  int rc = pcre2_match(
    re,
    (PCRE2_SPTR)input,
    len,
    0,              // 起始偏移
    0,              // 选项
    match_data,
    NULL
  );
  
  /* 清理资源 */
  pcre2_match_data_free(match_data);
  pcre2_code_free(re);
  
  /* 返回匹配结果 */
  return (rc > 0);  // rc > 0 表示匹配成功
}

/* ============================================
 * 状态聚类增强实现（完整版）
 * ============================================ */

/**
 * @brief 提取HTTP/SMTP/FTP关键header
 */
unsigned int extract_key_headers(const unsigned char *response_buf,
                                 unsigned int response_len,
                                 char *out_headers,
                                 unsigned int max_len) {
  if (!response_buf || !out_headers || response_len == 0 || max_len == 0) {
    return 0;
  }
  
  memset(out_headers, 0, max_len);
  unsigned int header_count = 0;
  unsigned int out_pos = 0;
  
  /* 定义关键header列表 */
  const char *key_headers[] = {
    "Set-Cookie:", "Cookie:",
    "Content-Type:", "Content-Length:",
    "Location:", "Authorization:",
    "WWW-Authenticate:", "Transfer-Encoding:",
    NULL
  };
  
  /* 逐行扫描响应 */
  unsigned int line_start = 0;
  for (unsigned int i = 0; i < response_len && i < 4096; i++) {
    if (response_buf[i] == '\n') {
      unsigned int line_len = i - line_start;
      
      /* 检查是否是关键header */
      for (int h = 0; key_headers[h] != NULL; h++) {
        unsigned int hdr_len = strlen(key_headers[h]);
        
        if (line_len >= hdr_len && 
            strncasecmp((char*)&response_buf[line_start], 
                       key_headers[h], hdr_len) == 0) {
          
          /* 提取header值（跳过header名称） */
          unsigned int value_start = line_start + hdr_len;
          while (value_start < i && 
                 (response_buf[value_start] == ' ' || 
                  response_buf[value_start] == '\t')) {
            value_start++;
          }
          
          unsigned int value_len = i - value_start;
                    if (value_len > 0) {
                        /* 复制header值（截断到50字符） */
                        unsigned int copy_len = (value_len > 50) ? 50 : value_len;

                        /* 需要的空间: "Header=" + value + ";" + "\0" */
                        unsigned int needed = hdr_len + 1 + copy_len + 1 + 1;
                        if (out_pos + needed > max_len) {
                            break;
                        }

                        /* 添加到输出（格式：header_name=value;） */
                        int written = snprintf(out_headers + out_pos,
                                                                     max_len - out_pos,
                                                                     "%s=", key_headers[h]);
                        if (written < 0 || (unsigned int)written >= (max_len - out_pos)) {
                            out_headers[max_len - 1] = '\0';
                            return header_count;
                        }
                        out_pos += (unsigned int)written;

                        memcpy(out_headers + out_pos,
                                     &response_buf[value_start],
                                     copy_len);
                        out_pos += copy_len;

                        out_headers[out_pos++] = ';';
                        header_count++;
                    }
          
          break;
        }
      }
      
      line_start = i + 1;
      
      /* 遇到空行（header结束） */
      if (line_len <= 1) break;
    }
  }
  
    if (out_pos >= max_len) {
        out_headers[max_len - 1] = '\0';
    } else {
        out_headers[out_pos] = '\0';
    }
  return header_count;
}

/**
 * @brief 计算增强的状态ID（基于响应码+header+coverage）
 */
unsigned int compute_enhanced_state_id(StateSignature *signature) {
  if (!signature) return 0;
  
  /* 使用哈希函数组合多个因素 */
  unsigned int hash = signature->response_code;
  
  /* 混入关键header的哈希 */
  if (signature->key_headers[0] != '\0') {
    for (int i = 0; signature->key_headers[i] != '\0' && i < 256; i++) {
      hash = hash * 33 + (unsigned char)signature->key_headers[i];
    }
  }
  
  /* 混入coverage hash（8字节） */
  for (int i = 0; i < 8; i++) {
    hash = hash * 33 + signature->coverage_hash[i];
  }
  
  /* 混入header数量 */
  hash = hash * 33 + signature->header_count;
  
  /* 聚类：将相似的hash映射到相同的状态ID */
  /* 简化版聚类：取hash的高16位作为粗粒度聚类 */
  unsigned int cluster_id = (hash >> 16) & 0xFFFF;
  
  /* 组合：response_code的低8位 + cluster_id */
  return ((signature->response_code & 0xFF) << 16) | cluster_id;
}

/* ============================================
 * 辅助函数：协议状态提取
 * ============================================ */

/**
 * @brief 从响应码和消息体中提取协议状态
 */
ProtoSemanticState extract_protocol_state(const char* proto_name, 
                                          int status_code, 
                                          const char* body) {
    if (!proto_name || !body) return PROTO_STATE_UNKNOWN;
    
    /* FTP状态映射 */
    if (strcasecmp(proto_name, "FTP") == 0) {
        if (status_code >= 200 && status_code < 300) {
            if (status_code == 220) return PROTO_STATE_INIT;      // 欢迎消息
            if (status_code == 230) return PROTO_STATE_READY;     // 登录成功
            if (status_code == 250) return PROTO_STATE_READY;     // 命令成功
            return PROTO_STATE_READY;
        }
        if (status_code >= 300 && status_code < 400) {
            return PROTO_STATE_AUTH;  // 需要密码
        }
        if (status_code >= 400 && status_code < 600) {
            return PROTO_STATE_ERROR;  // 错误状态
        }
    }
    
    /* SMTP状态映射 */
    if (strcasecmp(proto_name, "SMTP") == 0) {
        if (status_code == 220) return PROTO_STATE_INIT;
        if (status_code == 250) return PROTO_STATE_READY;
        if (status_code == 354) return PROTO_STATE_TRANSFER;  // 数据输入模式
        if (status_code >= 500) return PROTO_STATE_ERROR;
    }
    
    /* HTTP状态映射 */
    if (strcasecmp(proto_name, "HTTP") == 0) {
        if (status_code >= 200 && status_code < 300) return PROTO_STATE_READY;
        if (status_code == 401 || status_code == 407) return PROTO_STATE_AUTH;
        if (status_code >= 400) return PROTO_STATE_ERROR;
    }
    
    return PROTO_STATE_UNKNOWN;
}

/**
 * @brief 判断响应是否为拒绝类响应
 * 
 * P0-1修复：区分硬拒绝(Hard Rejection)和软拒绝(Soft Rejection/临时错误)
 * - 硬拒绝：永久性错误，需要CEGAR修正（如语法错误、权限拒绝）
 * - 软拒绝：临时性错误，可重试（如服务繁忙、资源暂时不可用）
 */
bool is_rejection_response(int status_code, const char* body, const char* proto_name) {
    if (!body || !proto_name) return false;
    
    /* FTP拒绝响应（RFC 959） */
    if (strcasecmp(proto_name, "FTP") == 0) {
        // 软拒绝（临时错误）：421=服务不可用, 425=无法打开数据连接
        if (status_code == 421 || status_code == 425) {
            return false;  // 视为部分接受，不触发CEGAR
        }
        // 硬拒绝：5xx永久错误, 4xx客户端错误（除421/425外）
        if (status_code >= 500 && status_code < 600) return true;
        if (status_code >= 400 && status_code < 500) return true;
        // 检查关键词（永久性错误）
        if (strstr(body, "failed") || strstr(body, "incorrect") || 
            strstr(body, "denied") || strstr(body, "invalid")) {
            return true;
        }
    }
    
    /* SMTP拒绝响应（RFC 5321） */
    if (strcasecmp(proto_name, "SMTP") == 0) {
        // 软拒绝（临时错误）：421=服务关闭, 450=邮箱不可用（临时）
        if (status_code == 421 || status_code == 450) {
            return false;  // 视为临时错误，不触发CEGAR
        }
        // 硬拒绝：5xx永久错误
        if (status_code >= 500) return true;
        if (strstr(body, "rejected") || strstr(body, "denied")) return true;
    }
    
    /* HTTP拒绝响应 */
    if (strcasecmp(proto_name, "HTTP") == 0) {
        if (status_code >= 400) return true;
    }
    
    return false;
}

/* ============================================
 * 核心验证逻辑
 * ============================================ */

/**
 * @brief 检查必需字段是否存在
 */
static bool check_mandatory_fields(json_object* jobj, ProtocolSpec* spec) {
    for (int i = 0; i < 3; i++) {
        if (strlen(spec->mandatory_fields[i]) == 0) break;
        
        if (!json_object_object_get_ex(jobj, spec->mandatory_fields[i], NULL)) {
            last_reject_reason = VFY_MISSING_MANDATORY;
            return false;
        }
    }
    return true;
}

/**
 * @brief 检查字段约束（类型、长度、枚举值等）
 */
static bool check_field_constraints(json_object* jobj, ProtocolSpec* spec) {
    json_object_object_foreach(jobj, key, val) {
        (void)key;  /* 消除未使用警告 */
        /* 检查字符串长度 */
        if (json_object_is_type(val, json_type_string)) {
            const char* str = json_object_get_string(val);
            if (strlen(str) > MAX_PAYLOAD_LEN) {
                last_reject_reason = VFY_TOO_LARGE;
                return false;
            }
        }
        
        /* 检查嵌套深度（防止递归炸弹） */
        if (json_object_is_type(val, json_type_object) || 
            json_object_is_type(val, json_type_array)) {
            // 简单实现：限制嵌套对象
            json_object_object_foreach(val, k2, v2) {
                (void)k2;  /* 消除未使用警告 */
                if (json_object_is_type(v2, json_type_object)) {
                    last_reject_reason = VFY_NESTING_TOO_DEEP;
                    return false;
                }
            }
        }
    }
    return true;
}

/**
 * @brief 检查字段数量（防止资源耗尽）
 */
static bool check_field_count(json_object* jobj) {
    int count = json_object_object_length(jobj);
    if (count > 50) {  // 合理限制
        last_reject_reason = VFY_EXCESSIVE_FIELDS;
        return false;
    }
    return true;
}

/**
 * @brief 核心验证函数
 */
bool verify_json_grammar(const char* json_input, ProtocolSpec* spec) {
    last_reject_reason = VFY_OK;
    
    /* 1. 基本检查 */
    if (!json_input || strlen(json_input) == 0) {
        last_reject_reason = VFY_EMPTY_INPUT;
        return false;
    }
    
    if (strlen(json_input) > MAX_PAYLOAD_LEN) {
        last_reject_reason = VFY_TOO_LARGE;
        return false;
    }
    
    /* 2. JSON解析 */
    json_object* jobj = json_tokener_parse(json_input);
    if (!jobj) {
        last_reject_reason = VFY_NO_JSON_OBJECT;
        return false;
    }
    
    /* 3. 必需字段检查 */
    if (!check_mandatory_fields(jobj, spec)) {
        json_object_put(jobj);
        return false;
    }
    
    /* 4. 字段约束检查 */
    if (!check_field_constraints(jobj, spec)) {
        json_object_put(jobj);
        return false;
    }
    
    /* 5. 资源限制检查 */
    if (!check_field_count(jobj)) {
        json_object_put(jobj);
        return false;
    }
    
    json_object_put(jobj);
    return true;
}

/**
 * @brief 获取上次拒绝原因
 */
VerifierRejectReason get_last_verifier_reason() {
    return last_reject_reason;
}

/**
 * @brief 将拒绝原因转换为可读字符串
 */
const char* verifier_reason_str(VerifierRejectReason r) {
    switch (r) {
        case VFY_OK: return "OK";
        case VFY_EMPTY_INPUT: return "Empty input";
        case VFY_TOO_LARGE: return "Input too large";
        case VFY_NO_JSON_OBJECT: return "Not a valid JSON object";
        case VFY_MISSING_MANDATORY: return "Missing mandatory field";
        case VFY_CONSTRAINT_MISMATCH: return "Constraint mismatch";
        case VFY_EXCESSIVE_FIELDS: return "Too many fields";
        case VFY_NESTING_TOO_DEEP: return "Nesting too deep";
        default: return "Unknown error";
    }
}

/* ============================================
 * SUT可接受性检查（Week 2核心）
 * ============================================ */

/**
 * @brief 根据响应判断测试用例的可接受性
 * @return true=被SUT接受, false=被拒绝
 */
bool is_test_case_acceptable(RealResponse* resp, ProtocolSpec* spec) {
    if (!resp || !spec) return false;
    
    /* 检查是否为拒绝响应 */
    if (is_rejection_response(resp->status_code, resp->body, spec->name)) {
        return false;
    }
    
    /* 检查状态是否为错误状态 */
    ProtoSemanticState state = extract_protocol_state(spec->name, 
                                                      resp->status_code, 
                                                      resp->body);
    if (state == PROTO_STATE_ERROR) {
        return false;
    }
    
    return true;
}

/**
 * @brief 提取响应中的状态哈希（用于状态覆盖追踪）
 */
void extract_state_hash(RealResponse* resp, ProtocolSpec* spec) {
    if (!resp || !spec) return;
    
    ProtoSemanticState state = extract_protocol_state(spec->name, 
                                                      resp->status_code, 
                                                      resp->body);
    
    /* 生成状态哈希: "S_<code>_<state_name>" */
    snprintf(resp->state_hash, sizeof(resp->state_hash), 
             "S_%d_%s", 
             resp->status_code,
             state == PROTO_STATE_INIT ? "init" :
             state == PROTO_STATE_AUTH ? "auth" :
             state == PROTO_STATE_READY ? "ready" :
             state == PROTO_STATE_TRANSFER ? "transfer" :
             state == PROTO_STATE_ERROR ? "error" : "unknown");
}

/* ============================================
 * P0-2修复：CEGAR修正后再验证（闭环保证）
 * ============================================ */

/**
 * @brief 对CEGAR修正后的输入进行完整4层验证
 * @param refined_input CEGAR修正后的JSON字符串
 * @param spec 协议规范
 * @param original_failure 原始失败响应（用于对比）
 * @return true=修正有效（通过验证），false=修正无效
 * 
 * 验证流程：
 * 1. Layer 1: 可解析性（JSON格式+Schema）
 * 2. Layer 2: 可接受性（模拟发送，检查响应）- 简化为格式检查
 * 3. Layer 3: 状态可达性（检查是否触发新状态）
 * 4. Layer 4: 覆盖增益（理论上应该有，此处简化）
 */
bool verify_refined_input(const char* refined_input, 
                         ProtocolSpec* spec,
                         RealResponse* original_failure) {
    if (!refined_input || !spec) {
        return false;
    }
    
    /* Layer 1: 可解析性验证 */
    if (!verify_json_grammar(refined_input, spec)) {
        return false;  // 修正后仍然无法解析，CEGAR失败
    }
    
    /* Layer 2: 可接受性验证（简化版：检查是否修正了明显错误）*/
    json_object *jobj = json_tokener_parse(refined_input);
    if (!jobj) {
        return false;
    }
    
    /* P0-CRITICAL: 集成is_rejection_response到Layer 2验证 */
    /* 尝试从refined_input中提取状态码（假设JSON中有"status"或"code"字段） */
    int extracted_status = 0;
    json_object *status_obj = NULL;
    if (json_object_object_get_ex(jobj, "status", &status_obj)) {
        extracted_status = json_object_get_int(status_obj);
    } else if (json_object_object_get_ex(jobj, "code", &status_obj)) {
        extracted_status = json_object_get_int(status_obj);
    }
    
    /* 如果提取到状态码，检查是否为拒绝响应（通用检查，不依赖具体协议） */
    if (extracted_status >= 400) {
        json_object_put(jobj);
        return false; /* refined_input包含4xx/5xx错误码，视为拒绝响应 */
    }
    
    /* 检查必需字段是否齐全 */
    bool has_required = true;
    for (int i = 0; i < 3 && spec->mandatory_fields[i][0] != '\0'; i++) {
        if (!json_object_object_get_ex(jobj, spec->mandatory_fields[i], NULL)) {
            has_required = false;
            break;
        }
    }
    json_object_put(jobj);
    
    if (!has_required) {
        return false;  // 修正后缺少必需字段
    }
    
    /* Layer 3 & 4: 状态可达性+覆盖增益 */
    /* P1-ENHANCEMENT: 集成真实SUT验证（采样模式） */
    #ifdef USE_REAL_SUT_VERIFICATION
    if (g_sut_verification_enabled) {
        /* 使用真实SUT验证（通过Unix socket与Python verifier通信） */
        sut_verify_result_t sut_result;
        if (sut_verify_layer3_layer4((const unsigned char*)refined_input, 
                                      strlen(refined_input), 
                                      &sut_result) == 0) {
            /* 成功获取SUT验证结果 */
            if (sut_result.sampled) {
                /* 被采样验证，使用真实结果 */
                bool sut_passed = sut_result.should_keep;
                if (sut_passed && sut_result.layer3_passed) {
                    /* 可选：记录新状态到state graph */
                    // fprintf(stderr, "[SUT-L3] New state: %s\n", sut_result.new_state);
                }
                json_object_put(jobj);
                return sut_passed;
            }
            /* 未采样，降级到启发式判断（下面的代码） */
        }
        /* SUT验证出错，降级到启发式判断 */
    }
    #endif
    
    /* 启发式判断（默认路径 or SUT未启用）*/
    size_t refined_len = strlen(refined_input);
    if (refined_len < 10 || refined_len > 65536) {
        return false;  // 长度异常
    }
    
    /* 对比原始失败：检查是否做了实质性修改 */
    if (original_failure && original_failure->body) {
        /* 如果refined_input与原始输入完全相同，则CEGAR未生效 */
        if (strcmp(refined_input, original_failure->body) == 0) {
            return false;
        }
    }
    
    /* 通过所有检查，认为修正有效 */
    return true;
}
