/*
 * 文件: protocol-spec.h
 * 描述: 协议规范核心数据结构定义
 * 作用: 从test.c迁移的核心类型，供所有模块共享
 */

#ifndef __PROTOCOL_SPEC_H
#define __PROTOCOL_SPEC_H

#include <stdbool.h>

#define MAX_PAYLOAD_LEN 4096
#define MAX_STATES 256

/* 协议类型 */
typedef enum { 
    PROTO_TEXT,    // 文本协议 (FTP, SMTP, HTTP)
    PROTO_BINARY   // 二进制协议 (MQTT, RTSP)
} ProtoType;

/* 序列化模式 */
typedef enum { 
    SER_OBJECT,    // JSON对象模式: 单个请求
    SER_LIST       // JSON数组模式: 批量请求序列
} SerializationMode;

/* 协议语义状态 */
typedef enum {
    PROTO_STATE_INIT = 0,     // 初始化/欢迎
    PROTO_STATE_AUTH,         // 认证中
    PROTO_STATE_READY,        // 就绪/已认证
    PROTO_STATE_TRANSFER,     // 数据传输
    PROTO_STATE_ERROR,        // 错误状态
    PROTO_STATE_UNKNOWN       // 未知状态
} ProtoSemanticState;

/* 协议规范结构 */
typedef struct {
    char name[32];                    // 协议名称 (FTP, HTTP, MQTT等)
    int default_port;                 // 默认端口
    char payload_end[16];             // 消息结束符 (如 "\r\n")
    ProtoType type;                   // 协议类型
    
    /* LLM相关字段 */
    char role_prompt[1024];           // LLM角色定义
    char json_schema[2048];           // JSON Schema约束
    char init_template[2048];         // 初始测试用例模板
    char mandatory_fields[3][32];     // 必需字段 (如 "command", "args")
    
    /* 模板与序列化 */
    SerializationMode ser_mode;       // 序列化模式
    char list_key[32];                // 列表模式的根键名
    char template_str[1024];          // 实际协议格式模板 (如 "%command% %args%\r\n")
    
    /* 行为特性 */
    bool recv_banner_first;           // 服务端是否先发送banner (FTP=true, HTTP=false)
} ProtocolSpec;

/* 真实响应结构 */
typedef struct {
    int status_code;                  // 响应状态码 (如 FTP 230, HTTP 200)
    char body[1024];                  // 响应正文
    char state_hash[256];             // 状态哈希 (用于状态转移追踪)
} RealResponse;

/* Corpus条目（用于状态调度）*/
typedef struct { 
    char json[MAX_PAYLOAD_LEN];       // JSON测试用例
    char edge[512];                   // 触发的状态转移边 (如 "S_220 -> S_230")
    char target_state[256];           // 目标状态
    bool occupied;                    // 槽位是否被占用
} CorpusEntry;

/* 状态计数（用于低覆盖率优先调度）*/
typedef struct { 
    char state[256];                  // 状态标识符
    int count;                        // 访问次数
} StateCount;

/* 注: RejectionClassifier 及rejection_rules在Week 6补充
 * 当前版本使用verifier.c中的硬编码规则
 */

#endif /* __PROTOCOL_SPEC_H */
