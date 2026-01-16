/*
 * rfc-grammar.h
 * 
 * RFC Grammar离线加载器
 * 集成rfc-grammar-converter.py生成的Grammar JSON
 * 
 * 用法：
 *   1. 运行: python3 rfc-grammar-converter.py --auto-generate-all
 *   2. 加载: load_rfc_grammar("FTP")
 *   3. 使用: get_grammar_commands(), get_grammar_state_machine()
 */

#ifndef RFC_GRAMMAR_H
#define RFC_GRAMMAR_H

#include <stdbool.h>
#include <json-c/json.h>

/* RFC Grammar结构 */
typedef struct {
    char protocol[16];
    char rfc_number[32];
    struct json_object* commands;       /* 命令模板 */
    struct json_object* responses;      /* 响应码 */
    struct json_object* state_machine;  /* 状态机 */
    struct json_object* constraints;    /* 字段约束 */
    struct json_object* raw_json;       /* 原始JSON（用于释放） */
} rfc_grammar_t;

/**
 * @brief 加载RFC Grammar（从JSON文件或内嵌C头文件）
 * @param protocol 协议名称（FTP/SMTP/HTTP/RTSP/SIP/DAAP）
 * @return Grammar对象指针，失败返回NULL
 */
rfc_grammar_t* load_rfc_grammar(const char* protocol);

/**
 * @brief 释放Grammar对象
 */
void free_rfc_grammar(rfc_grammar_t* grammar);

/**
 * @brief 获取命令列表（用于template generation）
 * @param grammar Grammar对象
 * @param commands 输出命令名数组（调用者需分配空间）
 * @param max_count 最大命令数
 * @return 实际命令数
 */
int get_grammar_commands(rfc_grammar_t* grammar, char** commands, int max_count);

/**
 * @brief 获取命令的模板
 * @param grammar Grammar对象
 * @param command 命令名
 * @return JSON对象（含template和constraints字段）
 */
struct json_object* get_command_template(rfc_grammar_t* grammar, const char* command);

/**
 * @brief 获取状态机定义（用于state exploration）
 * @param grammar Grammar对象
 * @param state 状态名
 * @param next_commands 输出下一步可用命令（调用者分配）
 * @param max_count 最大命令数
 * @return 实际命令数
 */
int get_next_commands_for_state(rfc_grammar_t* grammar, 
                                const char* state,
                                char** next_commands,
                                int max_count);

/**
 * @brief 将Grammar转换为prompt示例（兼容现有chat-llm.c接口）
 * @param grammar Grammar对象
 * @param example_buffer 输出缓冲区
 * @param buffer_size 缓冲区大小
 * @return 写入的字节数
 */
int grammar_to_prompt_examples(rfc_grammar_t* grammar, 
                               char* example_buffer, 
                               size_t buffer_size);

#endif /* RFC_GRAMMAR_H */
