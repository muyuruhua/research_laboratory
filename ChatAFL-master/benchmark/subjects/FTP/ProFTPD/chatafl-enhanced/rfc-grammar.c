/*
 * rfc-grammar.c
 * 
 * RFC Grammar加载器实现
 */

#include "rfc-grammar.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 预定义Grammar路径 */
#define RFC_GRAMMAR_DIR "rfc-grammars"

rfc_grammar_t* load_rfc_grammar(const char* protocol) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "%s/%s_grammar.json", 
             RFC_GRAMMAR_DIR, protocol);
    
    /* 尝试读取JSON文件 */
    FILE* fp = fopen(filepath, "r");
    if (!fp) {
        /* 降级：尝试从环境变量或备用路径 */
        char* alt_path = getenv("RFC_GRAMMAR_PATH");
        if (alt_path) {
            snprintf(filepath, sizeof(filepath), "%s/%s_grammar.json", 
                     alt_path, protocol);
            fp = fopen(filepath, "r");
        }
        
        if (!fp) {
            fprintf(stderr, "[WARN] RFC Grammar not found for %s, using inline fallback\n", 
                    protocol);
            return NULL;  /* 调用者应降级到hardcoded examples */
        }
    }
    
    /* 读取文件内容 */
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char* content = malloc(fsize + 1);
    if (!content) {
        fclose(fp);
        return NULL;
    }
    
    /* 安全读取文件内容 */
    size_t bytes_read = fread(content, 1, fsize, fp);
    fclose(fp);
    
    if (bytes_read != fsize) {
        free(content);
        fprintf(stderr, "[ERROR] Failed to read complete file %s\n", filepath);
        return NULL;
    }
    
    content[fsize] = '\0';
    
    /* 解析JSON */
    struct json_object* root = json_tokener_parse(content);
    free(content);
    
    if (!root) {
        fprintf(stderr, "[ERROR] Invalid JSON in %s\n", filepath);
        return NULL;
    }
    
    /* 分配Grammar结构 */
    rfc_grammar_t* grammar = calloc(1, sizeof(rfc_grammar_t));
    if (!grammar) {
        json_object_put(root);
        return NULL;
    }
    
    /* 提取字段 */
    struct json_object* tmp;
    
    if (json_object_object_get_ex(root, "protocol", &tmp)) {
        strncpy(grammar->protocol, json_object_get_string(tmp), 
                sizeof(grammar->protocol) - 1);
    }
    
    if (json_object_object_get_ex(root, "rfc", &tmp)) {
        strncpy(grammar->rfc_number, json_object_get_string(tmp), 
                sizeof(grammar->rfc_number) - 1);
    }
    
    if (json_object_object_get_ex(root, "commands", &tmp)) {
        grammar->commands = tmp;  /* 直接引用，不增加引用计数 */
    }
    
    if (json_object_object_get_ex(root, "responses", &tmp)) {
        grammar->responses = tmp;  /* 直接引用，不增加引用计数 */
    }
    
    if (json_object_object_get_ex(root, "state_machine", &tmp)) {
        grammar->state_machine = tmp;  /* 直接引用，不增加引用计数 */
    }
    
    if (json_object_object_get_ex(root, "constraints", &tmp)) {
        grammar->constraints = tmp;  /* 直接引用，不增加引用计数 */
    }
    
    grammar->raw_json = root;  /* 保存root用于后续释放 */
    
    fprintf(stderr, "[OK] Loaded RFC Grammar for %s (%s)\n", 
            grammar->protocol, grammar->rfc_number);
    
    return grammar;
}

void free_rfc_grammar(rfc_grammar_t* grammar) {
    if (!grammar) return;
    
    /* 只释放原始JSON对象 - 子对象会自动释放 */
    if (grammar->raw_json) {
        json_object_put(grammar->raw_json);
    }
    
    /* 清空指针防止野指针访问 */
    grammar->commands = NULL;
    grammar->responses = NULL;
    grammar->state_machine = NULL;
    grammar->constraints = NULL;
    grammar->raw_json = NULL;
    
    free(grammar);
}

int get_grammar_commands(rfc_grammar_t* grammar, char** commands, int max_count) {
    if (!grammar || !grammar->commands) return 0;
    
    int count = 0;
    json_object_object_foreach(grammar->commands, key, val) {
        if (count >= max_count) break;
        commands[count++] = strdup(key);
    }
    
    return count;
}

struct json_object* get_command_template(rfc_grammar_t* grammar, const char* command) {
    if (!grammar || !grammar->commands) return NULL;
    
    struct json_object* cmd_obj = NULL;
    if (json_object_object_get_ex(grammar->commands, command, &cmd_obj)) {
        return cmd_obj;
    }
    
    return NULL;
}

int get_next_commands_for_state(rfc_grammar_t* grammar, 
                                const char* state,
                                char** next_commands,
                                int max_count) {
    if (!grammar || !grammar->state_machine) return 0;
    
    struct json_object* state_obj = NULL;
    if (!json_object_object_get_ex(grammar->state_machine, state, &state_obj)) {
        return 0;
    }
    
    int count = 0;
    size_t array_len = json_object_array_length(state_obj);
    
    for (size_t i = 0; i < array_len && count < max_count; i++) {
        struct json_object* cmd = json_object_array_get_idx(state_obj, i);
        next_commands[count++] = strdup(json_object_get_string(cmd));
    }
    
    return count;
}

int grammar_to_prompt_examples(rfc_grammar_t* grammar, 
                               char* example_buffer, 
                               size_t buffer_size) {
    if (!grammar || !grammar->commands) return 0;
    
    size_t written = 0;
    
    /* 格式化为chat-llm.c兼容的prompt examples */
    written += snprintf(example_buffer + written, buffer_size - written,
                       "For the %s protocol (%s):\n",
                       grammar->protocol, grammar->rfc_number);
    
    /* 遍历所有命令 */
    json_object_object_foreach(grammar->commands, key, val) {
        if (written >= buffer_size - 200) break;
        
        struct json_object* template_obj = NULL;
        if (json_object_object_get_ex(val, "template", &template_obj)) {
            written += snprintf(example_buffer + written, buffer_size - written,
                              "  %s template: ", key);
            
            if (json_object_is_type(template_obj, json_type_array)) {
                /* 数组形式：["CMD <<VALUE>>\\r\\n"] */
                size_t len = json_object_array_length(template_obj);
                for (size_t i = 0; i < len; i++) {
                    struct json_object* elem = json_object_array_get_idx(template_obj, i);
                    written += snprintf(example_buffer + written, buffer_size - written,
                                      "%s", json_object_get_string(elem));
                }
            } else {
                /* 字符串形式 */
                written += snprintf(example_buffer + written, buffer_size - written,
                                  "%s", json_object_get_string(template_obj));
            }
            
            written += snprintf(example_buffer + written, buffer_size - written, "\n");
        }
    }
    
    return written;
}
