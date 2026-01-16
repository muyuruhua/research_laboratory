/*
 * sut-verifier-client.h
 * 
 * Layer 3-4 Real SUT Verifier Client
 * 与Python SUT Verifier Server通信（Unix socket）
 * 
 * 集成方式：
 *   1. 编译时链接: -lsut-verifier
 *   2. 运行时启动: python3 sut-verifier.py --server --protocol FTP
 *   3. 调用: sut_verify_layer3_layer4(data, len, &result)
 */

#ifndef SUT_VERIFIER_CLIENT_H
#define SUT_VERIFIER_CLIENT_H

#include <stdbool.h>
#include <stdint.h>

/* 验证结果 */
typedef struct {
    bool sampled;           /* 是否被采样验证 */
    bool layer3_passed;     /* Layer 3: 新状态 */
    bool layer4_passed;     /* Layer 4: 新响应码 */
    bool should_keep;       /* 是否保留输入 */
    char new_state[64];     /* 新状态名称（如有） */
    char response_code[8];  /* 响应码（如有） */
    bool has_error;         /* 是否出错 */
} sut_verify_result_t;

/* 连接到SUT Verifier Server */
int sut_verifier_connect(const char* socket_path);

/* 关闭连接 */
void sut_verifier_disconnect(void);

/* Layer 3-4 验证（主函数）
 * 
 * Args:
 *   data: 待验证的输入
 *   len: 输入长度
 *   result: 输出结果
 * 
 * Returns:
 *   0 on success, -1 on error
 */
int sut_verify_layer3_layer4(const unsigned char* data, 
                              unsigned int len,
                              sut_verify_result_t* result);

/* 获取统计信息（可选） */
typedef struct {
    uint32_t total_requests;
    uint32_t sampled_tests;
    uint32_t new_states_found;
    uint32_t new_responses_found;
    uint32_t errors;
} sut_verifier_stats_t;

int sut_verifier_get_stats(sut_verifier_stats_t* stats);

#endif /* SUT_VERIFIER_CLIENT_H */
