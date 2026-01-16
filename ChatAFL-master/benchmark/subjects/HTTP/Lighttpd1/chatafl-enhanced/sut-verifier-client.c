/*
 * sut-verifier-client.c
 * 
 * Layer 3-4 Real SUT Verifier Client Implementation
 */

#include "sut-verifier-client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <arpa/inet.h>    /* 网络字节序转换 */
#include <pthread.h>      /* 线程安全 */
#include <json-c/json.h>

/* 线程安全的全局socket连接 */
static int g_sut_socket = -1;
static bool g_sut_connected = false;
static pthread_mutex_t g_sut_mutex = PTHREAD_MUTEX_INITIALIZER;

int sut_verifier_connect(const char* socket_path) {
    pthread_mutex_lock(&g_sut_mutex);
    
    if (g_sut_connected) {
        pthread_mutex_unlock(&g_sut_mutex);
        return 0;  /* 已连接 */
    }
    
    /* 创建Unix socket */
    g_sut_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_sut_socket < 0) {
        pthread_mutex_unlock(&g_sut_mutex);
        return -1;
    }
    
    /* 连接到server */
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
    
    if (connect(g_sut_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        /* Server可能未启动，静默失败（降级到启发式验证） */
        close(g_sut_socket);
        g_sut_socket = -1;
        pthread_mutex_unlock(&g_sut_mutex);
        return -1;
    }
    
    g_sut_connected = true;
    pthread_mutex_unlock(&g_sut_mutex);
    return 0;
}

void sut_verifier_disconnect(void) {
    if (g_sut_connected && g_sut_socket >= 0) {
        close(g_sut_socket);
        g_sut_socket = -1;
        g_sut_connected = false;
    }
}

int sut_verify_layer3_layer4(const unsigned char* data, 
                              unsigned int len,
                              sut_verify_result_t* result) {
    /* 初始化结果 */
    memset(result, 0, sizeof(sut_verify_result_t));
    
    pthread_mutex_lock(&g_sut_mutex);
    
    /* 如果未连接，返回启发式结果（默认保留） */
    if (!g_sut_connected || g_sut_socket < 0) {
        result->sampled = false;
        result->should_keep = true;  /* 启发式：保留 */
        pthread_mutex_unlock(&g_sut_mutex);
        return 0;  /* 不算错误 */
    }
    
    /* 发送请求: <length:4bytes><data> 使用网络字节序 */
    uint32_t length_net = htonl(len);  /* 转换为网络字节序 */
    if (send(g_sut_socket, &length_net, 4, 0) != 4) {
        result->has_error = true;
        pthread_mutex_unlock(&g_sut_mutex);
        return -1;
    }
    
    if (send(g_sut_socket, data, len, 0) != (ssize_t)len) {
        result->has_error = true;
        pthread_mutex_unlock(&g_sut_mutex);
        return -1;
    }
    
    /* 接收响应: <length:4bytes><json> 使用网络字节序 */
    uint32_t response_len_net;
    if (recv(g_sut_socket, &response_len_net, 4, MSG_WAITALL) != 4) {
        result->has_error = true;
        pthread_mutex_unlock(&g_sut_mutex);
        return -1;
    }
    
    uint32_t response_len = ntohl(response_len_net);  /* 转换为主机字节序 */
    
    if (response_len > 65536) {  /* 安全检查 */
        result->has_error = true;
        pthread_mutex_unlock(&g_sut_mutex);
        return -1;
    }
    
    char* json_buf = malloc(response_len + 1);
    if (!json_buf) {
        result->has_error = true;
        pthread_mutex_unlock(&g_sut_mutex);
        return -1;
    }
    
    if (recv(g_sut_socket, json_buf, response_len, MSG_WAITALL) != (ssize_t)response_len) {
        free(json_buf);
        result->has_error = true;
        pthread_mutex_unlock(&g_sut_mutex);
        return -1;
    }
    json_buf[response_len] = '\0';
    
    /* 解析JSON响应 */
    struct json_object* root = json_tokener_parse(json_buf);
    free(json_buf);
    
    if (!root) {
        result->has_error = true;
        pthread_mutex_unlock(&g_sut_mutex);
        return -1;
    }
    
    /* 提取字段 */
    struct json_object* tmp;
    
    if (json_object_object_get_ex(root, "sampled", &tmp)) {
        result->sampled = json_object_get_boolean(tmp);
    }
    
    if (json_object_object_get_ex(root, "layer3_passed", &tmp)) {
        result->layer3_passed = json_object_get_boolean(tmp);
    }
    
    if (json_object_object_get_ex(root, "layer4_passed", &tmp)) {
        result->layer4_passed = json_object_get_boolean(tmp);
    }
    
    if (json_object_object_get_ex(root, "should_keep", &tmp)) {
        result->should_keep = json_object_get_boolean(tmp);
    }
    
    if (json_object_object_get_ex(root, "new_state", &tmp)) {
        const char* state = json_object_get_string(tmp);
        if (state) {
            strncpy(result->new_state, state, sizeof(result->new_state) - 1);
        }
    }
    
    if (json_object_object_get_ex(root, "response_code", &tmp)) {
        const char* code = json_object_get_string(tmp);
        if (code) {
            strncpy(result->response_code, code, sizeof(result->response_code) - 1);
        }
    }
    
    json_object_put(root);
    pthread_mutex_unlock(&g_sut_mutex);
    return 0;
}

int sut_verifier_get_stats(sut_verifier_stats_t* stats) {
    /* TODO: 实现统计查询（需要server端支持stats命令） */
    memset(stats, 0, sizeof(sut_verifier_stats_t));
    return 0;
}
