#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 引入 chat-llm 头文件（根据实际路径调整）
#include "chat-llm.h"

// 编译时需要链接的库：-lcurl -ljson-c -lpcre2-8
// 编译命令示例：
// gcc testLLM1.c ChatAFL-master/ChatAFL/chat-llm.c -o testLLM1 -lcurl -ljson-c -lpcre2-8
//gcc -o testLLM1 testLLM1.c chat-llm.c -lcurl -ljson-c -lpcre2-8 -Wall -g && ./testLLM1

// int main(int argc, char *argv[]) {
//     // 1. 定义测试用的 Prompt（支持两种模式：instruct / chat）
//     // 模式1：instruct 模式（对应 gpt-3.5-turbo-instruct）
//     char *instruct_prompt = "请解释什么是协议模糊测试？";
    
//     // 模式2：chat 模式（对应 gpt-3.5-turbo，需符合 OpenAI Chat 消息格式）
//     char *chat_prompt = "[{\"role\":\"user\",\"content\":\"请解释什么是协议模糊测试？\"}]";

//     // 2. 调用 chat_with_llm 函数
//     // 参数说明：
//     // - prompt: 提示词
//     // - model: 模型类型（"instruct" 或其他值表示 chat 模式）
//     // - tries: 重试次数
//     // - temperature: 生成温度（0.0~1.0，值越高越随机）
//     char *instruct_result = chat_with_llm(instruct_prompt, "gpt-4o-mini", 3, 0.7f);
//     char *chat_result = chat_with_llm(chat_prompt, "gpt-4o-mini", 3, 0.7f);

//     // 3. 输出结果
//     // printf("===== Instruct 模式响应 =====\n");
//     // if (instruct_result) {
//     //     printf("%s\n", instruct_result);
//     //     free(instruct_result); // 释放返回值内存
//     // } else {
//     //     printf("调用失败（instruct 模式）\n");
//     // }

//     printf("\n===== Chat 模式响应 =====\n");
//     if (chat_result) {
//         printf("%s\n", chat_result);
//         free(chat_result); // 释放返回值内存
//     } else {
//         printf("调用失败（chat 模式）\n");
//     }

//     return 0;
// }

// 示例使用
int main() {
    // 设置环境变量（在实际使用中，应该在shell中设置）
    // setenv("KEY", "sk-ILojcXJTq7HKk5RJ232858Aa05C24128830bDc12610d3c0d", 1);
    
    char* prompt = "You are an expert in networking protocols. For the RTSP protocol, "
                  "the typical sequence is: DESCRIBE, SETUP, PLAY. Please explain where "
                  "SET_PARAMETER and TEARDOWN should be placed in this sequence.";
    
    printf("Sending request to LLM API...\n");
    
    // 调用封装后的函数
    char* response = chat_with_llm(prompt, "gpt-4o-mini", 3, 0.7);
    
    if (response) {
        printf("\n=== LLM Response ===\n");
        printf("%s\n", response);
        free(response);
    }
    
    return 0;
}