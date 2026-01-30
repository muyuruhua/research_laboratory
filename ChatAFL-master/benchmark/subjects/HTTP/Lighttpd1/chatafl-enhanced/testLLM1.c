#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 引入 chat-llm 头文件（根据实际路径调整）
#include "chat-llm.h"


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