#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 直接引入官方头文件，替代手动声明，保证函数签名完全一致
// 路径说明：假设当前目录是 testLLM.c 所在目录，需根据实际目录层级调整路径
#include "chat-llm.h"

int main() {
    // 1. 定义测试用的LLM调用参数（适配ChatAFL的协议模糊测试场景）
    const char* test_prompt = "分析以下FTP协议报文的结构，生成5个符合协议规范的变异版本：USER anonymous\r\nPASS test@example.com\r\n";
    const char* llm_model = "gpt-4o-mini";  // ChatAFL默认使用的模型名
    int max_tokens = 1024;                    // 适配协议报文的生成长度

    // 2. 打印调用信息，便于调试
    printf("===== 调用ChatAFL的chat_with_llm函数 =====\n");
    printf("Prompt内容：\n%s\n", test_prompt);
    printf("模型名：%s | 最大Token数：%d\n\n", llm_model, max_tokens);

    // 3. 核心调用：chat_with_llm函数
    char* llm_response = chat_with_llm(test_prompt, llm_model, max_tokens, 0.7);

    // 4. 结果校验与处理（ChatAFL中函数返回NULL表示调用失败）
    if (llm_response == NULL) {
        fprintf(stderr, "错误：chat_with_llm调用失败，返回NULL！\n");
        fprintf(stderr, "可能原因：网络问题/API密钥未配置/模型名错误\n");
        return EXIT_FAILURE;
    }

    // 5. 输出LLM返回的结果
    printf("===== LLM返回结果 =====\n");
    printf("%s\n", llm_response);

    // 6. 释放内存（ChatAFL的chat_with_llm返回动态分配的字符串，必须释放）
    free(llm_response);
    llm_response = NULL;

    printf("\n调用完成，内存已释放！\n");
    return EXIT_SUCCESS;
}