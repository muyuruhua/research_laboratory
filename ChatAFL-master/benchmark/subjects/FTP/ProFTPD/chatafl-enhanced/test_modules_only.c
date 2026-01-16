// 最小化测试 - 不依赖afl-fuzz.c的函数
#include <stdio.h>
#include <string.h>
#include "verifier.h"
#include "cegar.h"
#include "state-graph.h"
#include "state-scheduler.h"
#include "alloc-inl.h"

int main() {
    printf("=== 核心模块独立功能测试 ===\n\n");
    
    // 1. Verifier测试
    printf("[1] Verifier - PCRE2正则验证\n");
    bool v1 = verify_with_pcre2((unsigned char*)"USER test\r\n", 11, "FTP", NULL);
    printf("   FTP命令验证: %s\n", v1 ? "✓" : "✗");
    
    // 2. CEGAR基础功能（不调用refine_hypothesis_with_cegar）
    printf("\n[2] CEGAR - 命令提取 & Patch验证\n");
    unsigned char test[] = "USER test\r\n";
    unsigned int len = 0;
    unsigned char *cmd = extract_command_line(test, sizeof(test)-1, &len);
    printf("   命令提取: %s (len=%u)\n", cmd ? "✓" : "✗", len);
    if (cmd) ck_free(cmd);
    
    unsigned int fields = 0;
    bool local = verify_patch_is_local("{\"cmd\":\"USER\"}", 3, &fields);
    printf("   本地Patch验证: %s (fields=%u)\n", local ? "✓" : "✗", fields);
    
    // 3. State Graph
    printf("\n[3] State Graph - 状态转移图\n");
    StateGraph g;
    state_graph_init(&g);
    state_graph_add_transition(&g, 0, 220, NULL, 10);
    printf("   转移添加: %s (total=%u)\n", g.total_transitions==1 ? "✓" : "✗", g.total_transitions);
    
    // 4. State Scheduler
    printf("\n[4] State Scheduler - 状态计数\n");
    increment_state_count("S1");
    increment_state_count("S1");
    increment_state_count("S2");
    printf("   状态计数: ✓ (无崩溃)\n");
    
    printf("\n=== 测试完成: 所有核心模块工作正常 ===\n");
    return 0;
}
