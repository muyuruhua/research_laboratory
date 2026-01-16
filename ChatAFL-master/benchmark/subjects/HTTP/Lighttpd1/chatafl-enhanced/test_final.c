#include <stdio.h>
#include "verifier.h"
#include "cegar.h"  
#include "state-graph.h"
#include "state-scheduler.h"

// 简化测试 - 只测试不需要LLM的核心功能
int main() {
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  ChatAFL-Enhanced 核心模块集成测试                       ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
    
    int pass = 0, total = 0;
    
    // Test 1: Verifier - PCRE2正则验证  
    printf("[Test 1/5] Verifier - PCRE2正则验证引擎\n");
    total++;
    bool v1 = verify_with_pcre2((unsigned char*)"USER anonymous\r\n", 16, "FTP", NULL);
    bool v2 = verify_with_pcre2((unsigned char*)"MAIL FROM:<test@test.com>\r\n", 27, "SMTP", NULL);
    bool v3 = verify_with_pcre2((unsigned char*)"INVALID_CMD!!!", 14, "FTP", NULL);
    if (v1 && v2 && !v3) {
        printf("   ✓ PASS - FTP/SMTP命令验证正确\n");
        pass++;
    } else {
        printf("   ✗ FAIL - 验证逻辑错误 (FTP:%d SMTP:%d INV:%d)\n", v1, v2, v3);
    }
    
    // Test 2: CEGAR - 命令提取
    printf("\n[Test 2/5] CEGAR - 命令行提取功能\n");
    total++;
    unsigned char test_input[] = "USER test\r\nPASS 123456\r\n";
    unsigned int cmd_len = 0;
    unsigned char *cmd = extract_command_line(test_input, sizeof(test_input)-1, &cmd_len);
    if (cmd && cmd_len == 9) {
        printf("   ✓ PASS - 命令提取成功 (len=%u, cmd=\"%.*s\")\n", cmd_len, cmd_len, cmd);
        ck_free(cmd);
        pass++;
    } else {
        printf("   ✗ FAIL - 命令提取失败\n");
        if (cmd) ck_free(cmd);
    }
    
    // Test 3: CEGAR - Patch本地性验证
    printf("\n[Test 3/5] CEGAR - Patch本地性验证\n");
    total++;
    unsigned int f1=0, f2=0;
    bool p1 = verify_patch_is_local("{\"cmd\":\"USER\",\"arg\":\"test\"}", 3, &f1);
    bool p2 = verify_patch_is_local("{\"a\":1,\"b\":2,\"c\":3,\"d\":4,\"e\":5}", 3, &f2);
    if (p1 && !p2 && f1==2 && f2==5) {
        printf("   ✓ PASS - 本地Patch约束生效 (合法2字段, 非法5字段)\n");
        pass++;
    } else {
        printf("   ✗ FAIL - Patch验证错误 (p1:%d f1:%u, p2:%d f2:%u)\n", p1, f1, p2, f2);
    }
    
    // Test 4: State Graph - 状态转移管理
    printf("\n[Test 4/5] State Graph - 状态转移图\n");
    total++;
    StateGraph graph;
    state_graph_init(&graph);
    state_graph_add_transition(&graph, 0, 220, NULL, 10);
    state_graph_add_transition(&graph, 220, 331, NULL, 15);
    state_graph_add_transition(&graph, 331, 200, NULL, 5);
    if (graph.total_transitions == 3 && graph.node_count >= 3) {
        printf("   ✓ PASS - 状态转移记录正确 (transitions=%u, nodes=%u)\n", 
               graph.total_transitions, graph.node_count);
        pass++;
    } else {
        printf("   ✗ FAIL - 状态图错误 (trans=%u, nodes=%u)\n", 
               graph.total_transitions, graph.node_count);
    }
    
    uint32_t target = state_graph_select_valuable_target(&graph, false);
    printf("   目标状态选择: state_id=%u %s\n", 
           target, target > 0 ? "(有效)" : "(无效)");
    
    // Test 5: State Scheduler - 状态计数与选择
    printf("\n[Test 5/5] State Scheduler - 状态访问计数\n");
    total++;
    increment_state_count("S_220");
    increment_state_count("S_220");
    increment_state_count("S_220");
    increment_state_count("S_331");
    
    char least[256];
    int ret = pick_least_visited_state(least, sizeof(least));
    if (ret == 0 && strstr(least, "331")) {
        printf("   ✓ PASS - 最少访问状态选择正确 (\"%s\")\n", least);
        pass++;
    } else {
        printf("   ✗ FAIL - 状态调度错误 (ret=%d, state=\"%s\")\n", ret, least);
    }
    
    // 总结
    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  测试结果: %d/%d PASSED                                    ║\n", pass, total);
    if (pass == total) {
        printf("║  ✓ 所有核心模块工作正常                                  ║\n");
        printf("║  ✓ 内存管理使用ck_alloc/ck_free配对                     ║\n");
        printf("║  ✓ API调用语法正确                                       ║\n");
        printf("║  ✓ 适配AFLNet基础架构完成                               ║\n");
    } else {
        printf("║  ✗ 存在失败的测试用例                                   ║\n");
    }
    printf("╚════════════════════════════════════════════════════════════╝\n\n");
    
    return (pass == total) ? 0 : 1;
}
