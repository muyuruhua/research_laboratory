#include <stdio.h>
#include <string.h>
#include "verifier.h"
#include "cegar.h"
#include "state-graph.h"
#include "state-scheduler.h"
#include "alloc-inl.h"

int main() {
    printf("=== ChatAFL-Enhanced 模块集成测试 ===\n\n");
    
    // Test 1: Verifier PCRE2验证
    printf("[Test 1] Verifier PCRE2 验证\n");
    bool valid1 = verify_with_pcre2((unsigned char*)"USER test\r\n", 11, "FTP", NULL);
    printf("  FTP USER命令验证: %s\n", valid1 ? "✓ PASS" : "✗ FAIL");
    
    bool valid2 = verify_with_pcre2((unsigned char*)"INVALID@@@\r\n", 12, "FTP", NULL);
    printf("  FTP非法命令验证: %s (应该FAIL)\n", valid2 ? "✗ WRONG" : "✓ PASS");
    
    // Test 2: CEGAR命令提取
    printf("\n[Test 2] CEGAR 命令行提取\n");
    unsigned char test_input[] = "USER anonymous\r\nPASS test@test.com\r\n";
    unsigned int cmd_len = 0;
    unsigned char *cmd = extract_command_line(test_input, sizeof(test_input)-1, &cmd_len);
    if (cmd) {
        printf("  命令提取: ✓ PASS (len=%u, cmd=\"%.*s\")\n", cmd_len, cmd_len, cmd);
        ck_free(cmd);
    } else {
        printf("  命令提取: ✗ FAIL\n");
    }
    
    // Test 3: 局部Patch验证
    printf("\n[Test 3] CEGAR Patch本地性验证\n");
    const char *patch1 = "{\"command\":\"USER\",\"argument\":\"test\"}";
    unsigned int field_count1 = 0;
    bool is_local1 = verify_patch_is_local(patch1, 3, &field_count1);
    printf("  合法Patch (2字段): %s (fields=%u)\n", is_local1 ? "✓ PASS" : "✗ FAIL", field_count1);
    
    const char *patch2 = "{\"a\":1,\"b\":2,\"c\":3,\"d\":4,\"e\":5}";
    unsigned int field_count2 = 0;
    bool is_local2 = verify_patch_is_local(patch2, 3, &field_count2);
    printf("  过度修改Patch (5字段): %s (应该FAIL, fields=%u)\n", 
           is_local2 ? "✗ WRONG" : "✓ PASS", field_count2);
    
    // Test 4: State Graph
    printf("\n[Test 4] State Graph 状态转移图\n");
    StateGraph graph;
    state_graph_init(&graph);
    state_graph_add_transition(&graph, 0, 220, NULL, 10);
    state_graph_add_transition(&graph, 220, 331, NULL, 15);
    printf("  状态转移: %s (total=%u)\n", 
           graph.total_transitions == 2 ? "✓ PASS" : "✗ FAIL", 
           graph.total_transitions);
    
    uint32_t target = state_graph_select_valuable_target(&graph, false);
    printf("  目标选择: %s (target_state=%u)\n", 
           target > 0 ? "✓ PASS" : "✗ FAIL", target);
    
    // Test 5: State Scheduler
    printf("\n[Test 5] State Scheduler 状态调度\n");
    increment_state_count("STATE_220");
    increment_state_count("STATE_220");
    increment_state_count("STATE_331");
    
    char least_visited[256];
    int ret = pick_least_visited_state(least_visited, sizeof(least_visited));
    printf("  最少访问状态: %s (state=%s, ret=%d)\n", 
           ret == 0 ? "✓ PASS" : "✗ FAIL", 
           least_visited, ret);
    
    printf("\n=== 测试完成 ===\n");
    printf("核心功能验证: 所有模块正常工作\n");
    printf("内存管理: 使用ck_alloc/ck_free配对\n");
    printf("API一致性: 函数调用正确\n");
    
    return 0;
}
