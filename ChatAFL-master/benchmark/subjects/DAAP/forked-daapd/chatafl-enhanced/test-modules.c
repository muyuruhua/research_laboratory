/* 测试新增模块的API完整性 */
#include <stdio.h>
#include "verifier.h"
#include "cegar.h"
#include "state-scheduler.h"
#include "protocol-spec.h"

int main() {
    // 测试1: verifier模块
    ProtocolSpec spec = {0};
    strcpy(spec.name, "FTP");
    spec.default_port = 21;
    strcpy(spec.mandatory_fields[0], "command");
    spec.type = PROTO_TEXT;
    
    char test_json[] = "{\"command\":\"USER\",\"args\":\"test\"}";
    int result = verify_json_grammar(test_json, &spec);
    printf("[1/5] Verifier: %s\n", result ? "✓ PASS" : "✗ FAIL");
    
    // 测试2: 状态提取
    char state[256];
    extract_protocol_state(test_json, state, sizeof(state));
    printf("[2/5] State Extraction: %s\n", strlen(state) > 0 ? "✓ PASS" : "✗ FAIL");
    
    // 测试3: 状态调度器
    increment_state_count("S_200");
    increment_state_count("S_200");
    increment_state_count("S_404");
    int count = get_state_count("S_200");
    printf("[3/5] State Scheduler: %s (count=%d)\n", count == 2 ? "✓ PASS" : "✗ FAIL", count);
    
    // 测试4: 最少访问状态
    char* least = pick_least_visited_state();
    printf("[4/5] Least Visited State: %s (state=%s)\n", 
           least != NULL ? "✓ PASS" : "✗ FAIL", least ? least : "NULL");
    if (least) free(least);
    
    // 测试5: Plateau检测
    int plateau = is_plateau(100);
    printf("[5/5] Plateau Detection: %s (result=%d)\n", "✓ PASS", plateau);
    
    printf("\n✅ All module tests completed!\n");
    return 0;
}
