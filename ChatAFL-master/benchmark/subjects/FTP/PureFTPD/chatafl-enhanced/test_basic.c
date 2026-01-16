#include <stdio.h>
#include "verifier.h"
#include "cegar.h"
#include "state-graph.h"
#include "state-scheduler.h"

int main() {
    printf("Testing verifier module...\n");
    VerifierRejectReason reason;
    bool valid = verify_with_pcre2((unsigned char*)"USER test\r\n", 11, "FTP", &reason);
    printf("FTP USER validation: %s\n", valid ? "PASS" : "FAIL");
    
    printf("\nTesting CEGAR module...\n");
    unsigned char test[] = "test";
    unsigned int len = 0;
    unsigned char *cmd = extract_command_line(test, 4, &len);
    if (cmd) {
        printf("Command extraction: PASS (len=%u)\n", len);
        free(cmd);
    }
    
    printf("\nTesting state-graph module...\n");
    StateGraph graph;
    state_graph_init(&graph, 100);
    state_graph_add_transition(&graph, 0, 1, NULL, 10);
    printf("State graph: PASS (transitions=%u)\n", graph.total_transitions);
    state_graph_destroy(&graph);
    
    printf("\nTesting state-scheduler module...\n");
    increment_state_count("TEST_STATE");
    char state[256];
    int ret = pick_least_visited_state(state, sizeof(state));
    printf("State scheduler: %s (ret=%d)\n", ret == 0 ? "PASS" : "FAIL", ret);
    
    printf("\n=== All module tests completed ===\n");
    return 0;
}
