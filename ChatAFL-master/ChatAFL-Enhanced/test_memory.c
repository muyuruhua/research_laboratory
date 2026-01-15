#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "alloc-inl.h"
#include "chat-llm.h"

int main() {
    // Test 1: extract_stalled_message
    char *test_input = "Initial response\n\nExpected output message";
    char *extracted = extract_stalled_message(test_input, strlen(test_input));
    printf("Extracted: %s\n", extracted ? extracted : "NULL");
    
    // Should use ck_free for the result from extract_stalled_message
    if (extracted) ck_free(extracted);
    
    // Test 2: format_request_message (takes ownership of input)
    char *test_message = ck_alloc(50);
    strcpy(test_message, "GET /test HTTP/1.1");
    char *formatted = format_request_message(test_message);  // This frees test_message internally
    printf("Formatted: %s\n", formatted ? formatted : "NULL");
    
    // Should use ck_free for the result from format_request_message
    if (formatted) ck_free(formatted);
    
    printf("Memory test completed successfully\n");
    return 0;
}
