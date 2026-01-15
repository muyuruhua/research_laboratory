#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcre2.h>
#include "alloc-inl.h"

char *extract_stalled_message(char *message, size_t message_len)
{
    int errornumber;
    size_t erroroffset;
    pcre2_code *extracter = pcre2_compile("\\r?\\n?.*?\\r?\\n", PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(extracter, NULL);
    int rc = pcre2_match(extracter, message, message_len, 0, 0, match_data, NULL);
    char *res = NULL;
    if (rc >= 0) {
        size_t *ovector = pcre2_get_ovector_pointer(match_data);
        size_t len = strlen(message + ovector[1]);
        res = ck_alloc(len + 1);
        strcpy(res, message + ovector[1]);
    }
    pcre2_match_data_free(match_data);
    pcre2_code_free(extracter);
    return res;
}

char *format_request_message(char *message) {
    int message_len = strlen(message);
    char *res = ck_alloc(message_len + 10);
    strcpy(res, message);
    strcat(res, "\r\n\r\n");
    free(message); // Free the input
    return res;
}

int main() {
    // Test extract_stalled_message 
    char *test_input = "Initial response\n\nExpected output message";
    char *extracted = extract_stalled_message(test_input, strlen(test_input));
    printf("Extracted: %s\n", extracted ? extracted : "NULL");
    if (extracted) ck_free(extracted); // Should use ck_free
    
    // Test format_request_message
    char *test_message = ck_alloc(50);
    strcpy(test_message, "GET /test HTTP/1.1");
    char *formatted = format_request_message(test_message);  // This frees test_message internally
    printf("Formatted: %s\n", formatted ? formatted : "NULL");
    if (formatted) ck_free(formatted); // Should use ck_free
    
    printf("Memory test passed!\n");
    return 0;
}
