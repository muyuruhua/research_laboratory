/*
 * Test program for extract_protocol_commands_from_response()
 * Compile: gcc -o test_extraction test_extraction.c ChatAFL-Opt/chat-llm.c -I ChatAFL-Opt -lcurl -ljson-c -lpcre2-8
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "chat-llm.h"

// Mock alloc functions for standalone compilation
void* ck_alloc(size_t size) { return malloc(size); }
void* ck_realloc(void *ptr, size_t size) { return realloc(ptr, size); }
void ck_free(void *ptr) { free(ptr); }

int main() {
    // Test case 1: Response with code block
    const char *test1 = 
        "Certainly! The RNFR command is used in FTP sessions. Here's the modified sequence:\n\n"
        "```\n"
        "USER anonymous\n"
        "PASS ubuntu\n"
        "SYST\n"
        "HELP\n"
        "PWD\n"
        "PORT 127,0,0,1,152,193\n"
        "LIST\n"
        "STOR filename.txt\n"
        "QUIT\n"
        "```\n\n"
        "This includes the STOR command for uploading a file.";
    
    printf("=== Test 1: Code block with FTP commands ===\n");
    printf("Input:\n%s\n\n", test1);
    
    char *extracted1 = extract_protocol_commands_from_response((char*)test1);
    if (extracted1) {
        printf("Extracted:\n%s\n", extracted1);
        printf("Length: %zu bytes\n\n", strlen(extracted1));
        free(extracted1);
    } else {
        printf("ERROR: Extraction failed!\n\n");
    }
    
    // Test case 2: Mixed content with explanations
    const char *test2 = 
        "Here's a modified sequence of client requests:\n\n"
        "1. After the `LIST` command, we can add:\n"
        "```\n"
        "USER anonymous\n"
        "PASS password123\n"
        "CWD /home/user\n"
        "RETR file.txt  ; This downloads a file\n"
        "DELE oldfile.txt\n"
        "QUIT\n"
        "```\n";
    
    printf("=== Test 2: Code block with comments ===\n");
    printf("Input:\n%s\n\n", test2);
    
    char *extracted2 = extract_protocol_commands_from_response((char*)test2);
    if (extracted2) {
        printf("Extracted:\n%s\n", extracted2);
        printf("Length: %zu bytes\n\n", strlen(extracted2));
        free(extracted2);
    } else {
        printf("ERROR: Extraction failed!\n\n");
    }
    
    // Test case 3: No code block, commands scattered in text
    const char *test3 = 
        "You should add these commands:\n"
        "USER anonymous\n"
        "PASS ubuntu\n"
        "Then do some operations like:\n"
        "LIST\n"
        "RETR important_file.txt\n"
        "Finally:\n"
        "QUIT\n";
    
    printf("=== Test 3: No code block, scattered commands ===\n");
    printf("Input:\n%s\n\n", test3);
    
    char *extracted3 = extract_protocol_commands_from_response((char*)test3);
    if (extracted3) {
        printf("Extracted:\n%s\n", extracted3);
        printf("Length: %zu bytes\n\n", strlen(extracted3));
        free(extracted3);
    } else {
        printf("ERROR: Extraction failed!\n\n");
    }
    
    // Test case 4: Real LLM response (from actual test)
    const char *test4 = 
        "Certainly! The RNFR (Rename From) command is typically used in FTP sessions to specify the source file that you want to rename, while the HELP command can be used to obtain information about available commands.\r\n\r\nHere's how you can integrate the RNFR and HELP commands into the provided sequence of client requests:\r\n\r\n1. After the `LIST` command, we can add the `RNFR` command to specify a file to rename.\r\n2. Before the `QUIT` command, we can add the `HELP` command to request information.\r\n\r\nHere's the modified sequence of client requests:\r\n\r\n```\r\nUSER anonymous\r\nPASS ubuntu\r\nSYST\r\nPWD\r\nPORT 127,0,0,1,152,193\r\nLIST\r\nRNFR old_filename.txt\r\nRNTO new_filename.txt\r\nHELP\r\nQUIT\r\n```";
    
    printf("=== Test 4: Real LLM response ===\n");
    printf("Input (first 200 chars): %.200s...\n\n", test4);
    
    char *extracted4 = extract_protocol_commands_from_response((char*)test4);
    if (extracted4) {
        printf("Extracted:\n%s\n", extracted4);
        printf("Length: %zu bytes\n", strlen(extracted4));
        
        // Count commands
        int cmd_count = 0;
        char *p = extracted4;
        while (*p) {
            if (*p == '\n') cmd_count++;
            p++;
        }
        printf("Command count: %d\n\n", cmd_count);
        free(extracted4);
    } else {
        printf("ERROR: Extraction failed!\n\n");
    }
    
    return 0;
}
