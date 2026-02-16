#!/bin/bash
# Quick test to verify control character handling

export OPENAI_API_KEY=$(grep -o 'sk-[^"]*' run_dev.sh | head -1)

cd ChatAFL-Opt

# Create test data with control characters
echo -e "USER\x01test\x02data\x03\r\nPASS secret\r\n" > /tmp/test_seq.txt

# Build a minimal test program
cat > /tmp/test_enrich.c << 'EOFC'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "chat-llm.h"
#include "khash.h"

KHASH_SET_INIT_STR(strSet)

int main() {
    // Read test sequence
    FILE *f = fopen("/tmp/test_seq.txt", "rb");
    if (!f) {
        fprintf(stderr, "Failed to open test file\n");
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *seq = malloc(len + 1);
    fread(seq, 1, len, f);
    seq[len] = '\0';
    fclose(f);
    
    // Create missing types
    khash_t(strSet) *missing = kh_init(strSet);
    int ret;
    kh_put(strSet, missing, strdup("STOR"), &ret);
    kh_put(strSet, missing, strdup("RETR"), &ret);
    
    printf("Testing enrichment with control characters...\n");
    printf("Sequence length: %zu bytes\n", len);
    
    // Test enrichment
    char *result = enrich_sequence(seq, missing);
    
    if (result) {
        printf("SUCCESS: Enrichment completed without error\n");
        printf("Result: %s\n", result);
        free(result);
    } else {
        printf("FAILED: Enrichment returned NULL\n");
    }
    
    // Cleanup
    for (khiter_t k = kh_begin(missing); k != kh_end(missing); ++k) {
        if (kh_exist(missing, k)) free((void*)kh_key(missing, k));
    }
    kh_destroy(strSet, missing);
    free(seq);
    
    return result ? 0 : 1;
}
EOFC

# Compile test
gcc -g -o /tmp/test_enrich /tmp/test_enrich.c chat-llm.c -I. -lcurl -ljson-c -lpcre2-8 2>&1 | head -20

# Run test if compilation succeeded
if [ -f /tmp/test_enrich ]; then
    echo "Running control character test..."
    /tmp/test_enrich
    echo "Test exit code: $?"
else
    echo "Compilation failed"
fi
