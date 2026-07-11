#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include "chat-llm.h"
#include <fcntl.h>

#include "hypothesis-adapter.h"
#include "alloc-inl.h"
#include "hash.h"

// Escape regex-special chars in a basic way
static char *escape_for_regex(const char *s) {
    size_t len = strlen(s);
    // worst case every char escaped => allocate 2x
    char *out = ck_alloc(len * 2 + 1);
    char *p = out;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c == '.' || c == '^' || c == '$' || c == '*' || c == '+' || c == '?' || c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}' || c == '|' || c == '\\') {
            *p++ = '\\';
        }
        *p++ = c;
    }
    *p = '\0';
    return out;
}

int integrate_hypotheses_into_protocol_patterns(hypothesis_context_t *ctx,
                                                klist_t(rang) *protocol_patterns,
                                                khash_t(strSet) *message_types_set,
                                                const char *out_dir) {
    if (!ctx || !protocol_patterns || !message_types_set) return 0;

    int integrated = 0;
    for (size_t i = 0; i < ctx->hypothesis_count; i++) {
        grammar_hypothesis_t *hyp = ctx->hypotheses[i];
        if (!hyp || !hyp->message_type) continue;

        // Build a simple header regex that matches the message_type at start
        char *escaped = escape_for_regex(hyp->message_type);
        char header_pattern[512];
        snprintf(header_pattern, sizeof(header_pattern), "^%s(?:[ \t].*)?\\r?\\n", escaped);
        ck_free(escaped);

        // Build a permissive fields pattern that captures the rest
        char fields_pattern[128];
        snprintf(fields_pattern, sizeof(fields_pattern), "(?s)(.*)");

        int errornumber;
        size_t erroroffset;

        pcre2_code *p_header = pcre2_compile((PCRE2_SPTR)header_pattern, PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
        if (!p_header) {
            fprintf(stderr, "[hyp-adapter] Failed to compile header regex for %s (err %d offset %zu)\n", hyp->message_type, errornumber, erroroffset);
            continue;
        }
        pcre2_jit_compile(p_header, PCRE2_JIT_COMPLETE);

        pcre2_code *p_fields = pcre2_compile((PCRE2_SPTR)fields_pattern, PCRE2_ZERO_TERMINATED, PCRE2_DOTALL, &errornumber, &erroroffset, NULL);
        if (!p_fields) {
            fprintf(stderr, "[hyp-adapter] Failed to compile fields regex for %s (err %d offset %zu)\n", hyp->message_type, errornumber, erroroffset);
            pcre2_code_free(p_header);
            continue;
        }
        pcre2_jit_compile(p_fields, PCRE2_JIT_COMPLETE);

        pcre2_code **patterns = ck_alloc(2 * sizeof(pcre2_code *));
        patterns[0] = p_header;
        patterns[1] = p_fields;

        int discard;
        // message_type might be non-unique; ensure insert works
        kh_put(strSet, message_types_set, hyp->message_type, &discard);
        *kl_pushp(rang, protocol_patterns) = patterns;

        // Debug output
        fprintf(stderr, "[hyp-adapter] Integrated hypothesis '%s' as pattern (index %zu)\n", hyp->message_type, i);

        // Optionally write pattern to out_dir for inspection
        if (out_dir) {
            char *path = alloc_printf("%s/protocol-grammars/hyp-pattern-%zu", out_dir, i);
            int fd = open(path, O_WRONLY | O_CREAT, 0600);
            if (fd != -1) {
                ck_write(fd, header_pattern, strlen(header_pattern), path);
                ck_write(fd, "\n", 1, path);
                ck_write(fd, fields_pattern, strlen(fields_pattern), path);
                close(fd);
            }
            ck_free(path);
        }

        integrated++;
    }

    fprintf(stderr, "[hyp-adapter] Total integrated hypotheses: %d\n", integrated);
    return integrated;
}
