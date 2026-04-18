/*
 * ChatAFL-Opt: Grammar Hypothesis Implementation
 * ==============================================
 * Implementation of hypothesis-driven grammar learning with validation loop
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  // For strcasestr
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>

#include "grammar-hypothesis.h"
#include "chat-llm.h"
#include "rfc-knowledge.h"
#include "alloc-inl.h"

#define MAX_HYPOTHESIS_PROMPT 65536  // 64KB for large RFC content
#define MAX_RFC_CHARS 50000             // RFC extraction limit - increased for better context
#define SAFE_RFC_LIMIT 50000            // Hard limit to prevent heap corruption
#define MAX_PCAP_SAMPLES 20             // Maximum PCAP samples to include
#define MAX_REFINEMENT_COUNTEREXAMPLES 10
#define FITNESS_THRESHOLD 0.7

/* ============================================
 * Initialization Functions
 * ============================================ */

hypothesis_context_t* init_hypothesis_context(
    const char *protocol_name,
    const char *rfc_text,
    char **pcap_samples,
    size_t pcap_count
) {
    // Defensive: Validate critical parameters
    if (!protocol_name) {
        fprintf(stderr, "[!] init_hypothesis_context: protocol_name is NULL\n");
        return NULL;
    }
    
    hypothesis_context_t *ctx = (hypothesis_context_t*)ck_alloc(sizeof(hypothesis_context_t));
    memset(ctx, 0, sizeof(hypothesis_context_t));  // Initialize all fields to 0/NULL
    
    ctx->protocol_name = (char*)ck_strdup((u8*)protocol_name);
    
    // RFC Knowledge Enhancement: Auto-fetch if not provided
    if (rfc_text) {
        size_t rfc_len = strlen(rfc_text);
        fprintf(stderr, "[DEBUG] Provided RFC text length: %zu bytes\n", rfc_len);
        
        // CRITICAL: Limit RFC size to prevent AFL allocator heap corruption
        if (rfc_len > SAFE_RFC_LIMIT) {
            fprintf(stderr, "[!] WARNING: RFC text too large (%zu bytes), truncating to %d\n", 
                    rfc_len, SAFE_RFC_LIMIT);
            char *truncated = (char*)ck_alloc(SAFE_RFC_LIMIT + 1);
            memcpy(truncated, rfc_text, SAFE_RFC_LIMIT);
            truncated[SAFE_RFC_LIMIT] = '\0';
            ctx->rfc_text = truncated;
        } else {
            ctx->rfc_text = (char*)ck_strdup((u8*)rfc_text);
        }
    } else {
        // Attempt to fetch RFC text from database
        printf("[*] RFC text not provided, attempting auto-fetch for %s...\n", protocol_name);
        char *fetched_rfc = fetch_rfc_text(protocol_name);  // Returns malloc'ed memory
        
        if (fetched_rfc) {
            size_t rfc_len = strlen(fetched_rfc);
            printf("[+] Successfully fetched RFC for %s (%zu bytes)\n", 
                   protocol_name, rfc_len);
            
            // CRITICAL: Limit RFC size to prevent heap corruption
            if (rfc_len > SAFE_RFC_LIMIT) {
                fprintf(stderr, "[!] WARNING: Fetched RFC too large (%zu bytes), truncating to %d\n", 
                        rfc_len, SAFE_RFC_LIMIT);
                fetched_rfc[SAFE_RFC_LIMIT] = '\0';
                rfc_len = SAFE_RFC_LIMIT;
            }
            
            // Copy to ck_alloc'ed memory for consistency
            ctx->rfc_text = (char*)ck_strdup((u8*)fetched_rfc);
            fprintf(stderr, "[DEBUG] Allocated rfc_text at %p (%zu bytes)\n", 
                    (void*)ctx->rfc_text, rfc_len);
            free(fetched_rfc);  // Free the malloc'ed memory from fetch_rfc_text
        } else {
            printf("[!] Could not fetch RFC for %s, proceeding without RFC knowledge\n", 
                   protocol_name);
            ctx->rfc_text = NULL;
        }
    }
    
    // Copy PCAP samples
    ctx->pcap_count = pcap_count;
    if (pcap_count > 0) {
        ctx->pcap_samples = (char**)ck_alloc(pcap_count * sizeof(char*));
        memset(ctx->pcap_samples, 0, pcap_count * sizeof(char*));  // Initialize to NULL
        for (size_t i = 0; i < pcap_count; i++) {
            ctx->pcap_samples[i] = (char*)ck_strdup((u8*)pcap_samples[i]);
        }
    } else {
        ctx->pcap_samples = NULL;
    }
    
    ctx->server_responses = NULL;
    ctx->response_count = 0;
    
    ctx->hypotheses = NULL;
    ctx->hypothesis_count = 0;
    ctx->refinement_iterations = 0;
    
    return ctx;
}

/* ============================================
 * LLM Prompt Construction
 * ============================================ */

/* ============================================
 * RFC Smart Extraction Functions (v2)
 * ============================================
 * Execution order:
 *   Step 1: Grammar block extraction (40% budget)
 *           - Text protocols → ABNF rules  (name = def)
 *           - Binary protocols → struct/enum/byte-table blocks
 *   Step 2: Section-boundary parsing → numbered RFC sections
 *   Step 3: Scored section selection → greedily fill remaining budget
 *
 * Design rationale:
 *   - ABNF rules (text) / struct+enum defs (binary) are the single
 *     most valuable content for grammar hypothesis generation.
 *   - Numbered RFC sections have clear boundaries; extracting whole
 *     sections preserves semantic coherence.
 *   - Protocol-specific scoring prioritizes relevant sections.
 * ============================================ */

/* Local helper: is this a binary-framed protocol?
 * Must stay in sync with hypothesis-adapter.c::is_binary_protocol(). */
static int rfc_is_binary_protocol(const char *name) {
    if (!name) return 0;
    return (strcasecmp(name, "MQTT")   == 0 ||
            strcasecmp(name, "DNS")    == 0 ||
            strcasecmp(name, "DTLS12") == 0 ||
            strcasecmp(name, "TLS")    == 0 ||
            strcasecmp(name, "SSH")    == 0 ||
            strcasecmp(name, "DICOM")  == 0);
}

/* --- Section representation for RFC parsing --- */
typedef struct {
    size_t start;     /* byte offset in rfc_text */
    size_t end;       /* byte offset (exclusive) */
    int    score;     /* relevance score */
    char   title[128];
} rfc_section_t;

#define MAX_RFC_SECTIONS 256

/* --- Protocol-specific keyword tables --- */
typedef struct {
    const char *protocol;
    const char *keywords[20]; /* NULL-terminated */
} protocol_keyword_table_t;

static const protocol_keyword_table_t PROTOCOL_KEYWORDS[] = {
    { "FTP", { "Command", "Reply", "Transfer", "Access Control",
               "Authentication", "Data Connection", "USER", "PASS",
               "RETR", "STOR", "LIST", "QUIT", "TYPE", NULL } },
    { "SMTP", { "Command", "Reply", "Mail Transaction", "EHLO", "HELO",
                "MAIL FROM", "RCPT TO", "DATA", "RSET", "VRFY", "NOOP",
                "QUIT", "Extension", NULL } },
    { "HTTP", { "Request", "Response", "Method", "Status", "Header",
                "GET", "POST", "PUT", "DELETE", "Content-Type",
                "Transfer-Encoding", "Message Body", NULL } },
    { "RTSP", { "Request", "Response", "Method", "Status", "Header",
                "DESCRIBE", "SETUP", "PLAY", "PAUSE", "TEARDOWN",
                "Session", "Transport", NULL } },
    { "SIP",  { "Request", "Response", "Method", "Header", "Dialog",
                "Transaction", "INVITE", "ACK", "BYE", "CANCEL",
                "REGISTER", "OPTIONS", "Via", "Contact", "CSeq", NULL } },
    { "MQTT", { "CONNECT", "PUBLISH", "SUBSCRIBE", "UNSUBSCRIBE",
                "PINGREQ", "DISCONNECT", "Packet", "Fixed Header",
                "Variable Header", "Payload", "QoS", "Topic", NULL } },
    { "DNS",  { "Query", "Response", "Resource Record", "Header",
                "QTYPE", "QCLASS", "RCODE", "OPCODE", "Domain Name",
                "Label", "Pointer", NULL } },
    { "DTLS12", { "Handshake", "Record", "ClientHello", "ServerHello",
                  "Fragment", "Retransmission", "Epoch", "Sequence",
                  "Cookie", "Alert", NULL } },
    { "TLS",  { "Handshake", "Record", "ClientHello", "ServerHello",
                "Certificate", "Cipher", "Extension", "Alert",
                "Application Data", "Key Exchange", NULL } },
    { "SSH",  { "Key Exchange", "Authentication", "Channel", "Packet",
                "Message Number", "Encryption", "MAC", "Compression",
                "Session", "Transport", NULL } },
    { "DICOM", { "Association", "PDU", "DIMSE", "Command", "Data Set",
                 "Transfer Syntax", "SOP", "Presentation Context",
                 "A-ASSOCIATE", "C-STORE", "C-FIND", NULL } },
    { "IPP",  { "Operation", "Attribute", "Status", "Request",
                "Response", "Job", "Printer", "Group", "Tag",
                "Value", NULL } },
    { NULL, { NULL } } /* terminator */
};

/* Get protocol-specific keywords, or NULL if unknown protocol */
static const char * const *get_protocol_keywords(const char *protocol_name) {
    for (int i = 0; PROTOCOL_KEYWORDS[i].protocol; i++) {
        if (strcasecmp(PROTOCOL_KEYWORDS[i].protocol, protocol_name) == 0)
            return (const char * const *)PROTOCOL_KEYWORDS[i].keywords;
    }
    return NULL;
}

/* --- Pass 1: Parse RFC section boundaries --- */
static int parse_rfc_sections(const char *text, size_t text_len,
                              rfc_section_t *sections, int max_sections)
{
    int count = 0;
    const char *p = text;
    const char *end = text + text_len;

    /* RFC section headers follow patterns:
     *   "1.  TITLE"           (top-level, starts at column 0)
     *   "   2.1.  Sub-title"  (sub-section, indented with spaces)
     *   "25  Augmented BNF"   (some RFCs omit the dot)
     *   "Appendix A.  Title"  (appendix sections — TLS, FTP, etc.)
     * We detect lines that start with optional whitespace + digit(s) + '.'
     * OR lines that start with "Appendix" */
    while (p < end && count < max_sections - 1) {
        /* Find start of line */
        const char *line = p;

        /* Skip leading spaces (max 6 for sub-sections) */
        const char *lp = line;
        int spaces = 0;
        while (lp < end && *lp == ' ' && spaces < 6) { lp++; spaces++; }

        int section_detected = 0;
        const char *title_start = NULL;  /* where the title text begins for copying */
        const char *title_end = NULL;

        /* --- Pattern 1: Numbered sections ("4.1.2  Title") --- */
        if (lp < end && *lp >= '1' && *lp <= '9') {
            const char *np = lp;
            /* Consume number like "4.1.2" */
            while (np < end && ((*np >= '0' && *np <= '9') || *np == '.'))
                np++;

            int num_len = (int)(np - lp);
            /* Must have at least "N." and be followed by whitespace+uppercase or whitespace+title */
            if (num_len >= 2 && *(np - 1) != '.' && lp[num_len - 1 - (num_len > 1)] == '.'
                ? 1 : (num_len >= 1 && np < end && *np == ' ')) {

                /* Skip whitespace after number */
                while (np < end && (*np == ' ' || *np == '\t')) np++;

                /* Check that remainder has title-like text (at least 3 alpha chars) */
                int alpha_count = 0;
                const char *tp = np;
                while (tp < end && *tp != '\n' && *tp != '\r') {
                    if ((*tp >= 'A' && *tp <= 'Z') || (*tp >= 'a' && *tp <= 'z'))
                        alpha_count++;
                    tp++;
                }

                if (alpha_count >= 3) {
                    section_detected = 1;
                    title_start = lp;  /* include number in title */
                    title_end = tp;
                }
            }
        }

        /* --- Pattern 2: Appendix sections ("Appendix A.  State Machine") ---
         * Only match at column 0 (no indent) to avoid TOC entries which
         * are typically indented with 2-3 spaces. */
        if (!section_detected && spaces == 0 && lp < end &&
            (size_t)(end - lp) > 10 && strncmp(lp, "Appendix", 8) == 0) {
            const char *np = lp + 8;
            /* Skip whitespace after "Appendix" */
            while (np < end && (*np == ' ' || *np == '\t')) np++;
            /* Expect letter (A-Z) optionally followed by digits and '.' */
            if (np < end && *np >= 'A' && *np <= 'Z') {
                const char *label_end = np + 1;
                while (label_end < end && ((*label_end >= '0' && *label_end <= '9') ||
                       *label_end == '.')) label_end++;
                /* Skip whitespace to title */
                while (label_end < end && (*label_end == ' ' || *label_end == '\t'))
                    label_end++;
                /* Check for title text */
                int alpha_count = 0;
                const char *tp = label_end;
                while (tp < end && *tp != '\n' && *tp != '\r') {
                    if ((*tp >= 'A' && *tp <= 'Z') || (*tp >= 'a' && *tp <= 'z'))
                        alpha_count++;
                    tp++;
                }
                if (alpha_count >= 3) {
                    section_detected = 1;
                    title_start = lp;  /* "Appendix A.  Title" */
                    title_end = tp;
                }
            }
        }

        /* Record detected section */
        if (section_detected && title_start && title_end) {
            /* Close previous section */
            if (count > 0) {
                sections[count - 1].end = (size_t)(line - text);
            }
            /* Record new section */
            sections[count].start = (size_t)(line - text);
            sections[count].score = 0;

            /* Copy title */
            size_t title_len = (size_t)(title_end - title_start);
            if (title_len > 127) title_len = 127;
            memcpy(sections[count].title, title_start, title_len);
            sections[count].title[title_len] = '\0';

            count++;
        }

        /* Advance to next line */
        while (p < end && *p != '\n') p++;
        if (p < end) p++;  /* skip '\n' */
    }

    /* Close last section */
    if (count > 0) {
        sections[count - 1].end = text_len;
    }

    return count;
}

/* --- Step 1b: Extract binary protocol definition blocks --- */
static size_t extract_binary_protocol_blocks(const char *text, size_t text_len,
                                             char *out, size_t max_out)
{
    /*
     * Binary protocol RFCs define message formats with:
     *  Pattern A: Byte-field tables   "+--+--+--+" (DNS, DICOM)
     *  Pattern B: struct/enum defs    "struct {" / "enum {" (TLS, DTLS)
     *  Pattern C: Field-type lines    "byte  field_name" / "uint32 field" (SSH)
     *  Pattern D: Constant defs       "NAME  VALUE"  or "NAME = VALUE" tables
     *
     * Strategy: scan line by line, detect blocks, extract with surrounding
     * context (3 lines before start for the human-readable description).
     */
    size_t out_len = 0;
    const char *p = text;
    const char *end = text + text_len;
    int blocks_found = 0;

    /* Write header */
    int w = snprintf(out, max_out,
                     "\n[=== Binary Protocol Format Definitions ===]\n");
    if (w > 0 && (size_t)w < max_out) out_len = (size_t)w;

    /* State for block extraction */
    int in_block = 0;          /* currently inside a definition block */
    const char *block_start = NULL;
    const char *context_start = NULL;  /* 3 lines before block for context */
    int brace_depth = 0;       /* for struct/enum { } tracking */
    int block_type = 0;        /* 1=byte-table, 2=struct/enum, 3=field-type */

    /* Ring buffer for last 3 line starts (for pre-context) */
    const char *prev_lines[3] = { text, text, text };
    int prev_idx = 0;

    while (p < end && out_len < max_out - 200) {
        const char *line_start = p;
        const char *line_end = p;
        while (line_end < end && *line_end != '\n') line_end++;
        size_t line_len = (size_t)(line_end - line_start);

        /* --- Detect block starts --- */
        if (!in_block) {
            /* Pattern A: Byte-field table (+--+--+) */
            if (line_len > 8) {
                const char *lp = line_start;
                while (lp < line_end && *lp == ' ') lp++;
                if (line_end - lp > 6 &&
                    lp[0] == '+' && lp[1] == '-' && lp[2] == '-') {
                    in_block = 1;
                    block_type = 1;
                    context_start = prev_lines[(prev_idx + 1) % 3];
                    block_start = context_start;
                }
            }

            /* Pattern B: struct { or enum { */
            if (!in_block && line_len > 4) {
                const char *lp = line_start;
                while (lp < line_end && *lp == ' ') lp++;
                size_t content_len = (size_t)(line_end - lp);
                if ((content_len >= 7 && strncmp(lp, "struct ", 7) == 0) ||
                    (content_len >= 7 && strncmp(lp, "struct{", 7) == 0) ||
                    (content_len >= 5 && strncmp(lp, "enum ", 5) == 0) ||
                    (content_len >= 5 && strncmp(lp, "enum{", 5) == 0)) {
                    in_block = 1;
                    block_type = 2;
                    brace_depth = 0;
                    /* Count braces on this line */
                    for (const char *bp = lp; bp < line_end; bp++) {
                        if (*bp == '{') brace_depth++;
                        else if (*bp == '}') brace_depth--;
                    }
                    context_start = prev_lines[(prev_idx + 1) % 3];
                    block_start = context_start;
                    /* If braces closed on same line, end immediately */
                    if (brace_depth <= 0 && brace_depth != 0) {
                        /* malformed, skip */
                        in_block = 0;
                    }
                }
            }

            /* Pattern C: Field-type lines (byte/uint32/uint16/uint8/string/opaque) */
            if (!in_block && line_len > 6) {
                const char *lp = line_start;
                while (lp < line_end && *lp == ' ') lp++;
                size_t content_len = (size_t)(line_end - lp);
                if ((content_len >= 5 && strncmp(lp, "byte ", 5) == 0) ||
                    (content_len >= 7 && strncmp(lp, "uint32 ", 7) == 0) ||
                    (content_len >= 7 && strncmp(lp, "uint16 ", 7) == 0) ||
                    (content_len >= 6 && strncmp(lp, "uint8 ", 6) == 0) ||
                    (content_len >= 7 && strncmp(lp, "uint24 ", 7) == 0) ||
                    (content_len >= 7 && strncmp(lp, "opaque ", 7) == 0) ||
                    (content_len >= 6 && strncmp(lp, "byte[", 5) == 0)) {
                    in_block = 1;
                    block_type = 3;
                    context_start = prev_lines[(prev_idx + 1) % 3];
                    block_start = context_start;
                }
            }
        }

        /* --- Track block continuation / end --- */
        if (in_block) {
            if (block_type == 1) {
                /* Byte-table: continues while lines have +--+ or | or field names
                 * Ends on blank line or next section */
                const char *lp = line_start;
                while (lp < line_end && *lp == ' ') lp++;
                int is_table_line = 0;
                if (lp < line_end) {
                    if (*lp == '+' || *lp == '|' || *lp == '/')
                        is_table_line = 1;
                    /* Field descriptions: indented text after table */
                    if (line_len > 0 && line_start[0] == ' ' && lp < line_end &&
                        ((*lp >= 'A' && *lp <= 'Z') || (*lp >= 'a' && *lp <= 'z')))
                        is_table_line = 1;
                }
                if (!is_table_line || line_len == 0) {
                    /* End of byte-table block — flush */
                    size_t blen = (size_t)(line_start - block_start);
                    if (blen > 10 && out_len + blen + 2 < max_out) {
                        memcpy(out + out_len, block_start, blen);
                        out_len += blen;
                        out[out_len++] = '\n';
                        blocks_found++;
                    }
                    in_block = 0;
                }
            } else if (block_type == 2) {
                /* struct/enum: track brace depth */
                for (const char *bp = line_start; bp < line_end; bp++) {
                    if (*bp == '{') brace_depth++;
                    else if (*bp == '}') brace_depth--;
                }
                if (brace_depth <= 0) {
                    /* Closing brace found — include this line, then flush */
                    const char *block_end = line_end;
                    if (block_end < end) block_end++;  /* include \n */
                    size_t blen = (size_t)(block_end - block_start);
                    if (blen > 10 && out_len + blen + 2 < max_out) {
                        memcpy(out + out_len, block_start, blen);
                        out_len += blen;
                        out[out_len++] = '\n';
                        blocks_found++;
                    }
                    in_block = 0;
                }
            } else if (block_type == 3) {
                /* Field-type lines: continues while lines match byte/uint/etc */
                const char *lp = line_start;
                while (lp < line_end && *lp == ' ') lp++;
                size_t content_len = (size_t)(line_end - lp);
                int is_field = 0;
                if (content_len >= 4 &&
                    (strncmp(lp, "byte", 4) == 0 ||
                     strncmp(lp, "uint", 4) == 0 ||
                     strncmp(lp, "opaq", 4) == 0 ||
                     strncmp(lp, "stri", 4) == 0 ||
                     strncmp(lp, "name", 4) == 0 ||
                     strncmp(lp, "bool", 4) == 0))
                    is_field = 1;
                /* Also continue for blank/comment lines within block */
                if (line_len == 0)
                    is_field = 0;  /* blank = end */

                if (!is_field) {
                    size_t blen = (size_t)(line_start - block_start);
                    if (blen > 10 && out_len + blen + 2 < max_out) {
                        memcpy(out + out_len, block_start, blen);
                        out_len += blen;
                        out[out_len++] = '\n';
                        blocks_found++;
                    }
                    in_block = 0;
                }
            }
        }

        /* Update previous-line ring buffer */
        prev_lines[prev_idx] = line_start;
        prev_idx = (prev_idx + 1) % 3;

        /* Next line */
        p = line_end;
        if (p < end) p++;
    }

    /* Flush final block */
    if (in_block && block_start) {
        size_t blen = (size_t)(end - block_start);
        if (blen > 10 && out_len + blen + 2 < max_out) {
            memcpy(out + out_len, block_start, blen);
            out_len += blen;
            blocks_found++;
        }
    }

    if (blocks_found == 0) {
        return 0;  /* No binary definitions found */
    }

    out[out_len] = '\0';
    printf("[RFC-Extract] Found %d binary protocol definition blocks (%zu bytes)\n",
           blocks_found, out_len);
    return out_len;
}

/* --- Step 1a: Extract ABNF/BNF grammar blocks (text protocols) --- */
static size_t extract_abnf_blocks(const char *text, size_t text_len,
                                  char *out, size_t max_out)
{
    /* ABNF rules:  "rule-name  =  definition"    (RFC 5234 style)
     * BNF rules:   "rule-name  ::=  definition"  (older RFCs: FTP 959, etc.)
     * Continuation: "               / alternative"
     * Match: ^[A-Za-z][A-Za-z0-9-]*  *(=|::=)  (but not == which is code) */
    size_t out_len = 0;
    const char *p = text;
    const char *end = text + text_len;
    int in_rule = 0;
    const char *rule_start = NULL;
    int rules_found = 0;

    /* Write header */
    int w = snprintf(out, max_out,
                     "\n[=== ABNF/BNF Grammar Rules ===]\n");
    if (w > 0 && (size_t)w < max_out) out_len = (size_t)w;

    while (p < end) {
        /* Find line boundaries */
        const char *line_start = p;
        const char *line_end = p;
        while (line_end < end && *line_end != '\n') line_end++;

        size_t line_len = (size_t)(line_end - line_start);

        /* Check if this line starts a new ABNF/BNF rule */
        int is_rule_start = 0;
        if (line_len > 4) {
            const char *lp = line_start;
            /* Allow leading spaces (some RFCs indent ABNF) */
            while (lp < line_end && *lp == ' ') lp++;

            if (lp < line_end &&
                ((*lp >= 'A' && *lp <= 'Z') || (*lp >= 'a' && *lp <= 'z'))) {
                /* Scan rule name: [A-Za-z0-9-]* */
                const char *name_end = lp + 1;
                while (name_end < line_end &&
                       ((*name_end >= 'A' && *name_end <= 'Z') ||
                        (*name_end >= 'a' && *name_end <= 'z') ||
                        (*name_end >= '0' && *name_end <= '9') ||
                        *name_end == '-'))
                    name_end++;

                /* Skip spaces before operator */
                const char *eq = name_end;
                while (eq < line_end && *eq == ' ') eq++;

                /* Check for ABNF '=' (not '==') or BNF '::=' */
                if ((name_end - lp) >= 2 && (name_end - lp) <= 40) {
                    if (eq < line_end && *eq == '=' &&
                        (eq + 1 >= line_end || *(eq + 1) != '=')) {
                        is_rule_start = 1;  /* ABNF: name = def */
                    } else if (eq + 2 < line_end &&
                               eq[0] == ':' && eq[1] == ':' && eq[2] == '=') {
                        is_rule_start = 1;  /* BNF: name ::= def */
                    }
                }
            }
        }

        /* Check if line is ABNF continuation: starts with lots of spaces then / or text */
        int is_continuation = 0;
        if (in_rule && line_len > 0) {
            int leading = 0;
            const char *lp = line_start;
            while (lp < line_end && *lp == ' ') { lp++; leading++; }
            /* Continuation: indented >= 6 spaces, or starts with / */
            if (leading >= 6 && lp < line_end && *lp != '\n') {
                is_continuation = 1;
            }
            if (lp < line_end && *lp == '/') {
                is_continuation = 1;
            }
        }

        if (is_rule_start) {
            /* Flush previous rule if any */
            if (in_rule && rule_start) {
                size_t rlen = (size_t)(line_start - rule_start);
                if (out_len + rlen + 2 < max_out) {
                    memcpy(out + out_len, rule_start, rlen);
                    out_len += rlen;
                    rules_found++;
                }
            }
            rule_start = line_start;
            in_rule = 1;
        } else if (!is_continuation && in_rule) {
            /* End of rule block — flush */
            if (rule_start) {
                size_t rlen = (size_t)(line_start - rule_start);
                if (out_len + rlen + 2 < max_out) {
                    memcpy(out + out_len, rule_start, rlen);
                    out_len += rlen;
                    rules_found++;
                }
            }
            in_rule = 0;
            rule_start = NULL;
        }

        /* Next line */
        p = line_end;
        if (p < end) p++;
    }

    /* Flush final rule */
    if (in_rule && rule_start) {
        size_t rlen = (size_t)(end - rule_start);
        if (out_len + rlen + 2 < max_out) {
            memcpy(out + out_len, rule_start, rlen);
            out_len += rlen;
            rules_found++;
        }
    }

    if (rules_found == 0) {
        return 0;  /* No ABNF found — caller should not use this output */
    }

    out[out_len] = '\0';
    printf("[RFC-Extract] Found %d ABNF rules (%zu bytes)\n", rules_found, out_len);
    return out_len;
}

/* --- Pass 3: Score and select sections --- */
static void score_sections(rfc_section_t *sections, int count,
                           const char *rfc_text,
                           const char *protocol_name)
{
    /* State-machine critical keywords — highest priority for fuzzer */
    static const char *generic_state[] = {
        "State Diagram", "State Machine", "Transaction",
        "Handshake", NULL
    };
    /* Generic high-value keywords (applicable to all protocols) */
    static const char *generic_high[] = {
        "ABNF", "BNF", "Grammar", "Syntax", "Format",
        "Definition", "Data Structure", "Constant", NULL
    };
    static const char *generic_mid[] = {
        "Command", "Request", "Response", "Reply", "Method",
        "Status", "Code", "State", "Machine", "Transition",
        "Header", "Field", "Parameter", "Message", NULL
    };
    static const char *generic_low[] = {
        "Example", "Scenario", "Overview", "Introduction",
        "Security", "IANA", "Acknowledgement", "Reference",
        "Author", "Copyright", "Abstract", NULL
        /* Note: "Appendix" removed from penalty list — we now properly
         * parse Appendix sections (Fix-21a) and they often contain
         * critical state machine and data structure definitions */
    };

    const char * const *proto_kw = get_protocol_keywords(protocol_name);

    for (int i = 0; i < count; i++) {
        int score = 0;
        const char *title = sections[i].title;
        size_t sec_len = sections[i].end - sections[i].start;

        /* Score based on title keyword matches — check tiers in priority order */
        /* Tier 0: State-machine critical (+40) — highest priority for fuzzer */
        int state_matched = 0;
        for (int k = 0; generic_state[k]; k++) {
            if (strcasestr(title, generic_state[k])) {
                score += 40; state_matched = 1; break;
            }
        }
        /* Tier 1: Grammar/syntax high (+30) */
        for (int k = 0; generic_high[k]; k++) {
            if (strcasestr(title, generic_high[k])) { score += 30; break; }
        }
        /* Tier 2: Protocol element mid (+15) */
        if (!state_matched) {  /* avoid double-counting State/Machine */
            for (int k = 0; generic_mid[k]; k++) {
                if (strcasestr(title, generic_mid[k])) { score += 15; break; }
            }
        }
        /* Tier 3: Low-value penalty (-10) */
        for (int k = 0; generic_low[k]; k++) {
            if (strcasestr(title, generic_low[k])) { score -= 10; break; }
        }

        /* Protocol-specific keyword bonus: check section CONTENT */
        if (proto_kw) {
            const char *sec_text = rfc_text + sections[i].start;
            /* Scan first 5000 chars of section for broader coverage */
            size_t scan_len = sec_len < 5000 ? sec_len : 5000;
            int hits = 0;
            for (int k = 0; proto_kw[k] && hits < 15; k++) {
                /* Count up to 2 occurrences per keyword */
                const char *found = sec_text;
                const char *scan_end = sec_text + scan_len;
                int kw_hits = 0;
                while (found < scan_end && kw_hits < 2) {
                    found = strcasestr(found, proto_kw[k]);
                    if (!found || found >= scan_end) break;
                    kw_hits++;
                    found += strlen(proto_kw[k]);
                }
                hits += kw_hits;
            }
            score += hits * 5;  /* Each hit = +5 */
        }

        /* ABNF/BNF content bonus: check for rule definitions (= and ::=) */
        {
            const char *sec_text = rfc_text + sections[i].start;
            size_t scan_len = sec_len < 5000 ? sec_len : 5000;
            const char *sp = sec_text;
            int abnf_count = 0;
            while (sp < sec_text + scan_len - 2 && abnf_count < 5) {
                /* Look for ' = ' (ABNF) */
                const char *eq = strstr(sp, " = ");
                /* Also look for ' ::= ' (BNF) */
                const char *bnf = strstr(sp, " ::= ");
                /* Take whichever comes first */
                const char *match = NULL;
                int advance = 3;
                if (eq && (!bnf || eq <= bnf)) {
                    match = eq; advance = 3;
                } else if (bnf) {
                    match = bnf; advance = 5;
                }
                if (!match || match >= sec_text + scan_len) break;
                /* Check if preceded by alpha (rule-name) */
                if (match > sec_text &&
                    ((*(match-1) >= 'A' && *(match-1) <= 'Z') ||
                     (*(match-1) >= 'a' && *(match-1) <= 'z') ||
                     *(match-1) == '-'))
                    abnf_count++;
                sp = match + advance;
            }
            score += abnf_count * 8;
        }

        /* State diagram content bonus: check for ASCII art state diagrams */
        {
            const char *sec_text = rfc_text + sections[i].start;
            size_t scan_len = sec_len < 8000 ? sec_len : 8000;
            int diagram_indicators = 0;
            /* Look for ASCII art patterns: "+---+", "| B |", "--->", "<---" */
            const char *sp = sec_text;
            while (sp < sec_text + scan_len - 4 && diagram_indicators < 5) {
                if ((sp[0] == '+' && sp[1] == '-' && sp[2] == '-' && sp[3] == '-') ||
                    (sp[0] == '-' && sp[1] == '-' && sp[2] == '-' && sp[3] == '>') ||
                    (sp[0] == '<' && sp[1] == '-' && sp[2] == '-' && sp[3] == '-') ||
                    (sp[0] == '|' && sp[1] == ' ' &&
                     ((sp[2] >= 'A' && sp[2] <= 'Z') || (sp[2] >= 'a' && sp[2] <= 'z')))) {
                    diagram_indicators++;
                }
                sp++;
            }
            if (diagram_indicators >= 3) {
                score += 25;  /* Strong state diagram bonus */
            } else if (diagram_indicators >= 1) {
                score += 10;  /* Weak diagram hint */
            }
        }

        /* Penalty for very large sections (>15KB) — they dilute the budget */
        if (sec_len > 15000) score -= 5;
        if (sec_len > 30000) score -= 10;

        /* Penalty for very short sections (<200 bytes) — likely just a title */
        if (sec_len < 200) score -= 20;

        sections[i].score = score;
    }
}

/* Comparator for sorting sections by score (descending) */
static int section_score_cmp(const void *a, const void *b) {
    const rfc_section_t *sa = (const rfc_section_t *)a;
    const rfc_section_t *sb = (const rfc_section_t *)b;
    return sb->score - sa->score;  /* descending */
}

/* --- Main extraction entry point (v2) --- */
char* extract_rfc_key_sections(const char *rfc_text, size_t max_chars,
                               const char *protocol_name) {
    if (!rfc_text) return NULL;

    size_t rfc_len = strlen(rfc_text);

    /* If RFC is small enough, use it all */
    if (rfc_len <= max_chars) {
        return (char*)ck_strdup((u8*)rfc_text);
    }

    char *extracted = (char*)ck_alloc(max_chars + 1);
    memset(extracted, 0, max_chars + 1);
    size_t out_len = 0;

    /* --- Step 1: Extract grammar definition blocks (40% budget) ---
     * Text protocols → ABNF rules  (e.g., SIP RFC has ~200 rules)
     * Binary protocols → struct/enum/byte-table definitions */
    size_t grammar_budget = max_chars * 2 / 5;
    size_t grammar_len = 0;

    if (rfc_is_binary_protocol(protocol_name)) {
        grammar_len = extract_binary_protocol_blocks(rfc_text, rfc_len,
                                                     extracted, grammar_budget);
        if (grammar_len == 0) {
            /* Fallback: some binary specs (MQTT HTML) may not have
             * recognizable struct/enum patterns after HTML stripping.
             * Try ABNF as a second chance. */
            grammar_len = extract_abnf_blocks(rfc_text, rfc_len,
                                              extracted, grammar_budget);
        }
    } else {
        grammar_len = extract_abnf_blocks(rfc_text, rfc_len,
                                          extracted, grammar_budget);
        if (grammar_len == 0) {
            /* Fallback: some text protocol RFCs lack ABNF.
             * Try binary patterns as a second chance. */
            grammar_len = extract_binary_protocol_blocks(rfc_text, rfc_len,
                                                         extracted, grammar_budget);
        }
    }
    out_len = grammar_len;

    /* --- Step 1c: Extract ASCII state diagrams (10% budget) ---
     * State diagrams use ASCII art: "+---+", "--->", "| B |"
     * These are critical for LLM understanding of protocol state machines.
     * We extract them as a dedicated pass before section scoring,
     * so they are guaranteed to be included regardless of section scores. */
    {
        size_t diagram_budget = max_chars / 10;  /* 10% = ~5KB */
        if (diagram_budget > max_chars - out_len)
            diagram_budget = max_chars - out_len;
        size_t diagram_len = 0;
        char *diagram_buf = extracted + out_len;
        int diagram_header_written = 0;

        const char *dp = rfc_text;
        const char *dp_end = rfc_text + rfc_len;
        int in_diagram = 0;
        const char *diag_start = NULL;
        /* Ring buffer for 2 lines of pre-context */
        const char *dprev[2] = { rfc_text, rfc_text };
        int dprev_idx = 0;

        while (dp < dp_end && diagram_len < diagram_budget - 200) {
            const char *dl_start = dp;
            const char *dl_end = dp;
            while (dl_end < dp_end && *dl_end != '\n') dl_end++;
            size_t dl_len = (size_t)(dl_end - dl_start);

            /* Detect state diagram line patterns */
            int is_diagram_line = 0;
            if (dl_len >= 4) {
                const char *dlp = dl_start;
                while (dlp < dl_end && *dlp == ' ') dlp++;
                size_t content_len = (size_t)(dl_end - dlp);
                if (content_len >= 4) {
                    /* +---+ box top/bottom */
                    if (dlp[0] == '+' && dlp[1] == '-' && dlp[2] == '-' && dlp[3] == '-')
                        is_diagram_line = 1;
                    /* | X | box body */
                    if (dlp[0] == '|' && dlp[1] == ' ' && content_len >= 5)
                        is_diagram_line = 1;
                    /* Arrow patterns: ---> or ----> or <--- */
                    for (const char *ap = dlp; ap < dl_end - 3; ap++) {
                        if ((ap[0] == '-' && ap[1] == '-' && ap[2] == '-' && ap[3] == '>') ||
                            (ap[0] == '<' && ap[1] == '-' && ap[2] == '-' && ap[3] == '-') ||
                            (ap[0] == '-' && ap[1] == '-' && ap[2] == '>')) {
                            is_diagram_line = 1; break;
                        }
                    }
                    /* Vertical connectors: lines that are mostly | and spaces */
                    if (!is_diagram_line && in_diagram) {
                        int pipe_count = 0, space_count = 0;
                        for (const char *cp = dlp; cp < dl_end; cp++) {
                            if (*cp == '|') pipe_count++;
                            else if (*cp == ' ') space_count++;
                        }
                        if (pipe_count >= 1 && space_count + pipe_count >= (int)content_len * 7 / 10)
                            is_diagram_line = 1;
                    }
                }
            }

            if (is_diagram_line && !in_diagram) {
                /* Start new diagram — include 2 lines of pre-context for description */
                in_diagram = 1;
                diag_start = dprev[(dprev_idx) % 2];  /* 2 lines back */
                if (!diagram_header_written) {
                    int hw = snprintf(diagram_buf + diagram_len,
                                      diagram_budget - diagram_len,
                                      "\n[=== State Diagrams ===]\n");
                    if (hw > 0) diagram_len += (size_t)hw;
                    diagram_header_written = 1;
                }
            } else if (!is_diagram_line && in_diagram) {
                /* Allow 1 blank line within diagram (common in RFC formatting) */
                if (dl_len == 0) {
                    /* Check if next non-empty line is also diagram */
                    const char *peek = dl_end;
                    if (peek < dp_end) peek++;  /* skip \n */
                    const char *pk_end = peek;
                    while (pk_end < dp_end && *pk_end != '\n') pk_end++;
                    int next_is_diag = 0;
                    if (pk_end - peek >= 4) {
                        const char *pkp = peek;
                        while (pkp < pk_end && *pkp == ' ') pkp++;
                        if ((pkp[0] == '+' && pkp[1] == '-') ||
                            (pkp[0] == '|' && pkp[1] == ' '))
                            next_is_diag = 1;
                        for (const char *a = pkp; a < pk_end - 3 && !next_is_diag; a++)
                            if (a[0] == '-' && a[1] == '-' && a[2] == '>')
                                next_is_diag = 1;
                    }
                    if (!next_is_diag) {
                        /* End diagram */
                        size_t dlen = (size_t)(dl_start - diag_start);
                        if (dlen > 20 && diagram_len + dlen + 2 < diagram_budget) {
                            memcpy(diagram_buf + diagram_len, diag_start, dlen);
                            diagram_len += dlen;
                            diagram_buf[diagram_len++] = '\n';
                        }
                        in_diagram = 0;
                    }
                } else {
                    /* Non-diagram, non-blank: end diagram */
                    size_t dlen = (size_t)(dl_start - diag_start);
                    if (dlen > 20 && diagram_len + dlen + 2 < diagram_budget) {
                        memcpy(diagram_buf + diagram_len, diag_start, dlen);
                        diagram_len += dlen;
                        diagram_buf[diagram_len++] = '\n';
                    }
                    in_diagram = 0;
                }
            }

            /* Update pre-context ring buffer */
            dprev[dprev_idx] = dl_start;
            dprev_idx = (dprev_idx + 1) % 2;

            dp = dl_end;
            if (dp < dp_end) dp++;
        }

        /* Flush final diagram */
        if (in_diagram && diag_start) {
            size_t dlen = (size_t)(dp - diag_start);
            if (dlen > 20 && diagram_len + dlen + 2 < diagram_budget) {
                memcpy(diagram_buf + diagram_len, diag_start, dlen);
                diagram_len += dlen;
            }
        }

        if (diagram_len > 0) {
            out_len += diagram_len;
            printf("[RFC-Extract] Extracted %zu bytes of state diagrams\n", diagram_len);
        }
    }

    /* --- Pass 1: Parse section boundaries --- */
    rfc_section_t *sections = (rfc_section_t *)ck_alloc(
        MAX_RFC_SECTIONS * sizeof(rfc_section_t));
    memset(sections, 0, MAX_RFC_SECTIONS * sizeof(rfc_section_t));

    int sec_count = parse_rfc_sections(rfc_text, rfc_len,
                                       sections, MAX_RFC_SECTIONS);

    if (sec_count == 0) {
        /* No recognizable sections — fall back to head of document */
        printf("[RFC-Extract] No sections found, using first %zu bytes\n", max_chars);
        if (out_len < max_chars) {
            size_t remain = max_chars - out_len;
            size_t copy = remain < rfc_len ? remain : rfc_len;
            memcpy(extracted + out_len, rfc_text, copy);
            out_len += copy;
        }
        ck_free(sections);
        extracted[out_len] = '\0';
        return extracted;
    }

    printf("[RFC-Extract] Parsed %d sections from RFC (%zu bytes)\n",
           sec_count, rfc_len);

    /* --- Pass 3: Score sections, greedily select top-scoring --- */
    score_sections(sections, sec_count, rfc_text,
                   protocol_name ? protocol_name : "GENERIC");

    /* Sort by score descending */
    qsort(sections, sec_count, sizeof(rfc_section_t), section_score_cmp);

    /* Greedily select sections until budget is full */
    size_t remaining_budget = max_chars - out_len;
    int selected = 0;

    for (int i = 0; i < sec_count && remaining_budget > 200; i++) {
        size_t sec_len = sections[i].end - sections[i].start;
        if (sections[i].score < 0) continue;  /* skip negatively-scored */

        /* Dynamic section cap: 12KB for state-machine sections, 8KB for others.
         * State machine sections (score >= 40 from generic_state tier, or title
         * contains 'State'/'Diagram'/'Transaction'/'Handshake') deserve more
         * space because they contain ASCII art diagrams and transition logic. */
        size_t section_cap = 8192;  /* default 8KB */
        if (sections[i].score >= 60 ||
            strcasestr(sections[i].title, "State") ||
            strcasestr(sections[i].title, "Diagram") ||
            strcasestr(sections[i].title, "Transaction") ||
            strcasestr(sections[i].title, "Handshake")) {
            section_cap = 12288;  /* 12KB for state-machine sections */
        }

        size_t copy_len = sec_len;
        if (copy_len > section_cap) copy_len = section_cap;
        if (copy_len > remaining_budget - 50) copy_len = remaining_budget - 50;

        /* Write section with header marker */
        int hdr = snprintf(extracted + out_len, remaining_budget,
                           "\n[--- Section: %s (score=%d) ---]\n",
                           sections[i].title, sections[i].score);
        if (hdr > 0 && (size_t)hdr < remaining_budget) {
            out_len += hdr;
            remaining_budget -= hdr;
        }

        /* Copy section content */
        if (copy_len > 0 && copy_len <= remaining_budget) {
            memcpy(extracted + out_len,
                   rfc_text + sections[i].start, copy_len);
            out_len += copy_len;
            remaining_budget -= copy_len;
            selected++;
        }
    }

    printf("[RFC-Extract] Selected %d/%d sections (grammar=%zu + sections=%zu = %zu/%zu bytes)\n",
           selected, sec_count, grammar_len, out_len - grammar_len, out_len, max_chars);

    ck_free(sections);
    extracted[out_len] = '\0';
    return extracted;
}

/* JSON escape helper - escape special characters for JSON strings */
static char* json_escape_string(const char *str, size_t max_len) {
    if (!str) {
        // Return empty string instead of NULL to prevent crashes
        char *empty = (char*)ck_alloc(1);
        empty[0] = '\0';
        return empty;
    }
    
    // Worst case: every character needs escaping (e.g., all quotes)
    size_t src_len = strlen(str);
    if (src_len > max_len) src_len = max_len;
    
    // Allocate enough for worst case: every char becomes 6 chars (\\uXXXX) + null terminator
    size_t buf_size = src_len * 6 + 1;
    char *escaped = (char*)ck_alloc(buf_size);
    memset(escaped, 0, buf_size);  // Initialize buffer
    size_t j = 0;
    
    for (size_t i = 0; i < src_len && str[i] != '\0'; i++) {
        // Safety check to prevent buffer overflow
        if (j >= buf_size - 7) {  // Reserve 7 bytes for worst case escape + null
            break;
        }
        
        unsigned char c = (unsigned char)str[i];
        
        // Handle all control characters and special JSON characters
        switch (c) {
            case '"':  escaped[j++] = '\\'; escaped[j++] = '"'; break;
            case '\\': escaped[j++] = '\\'; escaped[j++] = '\\'; break;
            case '\n': escaped[j++] = '\\'; escaped[j++] = 'n'; break;
            case '\r': escaped[j++] = '\\'; escaped[j++] = 'r'; break;
            case '\t': escaped[j++] = '\\'; escaped[j++] = 't'; break;
            case '\b': escaped[j++] = '\\'; escaped[j++] = 'b'; break;
            case '\f': escaped[j++] = '\\'; escaped[j++] = 'f'; break;
            default:
                // Skip ALL control characters (ASCII 0-31 and 127)
                // This includes \v (vertical tab, 0x0B), \a (bell, 0x07), etc.
                if (c < 32 || c == 127) {
                    // Replace with space for readability instead of skipping
                    escaped[j++] = ' ';
                } else if (c >= 128) {
                    // High-bit characters: keep as-is (UTF-8 safe)
                    escaped[j++] = c;
                } else {
                    // Normal printable ASCII character
                    escaped[j++] = c;
                }
                break;
        }
    }
    escaped[j] = '\0';
    return escaped;
}

int should_include_pcap_sample(
    const char *new_sample,
    char **existing_samples,
    size_t existing_count
) {
    // Deduplication: check if this sample is too similar to existing ones
    // Use simple edit distance heuristic
    
    size_t new_len = strlen(new_sample);
    
    for (size_t i = 0; i < existing_count; i++) {
        size_t existing_len = strlen(existing_samples[i]);
        
        // If lengths are too similar and first 20 chars match, likely duplicate
        if (abs((int)new_len - (int)existing_len) < 5) {
            size_t cmp_len = new_len < 20 ? new_len : 20;
            if (strncmp(new_sample, existing_samples[i], cmp_len) == 0) {
                return 0;  // Too similar, skip
            }
        }
    }
    
    return 1;  // Include this sample
}

char* construct_hypothesis_generation_prompt(hypothesis_context_t *ctx) {
    if (!ctx) {
        fprintf(stderr, "[!] construct_hypothesis_generation_prompt: ctx is NULL\n");
        return NULL;
    }
    
    char *prompt = (char*)ck_alloc(MAX_HYPOTHESIS_PROMPT);
    memset(prompt, 0, MAX_HYPOTHESIS_PROMPT);  // Initialize buffer
    int offset = 0;
    int written;
    
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "[{\"role\": \"system\", \"content\": \"You are a protocol grammar expert. "
        "Generate structured message grammars in JSON Schema format with field constraints.\"},"
        "{\"role\": \"user\", \"content\": \"");
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Prompt buffer overflow at system message\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;
    
    // Protocol context
    char *escaped_protocol = json_escape_string(ctx->protocol_name, 256);

    /* P1-rev: For MQTT, add specific instructions explaining the
     * binary-to-text bridge format so the LLM generates constraints
     * that match structured text like "CONNECT ClientId=x CleanSession=1"
     * rather than trying to describe raw binary wire format. */
    if (ctx->protocol_name && strcasecmp(ctx->protocol_name, "MQTT") == 0) {
      written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
          "Protocol: %s (binary, presented as structured text)\\n\\n"
          "IMPORTANT: MQTT is a binary protocol, but all seed samples and "
          "validation targets have been converted to structured text format "
          "by our binary-to-text decoder. Each MQTT packet appears as a "
          "single line like:\\n"
          "  CONNECT ClientId=fuzz_c1 CleanSession=1 KeepAlive=60\\n"
          "  PUBLISH Topic=test/topic QoS=1 Retain=0 PktId=42 PayloadLen=15\\n"
          "  SUBSCRIBE PktId=1 Filter=test/+ QoS=2\\n"
          "  CONNACK SessionPresent=0 ReturnCode=0\\n\\n"
          "Generate constraints that match THIS TEXT FORMAT, not raw binary. "
          "For example:\\n"
          "- REGEX: \\\"^CONNECT .*ClientId=.+\\\" to validate CONNECT structure\\n"
          "- ENUM: [\\\"0\\\", \\\"1\\\"] for CleanSession values\\n"
          "- NUMERIC: min=0 max=65535 for KeepAlive range\\n"
          "- REGEX: \\\"^PUBLISH .*Topic=.+\\\" for PUBLISH structure\\n\\n",
          escaped_protocol);
    } else {
      written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
          "Protocol: %s\\n\\n", escaped_protocol);
    }
    ck_free(escaped_protocol);
    
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Prompt buffer overflow at protocol name\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;
    
    // Add RFC specification with smart extraction
    if (ctx->rfc_text) {
        char *rfc_extract = extract_rfc_key_sections(ctx->rfc_text, MAX_RFC_CHARS,
                                                       ctx->protocol_name);
        
        if (rfc_extract) {
            char *escaped_rfc = json_escape_string(rfc_extract, MAX_RFC_CHARS);
            size_t extract_len = strlen(escaped_rfc);
            
            written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
                "RFC Specification (%zu characters):\\n%s\\n\\n",
                extract_len, escaped_rfc);
            
            ck_free(escaped_rfc);
            ck_free(rfc_extract);
            
            if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
                fprintf(stderr, "[!] Prompt buffer overflow at RFC content\n");
                fprintf(stderr, "[!] Continuing without RFC content\n");
            } else {
                offset += written;
                printf("[+] Injected %zu chars of RFC content into LLM prompt\n", extract_len);
            }
        }
    }
    
    // Add PCAP samples with deduplication
    if (ctx->pcap_count > 0) {
        written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
            "Example Messages (from initial seeds):\\n");
        if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
            fprintf(stderr, "[!] Prompt buffer overflow at PCAP header\n");
            goto finalize_prompt;  // Safe: selected_samples not yet allocated
        }
        offset += written;
        
        // Apply smart sampling: up to MAX_PCAP_SAMPLES diverse samples
        size_t sample_limit = ctx->pcap_count < MAX_PCAP_SAMPLES ? 
                              ctx->pcap_count : MAX_PCAP_SAMPLES;
        
        char **selected_samples = (char**)ck_alloc(sample_limit * sizeof(char*));
        memset(selected_samples, 0, sample_limit * sizeof(char*));  // Initialize to NULL
        size_t selected_count = 0;
        
        // Select diverse samples
        for (size_t i = 0; i < ctx->pcap_count && selected_count < sample_limit; i++) {
            if (should_include_pcap_sample(ctx->pcap_samples[i], 
                                          selected_samples, 
                                          selected_count)) {
                // Double-check bounds before adding (defensive programming)
                if (selected_count < sample_limit) {
                    selected_samples[selected_count++] = ctx->pcap_samples[i];
                }
            }
        }
        
        // Inject selected samples
        for (size_t i = 0; i < selected_count; i++) {
            char *escaped_sample = json_escape_string(selected_samples[i], 512);
            written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
                "%zu. %s\\n", i + 1, escaped_sample);
            ck_free(escaped_sample);
            
            if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
                fprintf(stderr, "[!] Prompt buffer overflow at PCAP sample %zu\n", i);
                break;
            }
            offset += written;
        }
        
        ck_free(selected_samples);
        
        printf("[+] Injected %zu diverse PCAP samples (from %zu total) into LLM prompt\n",
               selected_count, ctx->pcap_count);
        
        written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset, "\\n");
        if (written > 0 && written < MAX_HYPOTHESIS_PROMPT - offset) {
            offset += written;
        }
    }

    /* ── Gap-1 fix: Inject server response examples into the prompt ──
     * Gives the LLM concrete evidence of server behaviour (status codes,
     * header fields, error messages) which dramatically improves the
     * quality of constraint generation — especially enums and dependency
     * constraints that require knowledge of both directions. */
    if (ctx->server_responses && ctx->response_count > 0) {
        written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
            "Server Response Examples (observed during fuzzing):\\n");
        if (written > 0 && written < MAX_HYPOTHESIS_PROMPT - offset) {
            offset += written;
        }

        size_t resp_limit = ctx->response_count < 5 ? ctx->response_count : 5;
        for (size_t i = 0; i < resp_limit; i++) {
            char *escaped_resp = json_escape_string(ctx->server_responses[i], 512);
            written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
                "%zu. %s\\n", i + 1, escaped_resp);
            ck_free(escaped_resp);
            if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) break;
            offset += written;
        }

        written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset, "\\n");
        if (written > 0 && written < MAX_HYPOTHESIS_PROMPT - offset) {
            offset += written;
        }

        printf("[+] Injected %zu server response examples into LLM prompt\n",
               resp_limit);
    }
    
finalize_prompt:
    
    // Request format
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "Generate grammar hypotheses for this protocol. For each message type, provide:\\n"
        "1. message_type: Identifier (e.g., 'USER', 'GET')\\n"
        "2. description: What this message does\\n"
        "3. schema: JSON Schema with field definitions.  "
        "Use standard JSON Schema keywords: "
        "\\\"minLength\\\"/\\\"maxLength\\\" for string lengths, "
        "\\\"enum\\\": [\\\"val1\\\", \\\"val2\\\"] for allowed values, "
        "\\\"pattern\\\": \\\"regex\\\" for format constraints, "
        "\\\"minimum\\\"/\\\"maximum\\\" for numeric ranges, "
        "and \\\"required\\\": [\\\"field1\\\", ...] for mandatory fields.\\n"
        "4. constraints: Array of field constraints\\n"
        "5. production_rules: ABNF-like syntax rules\\n\\n"
        "Format your response as a JSON array of hypothesis objects:\\n"
        "[{\\\"message_type\\\": \\\"...\\\", \\\"description\\\": \\\"...\\\", "
        "\\\"schema\\\": {...}, \\\"constraints\\\": [...], "
        "\\\"production_rules\\\": [\\\"...\\\"]}]\\n\\n"
        "Include constraints like: length ranges, allowed values (enums), "
        "regex patterns, field dependencies, numeric ranges.\"}]");
    
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Prompt buffer overflow at final request format\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;
    
    printf("[+] Constructed LLM prompt (%d bytes total)\n", offset);
    
    // Debug: Save prompt to file for inspection
    FILE *debug_fp = fopen("/tmp/hypothesis_prompt_debug.json", "w");
    if (debug_fp) {
        fwrite(prompt, 1, offset, debug_fp);
        fclose(debug_fp);
        printf("[DEBUG] Prompt saved to /tmp/hypothesis_prompt_debug.json\n");
    }
    
    return prompt;
}

char* construct_hypothesis_refinement_prompt(
    grammar_hypothesis_t *hyp,
    const char *protocol_name
) {
    char *prompt = (char*)ck_alloc(MAX_HYPOTHESIS_PROMPT);
    memset(prompt, 0, MAX_HYPOTHESIS_PROMPT);
    int offset = 0;
    int written;
    
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "[{\"role\": \"system\", \"content\": \"You are refining protocol grammar hypotheses "
        "based on counterexamples.\"},"
        "{\"role\": \"user\", \"content\": \"");
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Refinement prompt buffer overflow at header\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;

    /* JSON-escape all user-data fields to prevent binary/special char corruption */
    char *esc_proto = json_escape_string(protocol_name, 256);
    char *esc_mtype = json_escape_string(hyp->message_type, 256);
    char *esc_desc  = json_escape_string(hyp->description ? hyp->description : "", 4096);
    char *esc_schema = json_escape_string(hyp->schema_str ? hyp->schema_str : "{}", 8192);

    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "Protocol: %s\\n"
        "Message Type: %s\\n\\n"
        "Current Hypothesis:\\n"
        "Description: %s\\n"
        "Schema: %s\\n\\n",
        esc_proto, esc_mtype, esc_desc, esc_schema);

    ck_free(esc_proto);
    ck_free(esc_mtype);
    ck_free(esc_desc);
    ck_free(esc_schema);

    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Refinement prompt buffer overflow at hypothesis details\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;
    
    /* Counterexamples — already hex-encoded by add_counterexample(),
     * but still JSON-escape them for safety. */
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "Counterexamples (messages that violated the hypothesis):\\n");
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Refinement prompt buffer overflow at counterexamples header\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;
    
    size_t ce_limit = hyp->counterexample_count < MAX_REFINEMENT_COUNTEREXAMPLES ? 
                      hyp->counterexample_count : MAX_REFINEMENT_COUNTEREXAMPLES;
    
    for (size_t i = 0; i < ce_limit; i++) {
        char *esc_ce = json_escape_string(hyp->counterexamples[i], 1024);
        written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
            "%zu. %s\\n", i + 1, esc_ce);
        ck_free(esc_ce);
        if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
            fprintf(stderr, "[!] Refinement prompt buffer overflow at counterexample %zu\n", i);
            break;
        }
        offset += written;
    }
    
    /* Fix-20a: Locality-constrained refinement instruction.
     * Spec: "让它只修一个字段/一条产生式, 限制LLM自由度, 降低幻觉" */
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset,
        "\\nIMPORTANT REFINEMENT RULES:\\n"
        "1. Make the MINIMAL change needed: modify at most ONE constraint, "
        "ONE production rule, or ONE schema field per refinement.\\n"
        "2. Do NOT rewrite the entire hypothesis. Keep all unchanged "
        "fields, rules, and constraints EXACTLY as they are.\\n"
        "3. In your response JSON, include a top-level field "
        "\\\"changed_field\\\": \\\"<name of the single field or rule you modified>\\\" "
        "so the change can be audited.\\n"
        "4. Return the COMPLETE hypothesis in the same JSON format as before, "
        "with only the single targeted fix applied.\\n"
        "5. If no single local fix can accommodate ALL counterexamples, "
        "fix the one that resolves the MOST counterexamples.\\n"
        "\"}]");
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Refinement prompt buffer overflow at footer\n");
        snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset, "\"}]");
    }
    
    return prompt;
}

/* ============================================
 * Hypothesis Generation
 * ============================================ */

int generate_grammar_hypotheses(hypothesis_context_t *ctx, int max_hypotheses) {
    if (!ctx) {
        fprintf(stderr, "[!] generate_grammar_hypotheses: ctx is NULL\n");
        return 0;
    }
    
    fprintf(stderr, "[DEBUG] generate_grammar_hypotheses called with max_hypotheses=%d\n", max_hypotheses);
    fprintf(stderr, "[DEBUG] Context: protocol=%s, pcap_count=%zu, rfc_text=%s\n",
            ctx->protocol_name ? ctx->protocol_name : "NULL",
            ctx->pcap_count,
            ctx->rfc_text ? "present" : "NULL");
    
    char *prompt = construct_hypothesis_generation_prompt(ctx);
    
    if (!prompt) {
        fprintf(stderr, "[!] Failed to construct hypothesis generation prompt (buffer overflow)\n");
        return 0;
    }
    
    fprintf(stderr, "[DEBUG] Prompt constructed successfully, length=%zu bytes\n", strlen(prompt));
    fprintf(stderr, "[DEBUG] Prompt first 500 chars: %.500s\n", prompt);
    fprintf(stderr, "[DEBUG] Prompt last 200 chars: %s\n", 
            strlen(prompt) > 200 ? prompt + strlen(prompt) - 200 : prompt);
    
    // Call LLM with structured prompt
    fprintf(stderr, "[DEBUG] Calling chat_with_llm(model=gpt-4o-mini, tries=3, temperature=0.3)...\n");
    char *response = chat_with_llm(prompt, "gpt-4o-mini", 3, 0.3);  // Low temperature for consistency
    fprintf(stderr, "[DEBUG] chat_with_llm returned: %p\n", (void*)response);
    
    ck_free(prompt);
    
    if (!response) {
        fprintf(stderr, "[!] Failed to generate hypotheses from LLM (NULL response)\n");
        fprintf(stderr, "[!] Possible causes: API key missing, network error, or LLM API failure\n");
        ctx->hypotheses = NULL;
        ctx->hypothesis_count = 0;
        return 0;
    }
    
    fprintf(stderr, "[DEBUG] LLM response length: %zu bytes\n", strlen(response));
    fprintf(stderr, "[DEBUG] LLM response first 200 chars: %.200s\n", response);
    
    // Check for error response from API
    if (strstr(response, "\"error\"") && strstr(response, "\"message\"")) {
        fprintf(stderr, "[!] LLM API returned error response\n");
        fprintf(stderr, "[!] Error details: %.500s\n", response);
        free(response);
        ctx->hypotheses = NULL;
        ctx->hypothesis_count = 0;
        return 0;
    }
    
    // Check for empty or invalid response
    if (strlen(response) < 10) {
        fprintf(stderr, "[!] LLM response too short (likely empty)\n");
        free(response);
        ctx->hypotheses = NULL;
        ctx->hypothesis_count = 0;
        return 0;
    }
    
    // Remove markdown code block markers if present (```json ... ```)
    char *json_start = response;
    if (strncmp(response, "```json", 7) == 0) {
        json_start = strchr(response + 7, '\n');
        if (json_start) {
            json_start++; // Skip the newline
            char *json_end = strstr(json_start, "```");
            if (json_end) {
                *json_end = '\0'; // Truncate at closing ```
            }
        } else {
            json_start = response; // Fallback if no newline found
        }
    } else if (strncmp(response, "```", 3) == 0) {
        json_start = strchr(response + 3, '\n');
        if (json_start) {
            json_start++;
            char *json_end = strstr(json_start, "```");
            if (json_end) {
                *json_end = '\0';
            }
        } else {
            json_start = response;
        }
    }
    
    fprintf(stderr, "[DEBUG] Parsing JSON starting at offset: %td\n", json_start - response);
    fprintf(stderr, "[DEBUG] JSON to parse (first 200 chars): %.200s\n", json_start);
    
    // Parse LLM response into hypotheses
    fprintf(stderr, "[DEBUG] About to call json_tokener_parse...\n");
    json_object *response_json = json_tokener_parse(json_start);
    fprintf(stderr, "[DEBUG] json_tokener_parse returned: %p\n", (void*)response_json);
    
    if (!response_json) {
        fprintf(stderr, "[!] Failed to parse JSON response (json_tokener_parse returned NULL)\n");
        FILE *debug_file = fopen("/tmp/failed_llm_response_parse_null.txt", "w");
        if (debug_file) {
            fprintf(debug_file, "Full response:\n%s\n\nJSON start:\n%s\n", response, json_start);
            fclose(debug_file);
        }
        free(response);
        ctx->hypotheses = NULL;
        ctx->hypothesis_count = 0;
        return 0;
    }
    
    if (!json_object_is_type(response_json, json_type_array)) {
        fprintf(stderr, "[!] Invalid JSON response from LLM (not an array, type=%s)\n",
                json_type_to_name(json_object_get_type(response_json)));
        FILE *debug_file = fopen("/tmp/failed_llm_response_not_array.txt", "w");
        if (debug_file) {
            fprintf(debug_file, "Full response:\n%s\n\nParsed JSON:\n%s\n", 
                   response, json_object_to_json_string_ext(response_json, JSON_C_TO_STRING_PRETTY));
            fclose(debug_file);
        }
        json_object_put(response_json);
        free(response);
        ctx->hypotheses = NULL;
        ctx->hypothesis_count = 0;
        return 0;
    }
    
    fprintf(stderr, "[DEBUG] Successfully parsed JSON array with %zu elements\n", 
           json_object_array_length(response_json));
    
    size_t hyp_count = json_object_array_length(response_json);
    if (hyp_count > (size_t)max_hypotheses) {
        hyp_count = max_hypotheses;
    }
    
    ctx->hypotheses = (grammar_hypothesis_t**)ck_alloc(hyp_count * sizeof(grammar_hypothesis_t*));
    memset(ctx->hypotheses, 0, hyp_count * sizeof(grammar_hypothesis_t*));  // Initialize to NULL
    ctx->hypothesis_count = 0;
    
    for (size_t i = 0; i < hyp_count; i++) {
        json_object *hyp_json = json_object_array_get_idx(response_json, i);
        if (!hyp_json) {
            fprintf(stderr, "[!] Warning: hypothesis %zu is NULL in response array\n", i);
            continue;
        }
        
        // CRITICAL FIX: Copy the JSON string because json_object_to_json_string returns internal buffer
        const char *json_str_ptr = json_object_to_json_string(hyp_json);
        if (!json_str_ptr) {
            fprintf(stderr, "[!] Warning: failed to serialize hypothesis %zu to JSON string\n", i);
            continue;
        }
        char *json_str_copy = strdup(json_str_ptr);
        
        grammar_hypothesis_t *hyp = parse_llm_hypothesis_response(json_str_copy);
        free(json_str_copy);  // Safe to free after parsing
        
        if (hyp && ctx->hypothesis_count < hyp_count) {  // Bounds check
            hyp->hypothesis_id = (unsigned long long)time(NULL) * 1000 + i;
            hyp->created_at = time(NULL);
            hyp->last_updated = time(NULL);
            
            ctx->hypotheses[ctx->hypothesis_count++] = hyp;
            fprintf(stderr, "[DEBUG] Successfully parsed hypothesis %zu (id=%llu)\n", i, hyp->hypothesis_id);
        } else if (hyp && ctx->hypothesis_count >= hyp_count) {
            // Array full but parse succeeded - free the orphaned hypothesis
            fprintf(stderr, "[!] Warning: hypothesis array full, discarding hypothesis %zu\n", i);
            free_grammar_hypothesis(hyp);
        } else {
            fprintf(stderr, "[!] Warning: failed to parse hypothesis %zu\n", i);
        }
    }
    
    fprintf(stderr, "[DEBUG] About to call json_object_put(response_json=%p) at line 640\n", (void*)response_json);
    json_object_put(response_json);
    fprintf(stderr, "[DEBUG] Successfully released response_json\n");
    free(response);
    
    printf("[+] Generated %zu grammar hypotheses\n", ctx->hypothesis_count);
    return ctx->hypothesis_count;
}

grammar_hypothesis_t* parse_llm_hypothesis_response(const char *llm_response) {
    if (!llm_response) {
        fprintf(stderr, "[!] parse_llm_hypothesis_response: NULL response\n");
        return NULL;
    }
    
    fprintf(stderr, "[DEBUG] parse_llm_hypothesis_response: parsing string (len=%zu)\n", strlen(llm_response));
    json_object *jobj = json_tokener_parse(llm_response);
    fprintf(stderr, "[DEBUG] parse_llm_hypothesis_response: jobj=%p\n", (void*)jobj);
    if (!jobj) {
        fprintf(stderr, "[!] parse_llm_hypothesis_response: Failed to parse JSON\n");
        fprintf(stderr, "[!] Response was: %.200s\n", llm_response);
        return NULL;
    }
    
    grammar_hypothesis_t *hyp = (grammar_hypothesis_t*)ck_alloc(sizeof(grammar_hypothesis_t));
    memset(hyp, 0, sizeof(grammar_hypothesis_t));
    
    // Extract message_type (normalised to UPPERCASE so that the
    // dedup check in hypothesis-adapter.c — which uses strcmp via
    // khash strSet — matches the LLM-grammar side that is already
    // uppercase by convention).
    json_object *msg_type_obj;
    if (json_object_object_get_ex(jobj, "message_type", &msg_type_obj)) {
        const char *msg_type_str = json_object_get_string(msg_type_obj);
        if (msg_type_str && strlen(msg_type_str) > 0) {
            hyp->message_type = (char*)ck_strdup((u8*)msg_type_str);
            for (char *p = hyp->message_type; *p; p++) *p = toupper((unsigned char)*p);
        }
    }
    
    // Extract description
    json_object *desc_obj;
    if (json_object_object_get_ex(jobj, "description", &desc_obj)) {
        const char *desc_str = json_object_get_string(desc_obj);
        if (desc_str && strlen(desc_str) > 0) {
            hyp->description = (char*)ck_strdup((u8*)desc_str);
        }
    }
    
    // Extract schema - store as string copy instead of JSON object to avoid ref count issues
    json_object *schema_obj;
    if (json_object_object_get_ex(jobj, "schema", &schema_obj)) {
        // Store schema as a string instead of keeping the JSON object
        const char *schema_str = json_object_to_json_string_ext(schema_obj, JSON_C_TO_STRING_PLAIN);
        if (schema_str) {
            hyp->schema_str = (char*)ck_strdup((u8*)schema_str);
        }
        extract_constraints_from_schema(hyp, schema_obj);
        // Don't store the JSON object itself to avoid reference count issues
        hyp->schema = NULL;
    }
    
    // Extract production_rules
    json_object *rules_obj;
    if (json_object_object_get_ex(jobj, "production_rules", &rules_obj)) {
        if (json_object_is_type(rules_obj, json_type_array)) {
            hyp->rule_count = json_object_array_length(rules_obj);
            hyp->production_rules = (char**)ck_alloc(hyp->rule_count * sizeof(char*));
            memset(hyp->production_rules, 0, hyp->rule_count * sizeof(char*));  // Initialize to NULL
            
            for (size_t i = 0; i < hyp->rule_count; i++) {
                json_object *rule = json_object_array_get_idx(rules_obj, i);
                if (rule) {
                    const char *rule_str = json_object_get_string(rule);
                    if (rule_str) {
                        hyp->production_rules[i] = (char*)ck_strdup((u8*)rule_str);
                    }
                }
            }
        }
    }
    
    // Initialize validation stats
    hyp->parse_success = 0;
    hyp->parse_failure = 0;
    hyp->generated_count = 0;
    hyp->fitness = 0.5;  // Neutral initial fitness
    
    hyp->counterexamples = NULL;
    hyp->counterexample_count = 0;
    
    fprintf(stderr, "[DEBUG] parse_llm_hypothesis_response: about to json_object_put(jobj=%p)\n", (void*)jobj);
    json_object_put(jobj);
    fprintf(stderr, "[DEBUG] parse_llm_hypothesis_response: successfully released jobj\n");
    return hyp;
}

void extract_constraints_from_schema(grammar_hypothesis_t *hyp, json_object *schema) {
    // Fallback string-based extractor: operate on hyp->schema_str when available
    // This avoids direct traversal of json_object internals which showed
    // instability across different json-c usages in this environment.
    if (!hyp || !hyp->schema_str) return;

    const char *s = hyp->schema_str;
    const char *props = strstr(s, "\"properties\"");
    if (!props) return;
    const char *p = strchr(props, '{');
    if (!p) return;
    p++; // enter properties block

    // Heuristic parser: find each "fieldname" : { ... }
    size_t max_constraints = 32;
    hyp->constraints = (field_constraint_t**)ck_alloc(max_constraints * sizeof(field_constraint_t*));
    memset(hyp->constraints, 0, max_constraints * sizeof(field_constraint_t*));
    hyp->constraint_count = 0;

    while (1) {
        // find next field name
        const char *quote = strchr(p, '"');
        if (!quote) break;
        const char *q2 = strchr(quote + 1, '"');
        if (!q2) break;
        size_t fnlen = q2 - quote - 1;
        char field_name[128];
        if (fnlen >= sizeof(field_name)) break;
        memcpy(field_name, quote + 1, fnlen);
        field_name[fnlen] = '\0';

        // move to the following '{'
        const char *brace = strchr(q2, '{');
        if (!brace) break;
        const char *block = brace + 1;
        // find the end of this block (simple brace matching)
        int depth = 1;
        const char *it = block;
        while (*it && depth > 0) {
            if (*it == '{') depth++; else if (*it == '}') depth--;
            it++;
        }
        if (depth != 0) break;
        size_t block_len = (size_t)(it - block - 1);
        char *block_buf = (char*)ck_alloc(block_len + 1);
        memcpy(block_buf, block, block_len);
        block_buf[block_len] = '\0';

        // search for minLength / maxLength
        const char *minp = strstr(block_buf, "minLength");
        const char *maxp = strstr(block_buf, "maxLength");
        if (minp || maxp) {
            field_constraint_t *constraint = (field_constraint_t*)ck_alloc(sizeof(field_constraint_t));
            memset(constraint, 0, sizeof(field_constraint_t));
            constraint->type = CONSTRAINT_LENGTH;
            constraint->field_name = (char*)ck_strdup((u8*)field_name);
            constraint->data.length.min = 0;
            constraint->data.length.max = SIZE_MAX;

            if (minp) {
                long long v = 0;
                // Simple digit scanner for minLength value
                const char *d = minp;
                while (*d && !isdigit((unsigned char)*d)) d++;
                if (*d) v = strtoll(d, NULL, 10);
                constraint->data.length.min = (size_t)(v > 0 ? v : 0);
            }
            if (maxp) {
                long long v = 0;
                // Simple digit scanner for maxLength value
                const char *d = maxp;
                while (*d && !isdigit((unsigned char)*d)) d++;
                if (*d) v = strtoll(d, NULL, 10);
                constraint->data.length.max = (size_t)(v > 0 ? v : SIZE_MAX);
            }

            if (hyp->constraint_count < max_constraints) {
                hyp->constraints[hyp->constraint_count++] = constraint;
            } else {
                ck_free(constraint->field_name);
                ck_free(constraint);
            }
        }

        // search for pattern
        const char *patternp = strstr(block_buf, "\"pattern\"");
        if (patternp) {
            const char *start = strchr(patternp, '"');
            if (start) {
                start = strchr(start+1, '"');
                if (start) {
                    start++;
                    const char *end = strchr(start, '"');
                    if (end) {
                        size_t plen = end - start;
                        field_constraint_t *constraint = (field_constraint_t*)ck_alloc(sizeof(field_constraint_t));
                        memset(constraint, 0, sizeof(field_constraint_t));
                        constraint->type = CONSTRAINT_REGEX;
                        constraint->field_name = (char*)ck_strdup((u8*)field_name);
                        constraint->data.regex.pattern = (char*)ck_alloc(plen + 1);
                        memcpy(constraint->data.regex.pattern, start, plen);
                        constraint->data.regex.pattern[plen] = '\0';
                        if (hyp->constraint_count < max_constraints) {
                            hyp->constraints[hyp->constraint_count++] = constraint;
                        } else {
                            ck_free(constraint->data.regex.pattern);
                            ck_free(constraint->field_name);
                            ck_free(constraint);
                        }
                    }
                }
            }
        }

        /* ── Gap-2 fix: Extract "enum" constraint ──
         * JSON Schema: "enum": ["GET", "POST", "PUT", ...]
         * We parse the array of quoted strings and create a
         * CONSTRAINT_ENUM with values/count. */
        const char *enump = strstr(block_buf, "\"enum\"");
        if (enump && hyp->constraint_count < max_constraints) {
            const char *arr_start = strchr(enump + 5, '[');
            if (arr_start) {
                const char *arr_end = strchr(arr_start, ']');
                if (arr_end) {
                    /* Count and extract quoted values inside [...] */
                    char **vals = NULL;
                    size_t val_cnt = 0;
                    const char *cur = arr_start + 1;
                    while (cur < arr_end && val_cnt < 32) {
                        const char *q1 = memchr(cur, '"', arr_end - cur);
                        if (!q1) break;
                        q1++;
                        const char *q2 = memchr(q1, '"', arr_end - q1);
                        if (!q2) break;
                        size_t vlen = q2 - q1;
                        if (vlen > 0 && vlen < 256) {
                            vals = (char **)ck_realloc(
                                vals, (val_cnt + 1) * sizeof(char *));
                            vals[val_cnt] = (char *)ck_alloc(vlen + 1);
                            memcpy(vals[val_cnt], q1, vlen);
                            vals[val_cnt][vlen] = '\0';
                            val_cnt++;
                        }
                        cur = q2 + 1;
                    }
                    if (val_cnt > 0) {
                        field_constraint_t *c = (field_constraint_t *)
                            ck_alloc(sizeof(field_constraint_t));
                        memset(c, 0, sizeof(field_constraint_t));
                        c->type = CONSTRAINT_ENUM;
                        c->field_name = (char *)ck_strdup((u8 *)field_name);
                        c->data.enumeration.values = vals;
                        c->data.enumeration.count  = val_cnt;
                        hyp->constraints[hyp->constraint_count++] = c;
                    } else if (vals) {
                        ck_free(vals);
                    }
                }
            }
        }

        /* ── Gap-2 fix: Extract "minimum" / "maximum" constraint ──
         * JSON Schema: "minimum": 0, "maximum": 65535
         * Creates a CONSTRAINT_NUMERIC with [min, max] range. */
        {
            const char *minp_num = strstr(block_buf, "\"minimum\"");
            const char *maxp_num = strstr(block_buf, "\"maximum\"");
            if ((minp_num || maxp_num) &&
                hyp->constraint_count < max_constraints) {
                field_constraint_t *c = (field_constraint_t *)
                    ck_alloc(sizeof(field_constraint_t));
                memset(c, 0, sizeof(field_constraint_t));
                c->type = CONSTRAINT_NUMERIC;
                c->field_name = (char *)ck_strdup((u8 *)field_name);
                c->data.numeric.min = LLONG_MIN;
                c->data.numeric.max = LLONG_MAX;

                if (minp_num) {
                    const char *d = minp_num + 9; /* skip "minimum" */
                    while (*d && *d != ':') d++;
                    if (*d == ':') d++;
                    while (*d && (*d == ' ' || *d == '\t')) d++;
                    if (*d == '-' || isdigit((unsigned char)*d))
                        c->data.numeric.min = strtoll(d, NULL, 10);
                }
                if (maxp_num) {
                    const char *d = maxp_num + 9; /* skip "maximum" */
                    while (*d && *d != ':') d++;
                    if (*d == ':') d++;
                    while (*d && (*d == ' ' || *d == '\t')) d++;
                    if (*d == '-' || isdigit((unsigned char)*d))
                        c->data.numeric.max = strtoll(d, NULL, 10);
                }
                hyp->constraints[hyp->constraint_count++] = c;
            }
        }

        ck_free(block_buf);
        p = it; // advance
    }

    /* ── Gap-3 fix: Extract "required" fields as CONSTRAINT_DEPENDENCY ──
     * JSON Schema: "required": ["field1", "field2", ...]
     * This keyword is at the schema level (sibling of "properties"),
     * so we scan the original schema_str, not individual field blocks.
     * Each required field becomes a CONSTRAINT_DEPENDENCY with
     * condition="required", enabling message-level presence checks. */
    {
        const char *reqp = strstr(s, "\"required\"");
        if (reqp) {
            const char *arr = strchr(reqp + 10, '[');
            if (arr) {
                const char *arr_e = strchr(arr, ']');
                if (arr_e) {
                    const char *cur = arr + 1;
                    while (cur < arr_e && hyp->constraint_count < max_constraints) {
                        const char *q1 = memchr(cur, '"', arr_e - cur);
                        if (!q1) break;
                        q1++;
                        const char *q2 = memchr(q1, '"', arr_e - q1);
                        if (!q2) break;
                        size_t nlen = q2 - q1;
                        if (nlen > 0 && nlen < 128) {
                            field_constraint_t *c = (field_constraint_t *)
                                ck_alloc(sizeof(field_constraint_t));
                            memset(c, 0, sizeof(field_constraint_t));
                            c->type = CONSTRAINT_DEPENDENCY;
                            c->field_name = (char *)ck_strdup((u8 *)"_schema");
                            c->data.dependency.target_field =
                                (char *)ck_alloc(nlen + 1);
                            memcpy(c->data.dependency.target_field, q1, nlen);
                            c->data.dependency.target_field[nlen] = '\0';
                            c->data.dependency.condition =
                                (char *)ck_strdup((u8 *)"required");
                            hyp->constraints[hyp->constraint_count++] = c;
                        }
                        cur = q2 + 1;
                    }
                }
            }
        }
    }
}

/* ============================================
 * Validation Functions
 * ============================================ */

/* Fix-20b: Constraint-type → human-readable label for counterexample reasons */
static const char* constraint_type_name(constraint_type_t t) {
    switch (t) {
        case CONSTRAINT_LENGTH:     return "LENGTH";
        case CONSTRAINT_ENUM:       return "ENUM";
        case CONSTRAINT_REGEX:      return "REGEX";
        case CONSTRAINT_DEPENDENCY: return "DEPENDENCY";
        case CONSTRAINT_NUMERIC:    return "NUMERIC";
        default:                    return "UNKNOWN";
    }
}

/* Fix-20b: Collect detailed violation reasons for counterexample enrichment.
 * Returns a heap-allocated string like:
 *   "Failed LENGTH(command,expect=4-32,got=130), ENUM(method)"
 * Caller must ck_free() the result.  Returns NULL if all constraints pass.
 * This does NOT update constraint stats — call validate_message_against_hypothesis()
 * for that; this is a read-only diagnostic. */
char* collect_violation_details(
    grammar_hypothesis_t *hyp,
    const unsigned char *message,
    size_t len
) {
    if (!hyp || !message || hyp->constraint_count == 0)
        return NULL;

    char buf[2048];
    int off = 0;
    int violation_count = 0;

    off += snprintf(buf + off, sizeof(buf) - off, "Failed ");

    for (size_t i = 0; i < hyp->constraint_count && off < (int)sizeof(buf) - 80; i++) {
        field_constraint_t *c = hyp->constraints[i];

        if (check_constraint(c, (const char*)message, len))
            continue;  /* This constraint passed */

        if (violation_count > 0)
            off += snprintf(buf + off, sizeof(buf) - off, ", ");

        const char *fname = c->field_name ? c->field_name : "?";

        switch (c->type) {
            case CONSTRAINT_LENGTH:
                off += snprintf(buf + off, sizeof(buf) - off,
                    "%s(%s,expect=%zu-%zu,got=%zu)",
                    constraint_type_name(c->type), fname,
                    c->data.length.min, c->data.length.max, len);
                break;
            case CONSTRAINT_ENUM:
                off += snprintf(buf + off, sizeof(buf) - off,
                    "%s(%s,%zu values)", constraint_type_name(c->type),
                    fname, c->data.enumeration.count);
                break;
            case CONSTRAINT_REGEX:
                off += snprintf(buf + off, sizeof(buf) - off,
                    "%s(%s,pat=%.30s)", constraint_type_name(c->type),
                    fname,
                    c->data.regex.pattern ? c->data.regex.pattern : "null");
                break;
            case CONSTRAINT_NUMERIC:
                off += snprintf(buf + off, sizeof(buf) - off,
                    "%s(%s,range=%lld-%lld)",
                    constraint_type_name(c->type), fname,
                    c->data.numeric.min, c->data.numeric.max);
                break;
            case CONSTRAINT_DEPENDENCY:
                off += snprintf(buf + off, sizeof(buf) - off,
                    "%s(%s->%s)", constraint_type_name(c->type),
                    fname,
                    c->data.dependency.target_field ?
                        c->data.dependency.target_field : "?");
                break;
            default:
                off += snprintf(buf + off, sizeof(buf) - off,
                    "%s(%s)", constraint_type_name(c->type), fname);
                break;
        }

        violation_count++;

        /* Cap at 5 violations to keep counterexample concise */
        if (violation_count >= 5) {
            off += snprintf(buf + off, sizeof(buf) - off, ", ...");
            break;
        }
    }

    if (violation_count == 0)
        return NULL;

    return (char*)ck_strdup((u8*)buf);
}

int validate_message_against_hypothesis(
    grammar_hypothesis_t *hyp,
    const unsigned char *message,
    size_t len
) {
    if (!hyp || !message) {
        return 0;  // Invalid parameters
    }
    
    // Simple validation: check if message can be parsed according to schema
    // In a full implementation, this would parse the message and validate each field
    
    int valid = 1;
    
    // For now, we do basic validation on constraints
    for (size_t i = 0; i < hyp->constraint_count; i++) {
        field_constraint_t *c = hyp->constraints[i];
        c->validations++;
        
        // Simplified validation logic
        // In practice, you'd parse the message and extract field values
        if (!check_constraint(c, (const char*)message, len)) {
            c->violations++;
            valid = 0;
        }
        
        // Update constraint confidence
        if (c->validations > 0) {
            c->confidence = 1.0 - ((double)c->violations / (double)c->validations);
        }
    }
    
    if (valid) {
        hyp->parse_success++;
    } else {
        hyp->parse_failure++;
    }
    
    // Update fitness (both full recalculation and dynamic adjustment)
    hyp->fitness = calculate_hypothesis_fitness(hyp);
    update_hypothesis_fitness_dynamic(hyp, valid);
    
    return valid;
}

/* ============================================
 * Fix-15: Constraint check — all types implemented.
 *
 * CONSTRAINT_LENGTH:     min/max byte-length check          ✅ (was working)
 * CONSTRAINT_ENUM:       value \u2208 allowed set, with length   ✅ (fixed)
 * CONSTRAINT_REGEX:      PCRE2 compile-and-match            ✅ (was placeholder)
 * CONSTRAINT_NUMERIC:    strtoll range [min, max]           ✅ (was placeholder)
 * CONSTRAINT_DEPENDENCY: logged, soft-pass (cross-field     ✅ (best-effort)
 *                        deps need message-level context)
 *
 * Performance note: these only run on the sampled path (~50/s),
 * so per-call PCRE2 compile is acceptable (~5 µs each).
 * ============================================ */
int check_constraint(
    field_constraint_t *constraint,
    const char *field_value,
    size_t value_len
) {
    switch (constraint->type) {

        case CONSTRAINT_LENGTH:
            return value_len >= constraint->data.length.min &&
                   value_len <= constraint->data.length.max;

        case CONSTRAINT_ENUM:
            for (size_t i = 0; i < constraint->data.enumeration.count; i++) {
                const char *ev = constraint->data.enumeration.values[i];
                size_t ev_len = strlen(ev);
                /* Match exact length AND content (case-insensitive for
                 * protocol keywords like "GET" vs "get"). */
                if (ev_len == value_len &&
                    strncasecmp(field_value, ev, value_len) == 0) {
                    return 1;
                }
            }
            return 0;

        case CONSTRAINT_REGEX: {
            /* PCRE2 compile-and-match.  Tolerates NULL/empty patterns
             * (treated as unconditional pass). */
            if (!constraint->data.regex.pattern ||
                constraint->data.regex.pattern[0] == '\0')
                return 1;

            int errcode;
            PCRE2_SIZE erroffset;
            pcre2_code *re = pcre2_compile(
                (PCRE2_SPTR)constraint->data.regex.pattern,
                PCRE2_ZERO_TERMINATED,
                PCRE2_CASELESS | PCRE2_DOTALL,
                &errcode, &erroffset, NULL);

            if (!re) {
                /* Bad pattern → can't validate → soft-pass, but log once */
                static int regex_err_logged = 0;
                if (!regex_err_logged) {
                    fprintf(stderr,
                            "[hypothesis] WARNING: bad regex pattern '%.60s' "
                            "(err=%d, offset=%zu)\n",
                            constraint->data.regex.pattern,
                            errcode, (size_t)erroffset);
                    regex_err_logged = 1;
                }
                return 1;  /* Soft-pass on bad pattern */
            }

            pcre2_match_data *md =
                pcre2_match_data_create_from_pattern(re, NULL);
            int rc = pcre2_match(re, (PCRE2_SPTR)field_value,
                                 (PCRE2_SIZE)value_len,
                                 0, 0, md, NULL);
            pcre2_match_data_free(md);
            pcre2_code_free(re);

            return rc >= 0 ? 1 : 0;  /* rc >= 0 → match found */
        }

        case CONSTRAINT_NUMERIC: {
            /* Parse field_value as decimal integer, check [min, max].
             * Non-numeric values → fail (not a valid number). */
            char tmp[64];
            size_t cpy = value_len < sizeof(tmp) - 1 ? value_len : sizeof(tmp) - 1;
            memcpy(tmp, field_value, cpy);
            tmp[cpy] = '\0';

            char *endp = NULL;
            errno = 0;
            long long val = strtoll(tmp, &endp, 10);

            /* Must consume at least one digit, no overflow */
            if (endp == tmp || errno == ERANGE)
                return 0;

            return val >= constraint->data.numeric.min &&
                   val <= constraint->data.numeric.max;
        }

        case CONSTRAINT_DEPENDENCY:
            /* ── Gap-3 fix: Message-level field presence check ──
             * validate_message_against_hypothesis() passes the FULL message
             * as (field_value, value_len), so we can do substring search for
             * the target_field name.
             *
             * Semantics:
             *   condition == "required"  → target_field must appear in msg
             *   condition == "absent"    → target_field must NOT appear
             *   other / NULL             → soft-pass (future extensibility)
             *
             * This works well for text protocols where field names appear
             * literally (e.g., "Content-Length:", "Host:", "USER ").
             * For binary protocols the LLM won't generate "required"
             * constraints (it generates length/numeric instead), so
             * the check gracefully degrades to soft-pass. */
            if (constraint->data.dependency.target_field &&
                constraint->data.dependency.condition) {
                const char *target = constraint->data.dependency.target_field;
                size_t tlen = strlen(target);
                if (tlen == 0 || tlen > value_len) return 1; /* degenerate */

                /* Case-insensitive substring search in message */
                int found = 0;
                for (size_t i = 0; i + tlen <= value_len; i++) {
                    if (strncasecmp(field_value + i, target, tlen) == 0) {
                        found = 1;
                        break;
                    }
                }

                if (strcmp(constraint->data.dependency.condition,
                           "required") == 0) {
                    return found;  /* must be present */
                }
                if (strcmp(constraint->data.dependency.condition,
                           "absent") == 0) {
                    return !found; /* must NOT be present */
                }
            }
            return 1;  /* unknown condition → soft-pass */

        default:
            return 1;
    }
}

double calculate_hypothesis_fitness(grammar_hypothesis_t *hyp) {
    if (hyp->parse_success + hyp->parse_failure == 0) {
        return 0.5;  // Neutral fitness with no data
    }
    
    // Parse success rate
    double parse_rate = (double)hyp->parse_success / 
                       (double)(hyp->parse_success + hyp->parse_failure);
    
    // Average constraint confidence
    double avg_confidence = 0.0;
    if (hyp->constraint_count > 0) {
        for (size_t i = 0; i < hyp->constraint_count; i++) {
            avg_confidence += hyp->constraints[i]->confidence;
        }
        avg_confidence /= hyp->constraint_count;
    } else {
        avg_confidence = 1.0;
    }
    
    // Combined fitness: 70% parse rate, 30% constraint confidence
    return 0.7 * parse_rate + 0.3 * avg_confidence;
}

/* ============================================
 * Dynamic Fitness Update (Incremental)
 * ============================================ */

void update_hypothesis_fitness_dynamic(grammar_hypothesis_t *hyp, int is_success) {
    if (!hyp) return;
    
    // Incremental fitness adjustment based on validation result
    // Success: increase fitness by 0.01 (capped at 1.0)
    // Failure: decrease fitness by 0.005 (floored at 0.0)
    if (is_success) {
        hyp->fitness += 0.01;
        if (hyp->fitness > 1.0) hyp->fitness = 1.0;
    } else {
        hyp->fitness -= 0.005;
        if (hyp->fitness < 0.0) hyp->fitness = 0.0;
    }
    
    // Log significant fitness changes
    if (hyp->parse_success + hyp->parse_failure > 0 && 
        (hyp->parse_success + hyp->parse_failure) % 100 == 0) {
        fprintf(stderr, "[hypothesis] %s: fitness=%.3f (success=%u, failure=%u)\n",
                hyp->message_type, hyp->fitness, hyp->parse_success, hyp->parse_failure);
    }
}

/* ============================================
 * Counterexample & Refinement
 * ============================================ */

/* ============================================
 * Field-level counterexample minimization for text protocols.
 *
 * Given a failing message, split it by CRLF into "lines" (protocol fields),
 * then iteratively try removing each line.  If the message STILL fails
 * validation after removing a line, that line is not needed to reproduce
 * the violation — drop it.  The result is the minimal set of lines that
 * together still violate the hypothesis.
 *
 * This is a 1-minimal delta-debugging variant:
 *   for each line i in [0, N):
 *     reconstruct message without line i
 *     if still invalid → mark line i as removable
 *   remove all removable lines
 *
 * Worst case: N lines × C constraints ≈ N×C check_constraint() calls.
 * With typical text protocol messages (5-15 lines) and ≤5 constraints,
 * this is ~75 calls — microseconds.
 *
 * Binary protocols are NOT minimized (fields are not line-delimited).
 *
 * Returns a NEW heap-allocated buffer with the minimized message and
 * sets *out_len.  Caller must ck_free().  Returns NULL if minimization
 * is not applicable (binary, too short, etc.)
 * ============================================ */
static unsigned char* minimize_counterexample_fields(
    grammar_hypothesis_t *hyp,
    const unsigned char *message,
    size_t len,
    size_t *out_len)
{
    *out_len = 0;

    /* Only minimize text protocol messages with CRLF structure */
    if (!hyp || !message || len < 4) return NULL;

    /* Quick check: does it contain at least one \r\n? */
    int has_crlf = 0;
    for (size_t i = 0; i + 1 < len; i++) {
        if (message[i] == '\r' && message[i+1] == '\n') { has_crlf = 1; break; }
    }
    if (!has_crlf) return NULL;

    /* Split by \r\n into lines (keep each line INCLUDING its \r\n) */
    #define MAX_MINIMIZE_LINES 32
    struct { size_t start; size_t len; } lines[MAX_MINIMIZE_LINES];
    int nlines = 0;
    size_t pos = 0;
    while (pos < len && nlines < MAX_MINIMIZE_LINES) {
        size_t line_start = pos;
        /* Find next \r\n */
        size_t end = pos;
        while (end + 1 < len && !(message[end] == '\r' && message[end+1] == '\n'))
            end++;
        if (end + 1 < len) end += 2; /* include \r\n */
        else end = len;              /* last line without \r\n */
        lines[nlines].start = line_start;
        lines[nlines].len = end - line_start;
        nlines++;
        pos = end;
    }

    if (nlines <= 1) return NULL;  /* single line, nothing to minimize */

    /* For each line, test if removing it still causes validation failure */
    u8 keep[MAX_MINIMIZE_LINES];
    memset(keep, 1, sizeof(keep));

    for (int i = 0; i < nlines; i++) {
        /* Build message without line i */
        size_t new_len = 0;
        for (int j = 0; j < nlines; j++) {
            if (j != i && keep[j]) new_len += lines[j].len;
        }
        if (new_len < 2) continue; /* too short to be valid probe */

        unsigned char *probe = (unsigned char*)ck_alloc(new_len);
        size_t off = 0;
        for (int j = 0; j < nlines; j++) {
            if (j != i && keep[j]) {
                memcpy(probe + off, message + lines[j].start, lines[j].len);
                off += lines[j].len;
            }
        }

        /* Check: does removing line i still fail? */
        int still_invalid = !validate_message_against_hypothesis(hyp, probe, new_len);
        ck_free(probe);

        if (still_invalid) {
            keep[i] = 0;  /* line i is not needed for the violation */
        }
    }

    /* Count how many lines we kept */
    int kept = 0;
    for (int i = 0; i < nlines; i++) if (keep[i]) kept++;

    /* If we didn't remove anything, minimization didn't help */
    if (kept == nlines) return NULL;

    /* Build minimized message */
    size_t min_len = 0;
    for (int i = 0; i < nlines; i++) if (keep[i]) min_len += lines[i].len;

    unsigned char *result = (unsigned char*)ck_alloc(min_len);
    size_t roff = 0;
    for (int i = 0; i < nlines; i++) {
        if (keep[i]) {
            memcpy(result + roff, message + lines[i].start, lines[i].len);
            roff += lines[i].len;
        }
    }

    *out_len = min_len;
    fprintf(stderr, "[minimize-ce] %s: %d/%d lines kept (%zu→%zu bytes)\n",
            hyp->message_type ? hyp->message_type : "?",
            kept, nlines, len, min_len);
    return result;
    #undef MAX_MINIMIZE_LINES
}

void add_counterexample(
    grammar_hypothesis_t *hyp,
    const unsigned char *message,
    size_t len,
    const char *error_reason
) {
    /* Cap counterexample storage to avoid unbounded memory growth */
    if (hyp->counterexample_count >= 200) return;

    /* ---- Field-level minimization for text protocols ----
     * Try to reduce the message to the minimal set of CRLF-delimited
     * lines that still violate the hypothesis.  If successful, the
     * minimized message replaces the original for storage, making
     * the refinement prompt more precise and reducing LLM confusion. */
    const unsigned char *store_msg = message;
    size_t store_len = len;
    unsigned char *minimized = NULL;
    size_t min_len = 0;

    minimized = minimize_counterexample_fields(hyp, message, len, &min_len);
    if (minimized && min_len > 0) {
        store_msg = minimized;
        store_len = min_len;
    }

    /* Limit individual counterexample to 128 bytes of hex (= 64 raw bytes)
     * to keep refinement prompts reasonably sized. */
    size_t hex_bytes = store_len > 64 ? 64 : store_len;

    /* Hex-encode the (possibly minimized) message so binary data is JSON-safe.
     * Format:  HEX[0a1b2c...] [Reason: ...] */
    size_t ce_size = 4 + hex_bytes * 2 + 1 + 12 + strlen(error_reason) + 2;
    char *ce = (char*)ck_alloc(ce_size);
    int off = 0;
    off += snprintf(ce + off, ce_size - off, "HEX[");
    for (size_t i = 0; i < hex_bytes && (size_t)off < ce_size - 10; i++)
        off += snprintf(ce + off, ce_size - off, "%02x", store_msg[i]);
    off += snprintf(ce + off, ce_size - off, "] [Reason: %s]", error_reason);

    hyp->counterexamples = (char**)ck_realloc(hyp->counterexamples,
                                      (hyp->counterexample_count + 1) * sizeof(char*));
    hyp->counterexamples[hyp->counterexample_count++] = ce;

    log_hypothesis_event(hyp, "COUNTEREXAMPLE", error_reason);

    if (minimized) ck_free(minimized);
}

int refine_hypothesis_with_counterexamples(
    hypothesis_context_t *ctx,
    grammar_hypothesis_t *hyp
) {
    if (hyp->counterexample_count == 0) {
        return 0;  // Nothing to refine
    }
    
    char *prompt = construct_hypothesis_refinement_prompt(hyp, ctx->protocol_name);
    
    char *response = chat_with_llm(prompt, "gpt-4o-mini", 3, 0.3);
    ck_free(prompt);
    
    if (!response) {
        fprintf(stderr, "[!] Failed to refine hypothesis from LLM\n");
        return 0;
    }
    
    // Parse refined hypothesis
    grammar_hypothesis_t *refined_hyp = parse_llm_hypothesis_response(response);
    free(response);
    
    if (!refined_hyp) {
        fprintf(stderr, "[!] Failed to parse refined hypothesis\n");
        return 0;
    }
    
    /* Fix-20c: Diff-based selective merge — only overwrite fields that
     * actually changed.  Log every changed field so the refinement is
     * auditable and LLM hallucination (wholesale rewrite) is detectable.
     *
     * Spec: "只允许局部 patch" — if the LLM changed >2 major fields we
     * still accept (prompt already constrains to 1), but we warn. */
    int fields_changed = 0;
    char change_log[2048];
    int cl_off = 0;

    /* --- message_type: should almost never change --- */
    if (refined_hyp->message_type && hyp->message_type &&
        strcmp(refined_hyp->message_type, hyp->message_type) != 0) {
        cl_off += snprintf(change_log + cl_off, sizeof(change_log) - cl_off,
            "message_type(%s->%s) ", hyp->message_type, refined_hyp->message_type);
        ck_free(hyp->message_type);
        hyp->message_type = refined_hyp->message_type;
        refined_hyp->message_type = NULL;
        fields_changed++;
    } else {
        /* Keep original, discard refined copy */
        if (refined_hyp->message_type) ck_free(refined_hyp->message_type);
        refined_hyp->message_type = NULL;
    }

    /* --- description: cosmetic, always accept --- */
    if (refined_hyp->description) {
        int desc_changed = !hyp->description ||
            strcmp(refined_hyp->description, hyp->description) != 0;
        if (desc_changed) {
            cl_off += snprintf(change_log + cl_off, sizeof(change_log) - cl_off,
                "description ");
            fields_changed++;
        }
        ck_free(hyp->description);
        hyp->description = refined_hyp->description;
        refined_hyp->description = NULL;
    }

    /* --- schema / schema_str --- */
    {
        int schema_changed = 0;
        if (refined_hyp->schema_str && hyp->schema_str) {
            schema_changed = strcmp(refined_hyp->schema_str, hyp->schema_str) != 0;
        } else if (refined_hyp->schema_str || hyp->schema_str) {
            schema_changed = 1;
        }

        if (schema_changed) {
            cl_off += snprintf(change_log + cl_off, sizeof(change_log) - cl_off,
                "schema ");
            fields_changed++;

            if (hyp->schema) json_object_put(hyp->schema);
            hyp->schema = refined_hyp->schema;
            refined_hyp->schema = NULL;

            ck_free(hyp->schema_str);
            hyp->schema_str = refined_hyp->schema_str;
            refined_hyp->schema_str = NULL;
        } else {
            /* Keep original */
            if (refined_hyp->schema) { json_object_put(refined_hyp->schema); refined_hyp->schema = NULL; }
            if (refined_hyp->schema_str) { ck_free(refined_hyp->schema_str); refined_hyp->schema_str = NULL; }
        }
    }

    /* --- production_rules --- */
    {
        int rules_changed = (refined_hyp->rule_count != hyp->rule_count);
        if (!rules_changed) {
            for (size_t i = 0; i < hyp->rule_count; i++) {
                if (strcmp(hyp->production_rules[i],
                           refined_hyp->production_rules[i]) != 0) {
                    rules_changed = 1;
                    break;
                }
            }
        }

        if (rules_changed) {
            cl_off += snprintf(change_log + cl_off, sizeof(change_log) - cl_off,
                "production_rules(%zu->%zu) ", hyp->rule_count, refined_hyp->rule_count);
            fields_changed++;

            for (size_t i = 0; i < hyp->rule_count; i++)
                ck_free(hyp->production_rules[i]);
            ck_free(hyp->production_rules);
            hyp->production_rules = refined_hyp->production_rules;
            hyp->rule_count = refined_hyp->rule_count;
            refined_hyp->production_rules = NULL;
            refined_hyp->rule_count = 0;
        } else {
            for (size_t i = 0; i < refined_hyp->rule_count; i++)
                ck_free(refined_hyp->production_rules[i]);
            ck_free(refined_hyp->production_rules);
            refined_hyp->production_rules = NULL;
            refined_hyp->rule_count = 0;
        }
    }

    /* --- constraints: always accept (this is the primary refinement target) --- */
    {
        int constraints_changed = (refined_hyp->constraint_count != hyp->constraint_count);
        if (!constraints_changed) {
            /* Shallow check: compare field names and types */
            for (size_t i = 0; i < hyp->constraint_count; i++) {
                field_constraint_t *a = hyp->constraints[i];
                field_constraint_t *b = refined_hyp->constraints[i];
                if (a->type != b->type ||
                    !a->field_name || !b->field_name ||
                    strcmp(a->field_name, b->field_name) != 0) {
                    constraints_changed = 1;
                    break;
                }
            }
        }

        if (constraints_changed) {
            cl_off += snprintf(change_log + cl_off, sizeof(change_log) - cl_off,
                "constraints(%zu->%zu) ", hyp->constraint_count,
                refined_hyp->constraint_count);
            fields_changed++;

            /* Free old constraints with nested data */
            for (size_t i = 0; i < hyp->constraint_count; i++) {
                field_constraint_t *c = hyp->constraints[i];
                ck_free(c->field_name);
                if (c->type == CONSTRAINT_ENUM) {
                    for (size_t j = 0; j < c->data.enumeration.count; j++)
                        ck_free(c->data.enumeration.values[j]);
                    ck_free(c->data.enumeration.values);
                } else if (c->type == CONSTRAINT_REGEX) {
                    ck_free(c->data.regex.pattern);
                } else if (c->type == CONSTRAINT_DEPENDENCY) {
                    ck_free(c->data.dependency.target_field);
                    ck_free(c->data.dependency.condition);
                }
                ck_free(c);
            }
            ck_free(hyp->constraints);

            hyp->constraints = refined_hyp->constraints;
            hyp->constraint_count = refined_hyp->constraint_count;
            refined_hyp->constraints = NULL;
            refined_hyp->constraint_count = 0;
        } else {
            /* Constraints unchanged — free refined copy */
            for (size_t i = 0; i < refined_hyp->constraint_count; i++) {
                field_constraint_t *c = refined_hyp->constraints[i];
                ck_free(c->field_name);
                if (c->type == CONSTRAINT_ENUM) {
                    for (size_t j = 0; j < c->data.enumeration.count; j++)
                        ck_free(c->data.enumeration.values[j]);
                    ck_free(c->data.enumeration.values);
                } else if (c->type == CONSTRAINT_REGEX) {
                    ck_free(c->data.regex.pattern);
                } else if (c->type == CONSTRAINT_DEPENDENCY) {
                    ck_free(c->data.dependency.target_field);
                    ck_free(c->data.dependency.condition);
                }
                ck_free(c);
            }
            ck_free(refined_hyp->constraints);
            refined_hyp->constraints = NULL;
            refined_hyp->constraint_count = 0;
        }
    }

    /* Warn if LLM changed too many fields (locality violation) */
    if (fields_changed > 2) {
        fprintf(stderr,
            "[!] Fix-20c WARNING: LLM changed %d fields (expected ≤2): %s\n",
            fields_changed, change_log);
    }
    
    /* Log the diff for auditability */
    if (fields_changed > 0) {
        fprintf(stderr, "[hypothesis-refine] Diff: %s(%d field%s)\n",
                change_log, fields_changed, fields_changed > 1 ? "s" : "");
    } else {
        fprintf(stderr, "[hypothesis-refine] No field changes detected "
                "(LLM returned identical hypothesis)\n");
    }
    
    // Clear counterexamples after refinement
    for (size_t i = 0; i < hyp->counterexample_count; i++) {
        ck_free(hyp->counterexamples[i]);
    }
    ck_free(hyp->counterexamples);
    hyp->counterexamples = NULL;
    hyp->counterexample_count = 0;
    
    hyp->last_updated = time(NULL);
    ctx->refinement_iterations++;
    
    free_grammar_hypothesis(refined_hyp);
    
    log_hypothesis_event(hyp, "REFINED", "Hypothesis updated from counterexamples");
    printf("[+] Refined hypothesis for %s (iteration %u)\n", 
           hyp->message_type, ctx->refinement_iterations);
    
    return 1;
}

grammar_hypothesis_t* select_best_hypothesis(
    hypothesis_context_t *ctx,
    const char *message_type
) {
    grammar_hypothesis_t *best = NULL;
    double best_fitness = -1.0;
    
    for (size_t i = 0; i < ctx->hypothesis_count; i++) {
        grammar_hypothesis_t *hyp = ctx->hypotheses[i];
        
        if (strcmp(hyp->message_type, message_type) == 0) {
            if (hyp->fitness > best_fitness) {
                best_fitness = hyp->fitness;
                best = hyp;
            }
        }
    }
    
    return best;
}

/* ============================================
 * Persistence Functions
 * ============================================ */

int save_hypothesis_to_file(grammar_hypothesis_t *hyp, const char *filepath) {
    // Defensive NULL checks
    if (!hyp) {
        fprintf(stderr, "[!] save_hypothesis_to_file: hyp is NULL\n");
        return 0;
    }
    if (!filepath) {
        fprintf(stderr, "[!] save_hypothesis_to_file: filepath is NULL\n");
        return 0;
    }
    
    // CRITICAL FIX: Ensure directory exists before writing
    char *dir_path = strdup(filepath);
    char *last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        // Create directory with mkdir -p behavior
        char mkdir_cmd[2048];
        snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p \"%s\" 2>/dev/null", dir_path);
        int mkdir_result = system(mkdir_cmd);
        if (mkdir_result == 0) {
            fprintf(stderr, "[+] Created/verified grammar directory: %s\n", dir_path);
        } else {
            fprintf(stderr, "[!] Failed to create grammar directory: %s (result=%d)\n", dir_path, mkdir_result);
        }
    }
    free(dir_path);
    
    fprintf(stderr, "[*] Attempting to save hypothesis to: %s\n", filepath);
    fprintf(stderr, "[*] Hypothesis details: message_type=%s, fitness=%.2f, id=%lld\n",
            hyp->message_type ? hyp->message_type : "NULL",
            hyp->fitness,
            (long long)hyp->hypothesis_id);
    
    FILE *f = fopen(filepath, "w");
    if (!f) {
        fprintf(stderr, "[!] save_hypothesis_to_file: failed to open %s (errno=%d: %s)\n", 
                filepath, errno, strerror(errno));
        return 0;
    }
    
    fprintf(stderr, "[+] Successfully opened file for writing: %s\n", filepath);
    
    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "hypothesis_id", json_object_new_int64(hyp->hypothesis_id));
    
    // CRITICAL: NULL-safe string handling for JSON
    json_object_object_add(jobj, "message_type", 
        hyp->message_type ? json_object_new_string(hyp->message_type) : json_object_new_string("UNKNOWN"));
    json_object_object_add(jobj, "description", 
        hyp->description ? json_object_new_string(hyp->description) : json_object_new_string(""));
    
    // CRITICAL: Handle NULL schema safely - use schema_str instead of schema object
    if (hyp->schema_str) {
        json_object *schema_parsed = json_tokener_parse(hyp->schema_str);
        if (schema_parsed) {
            json_object_object_add(jobj, "schema", schema_parsed);
        } else {
            json_object_object_add(jobj, "schema", json_object_new_object());
        }
    } else {
        json_object_object_add(jobj, "schema", json_object_new_object());
    }
    
    json_object_object_add(jobj, "parse_success", json_object_new_int(hyp->parse_success));
    json_object_object_add(jobj, "parse_failure", json_object_new_int(hyp->parse_failure));
    json_object_object_add(jobj, "fitness", json_object_new_double(hyp->fitness));
    json_object_object_add(jobj, "created_at", json_object_new_int64(hyp->created_at));
    json_object_object_add(jobj, "last_updated", json_object_new_int64(hyp->last_updated));
    
    const char *json_str = json_object_to_json_string_ext(jobj, JSON_C_TO_STRING_PRETTY);
    fprintf(f, "%s\n", json_str);
    fflush(f);  // Ensure data is written
    json_object_put(jobj);
    
    fclose(f);
    
    // Verify file was written
    struct stat st;
    if (stat(filepath, &st) == 0) {
        fprintf(stderr, "[+] Grammar hypothesis saved successfully: %s (%ld bytes)\n", 
                filepath, (long)st.st_size);
        return 1;
    } else {
        fprintf(stderr, "[!] File verification failed after write: %s\n", filepath);
        return 0;
    }
}

grammar_hypothesis_t* load_hypothesis_from_file(const char *filepath) {
    FILE *f = fopen(filepath, "r");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *content = (char*)ck_alloc(fsize + 1);
    memset(content, 0, fsize + 1);  // Initialize buffer
    fread(content, 1, fsize, f);
    content[fsize] = '\0';
    fclose(f);
    
    grammar_hypothesis_t *hyp = parse_llm_hypothesis_response(content);
    ck_free(content);
    
    return hyp;
}

/* ============================================
 * Cleanup Functions
 * ============================================ */

void free_grammar_hypothesis(grammar_hypothesis_t *hyp) {
    if (!hyp) return;
    
    ck_free(hyp->message_type);
    ck_free(hyp->description);
    
    if (hyp->schema) {
        json_object_put(hyp->schema);
    }
    ck_free(hyp->schema_str);
    
    for (size_t i = 0; i < hyp->constraint_count; i++) {
        field_constraint_t *c = hyp->constraints[i];
        ck_free(c->field_name);
        
        if (c->type == CONSTRAINT_ENUM) {
            for (size_t j = 0; j < c->data.enumeration.count; j++) {
                ck_free(c->data.enumeration.values[j]);
            }
            ck_free(c->data.enumeration.values);
        } else if (c->type == CONSTRAINT_REGEX) {
            ck_free(c->data.regex.pattern);
        } else if (c->type == CONSTRAINT_DEPENDENCY) {
            ck_free(c->data.dependency.target_field);
            ck_free(c->data.dependency.condition);
        }
        
        ck_free(c);
    }
    ck_free(hyp->constraints);
    
    for (size_t i = 0; i < hyp->rule_count; i++) {
        ck_free(hyp->production_rules[i]);
    }
    ck_free(hyp->production_rules);
    
    for (size_t i = 0; i < hyp->counterexample_count; i++) {
        ck_free(hyp->counterexamples[i]);
    }
    ck_free(hyp->counterexamples);
    
    ck_free(hyp);
}

void free_hypothesis_context(hypothesis_context_t *ctx) {
    if (!ctx) return;
    
    fprintf(stderr, "[DEBUG] free_hypothesis_context: ctx=%p\n", (void*)ctx);
    fprintf(stderr, "[DEBUG] Freeing protocol_name=%p\n", (void*)ctx->protocol_name);
    ck_free(ctx->protocol_name);
    
    fprintf(stderr, "[DEBUG] Freeing rfc_text=%p (size likely large)\n", (void*)ctx->rfc_text);
    ck_free(ctx->rfc_text);  // Now consistently ck_alloc'ed
    
    fprintf(stderr, "[DEBUG] Freeing %zu pcap_samples\n", ctx->pcap_count);
    for (size_t i = 0; i < ctx->pcap_count; i++) {
        fprintf(stderr, "[DEBUG]   pcap_samples[%zu]=%p\n", i, (void*)ctx->pcap_samples[i]);
        ck_free(ctx->pcap_samples[i]);
    }
    fprintf(stderr, "[DEBUG] Freeing pcap_samples array=%p\n", (void*)ctx->pcap_samples);
    ck_free(ctx->pcap_samples);
    
    fprintf(stderr, "[DEBUG] Freeing %zu server_responses\n", ctx->response_count);
    for (size_t i = 0; i < ctx->response_count; i++) {
        fprintf(stderr, "[DEBUG]   server_responses[%zu]=%p\n", i, (void*)ctx->server_responses[i]);
        ck_free(ctx->server_responses[i]);
    }
    fprintf(stderr, "[DEBUG] Freeing server_responses array=%p\n", (void*)ctx->server_responses);
    ck_free(ctx->server_responses);
    
    fprintf(stderr, "[DEBUG] Freeing %zu hypotheses\n", ctx->hypothesis_count);
    for (size_t i = 0; i < ctx->hypothesis_count; i++) {
        fprintf(stderr, "[DEBUG]   hypotheses[%zu]=%p\n", i, (void*)ctx->hypotheses[i]);
        free_grammar_hypothesis(ctx->hypotheses[i]);
    }
    fprintf(stderr, "[DEBUG] Freeing hypotheses array=%p (THIS IS WHERE CRASH HAPPENS)\n", (void*)ctx->hypotheses);
    ck_free(ctx->hypotheses);
    
    fprintf(stderr, "[DEBUG] Freeing ctx itself=%p\n", (void*)ctx);
    ck_free(ctx);
    fprintf(stderr, "[DEBUG] free_hypothesis_context completed successfully\n");
}

/* ============================================
 * Utility Functions
 * ============================================ */

void log_hypothesis_event(
    grammar_hypothesis_t *hyp,
    const char *event_type,
    const char *details
) {
    // Log to stderr for debugging
    fprintf(stderr, "[HYPOTHESIS-%llu] %s: %s | Type: %s | Fitness: %.3f\n",
            hyp->hypothesis_id,
            event_type,
            details,
            hyp->message_type,
            hyp->fitness);
}
