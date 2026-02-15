/*
 * ChatAFL-Opt: RFC Knowledge Implementation
 * =========================================
 *
 * Implements RFC fetching, caching, and structured knowledge extraction.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <curl/curl.h>

// PCRE2 requires this to be defined before including the header
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#include "rfc-knowledge.h"
#include "alloc-inl.h"

/* ============================================
 * Helper: CURL Write Callback
 * ============================================ */

typedef struct {
    char *data;
    size_t size;
} curl_buffer_t;

static size_t rfc_write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    curl_buffer_t *buffer = (curl_buffer_t *)userp;
    
    char *ptr = realloc(buffer->data, buffer->size + realsize + 1);
    if (!ptr) {
        fprintf(stderr, "[!] RFC fetch: out of memory\n");
        return 0;
    }
    
    buffer->data = ptr;
    memcpy(&(buffer->data[buffer->size]), contents, realsize);
    buffer->size += realsize;
    buffer->data[buffer->size] = 0;
    
    return realsize;
}

/* ============================================
 * RFC Lookup Functions
 * ============================================ */

const rfc_info_t* get_rfc_info_for_protocol(const char *protocol_name) {
    if (!protocol_name) return NULL;
    
    for (size_t i = 0; i < RFC_DATABASE_SIZE; i++) {
        if (strcasecmp(RFC_DATABASE[i].protocol_name, protocol_name) == 0) {
            return &RFC_DATABASE[i];
        }
    }
    
    return NULL;
}

const char* get_rfc_url_for_protocol(const char *protocol_name) {
    const rfc_info_t *info = get_rfc_info_for_protocol(protocol_name);
    return info ? info->rfc_url : NULL;
}

/* ============================================
 * RFC Fetching with Caching
 * ============================================ */

static char* get_rfc_cache_path(const char *protocol_name) {
    char *cache_path = NULL;
    asprintf(&cache_path, "%s/%s.txt", RFC_CACHE_DIR, protocol_name);
    return cache_path;
}

static char* load_from_cache(const char *protocol_name) {
    char *cache_path = get_rfc_cache_path(protocol_name);
    if (!cache_path) return NULL;
    
    FILE *fp = fopen(cache_path, "r");
    if (!fp) {
        free(cache_path);
        return NULL;
    }
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    if (size <= 0 || size > RFC_MAX_SIZE) {
        fclose(fp);
        free(cache_path);
        return NULL;
    }
    
    char *content = malloc(size + 1);
    if (!content) {
        fclose(fp);
        free(cache_path);
        return NULL;
    }
    
    size_t read_size = fread(content, 1, size, fp);
    content[read_size] = '\0';
    
    fclose(fp);
    free(cache_path);
    
    printf("[*] Loaded RFC for %s from cache (%ld bytes)\n", protocol_name, size);
    return content;
}

static int save_to_cache(const char *protocol_name, const char *content) {
    // Create cache directory if not exists
    struct stat st = {0};
    if (stat(RFC_CACHE_DIR, &st) == -1) {
        mkdir(RFC_CACHE_DIR, 0755);
    }
    
    char *cache_path = get_rfc_cache_path(protocol_name);
    if (!cache_path) return 0;
    
    FILE *fp = fopen(cache_path, "w");
    if (!fp) {
        free(cache_path);
        return 0;
    }
    
    size_t written = fwrite(content, 1, strlen(content), fp);
    fclose(fp);
    free(cache_path);
    
    printf("[*] Saved RFC for %s to cache (%zu bytes)\n", protocol_name, written);
    return 1;
}

char* fetch_rfc_text(const char *protocol_name) {
    if (!protocol_name) return NULL;
    
    // Try cache first
    if (RFC_CACHE_ENABLED) {
        char *cached = load_from_cache(protocol_name);
        if (cached) return cached;
    }
    
    // Get RFC URL
    const char *url = get_rfc_url_for_protocol(protocol_name);
    if (!url) {
        fprintf(stderr, "[RFC] No RFC URL configured for protocol: %s\n", protocol_name);
        return NULL;
    }
    
    printf("[RFC] Fetching RFC for %s from %s...\n", protocol_name, url);
    
    // Retry configuration
    const int max_retries = 3;
    int backoff = 2; // seconds
    CURLcode res = CURLE_OK;
    curl_buffer_t buffer = {.data = NULL, .size = 0};
    int should_retry = 1;
    
    for (int attempt = 1; attempt <= max_retries && should_retry; attempt++) {
        if (attempt > 1) {
            printf("[RFC] Retry attempt %d/%d after %d seconds...\n", attempt, max_retries, backoff);
            sleep(backoff);
            backoff *= 2; // Exponential backoff: 2 -> 4 -> 8 seconds
        }
        
        // Initialize buffer for this attempt
        if (buffer.data) free(buffer.data);
        buffer.data = malloc(1);
        buffer.size = 0;
        
        CURL *curl = curl_easy_init();
        if (!curl) {
            fprintf(stderr, "[RFC] Failed to initialize CURL\n");
            return NULL;
        }
        
        // CURL error buffer for detailed diagnostics
        char curl_error_buffer[CURL_ERROR_SIZE];
        curl_error_buffer[0] = '\0';
        
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, rfc_write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)RFC_FETCH_TIMEOUT);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L); // 10s connection timeout
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L); // Limit redirects
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "ChatAFL-Opt/1.0");
        
        // Slow connection protection: abort if speed < 5KB/s for 20 seconds
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 5120L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 20L);
        
        // Enable detailed error messages
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_error_buffer);
        
        res = curl_easy_perform(curl);
        
        // Check HTTP status code
        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        
        curl_easy_cleanup(curl);
        
        if (res == CURLE_OK) {
            // Check size validity
            if (buffer.size == 0) {
                fprintf(stderr, "[RFC] ⚠ Warning: RFC content is empty (0 bytes)\n");
                should_retry = (attempt < max_retries);
                continue;
            }
            if (buffer.size > RFC_MAX_SIZE) {
                fprintf(stderr, "[RFC] ✗ RFC too large: %zu bytes (max: %d bytes)\n", 
                       buffer.size, RFC_MAX_SIZE);
                free(buffer.data);
                return NULL; // Size limit is not retryable
            }
            
            printf("[RFC] ✓ Fetched RFC for %s (%zu bytes)\n", protocol_name, buffer.size);
            
            // Save to cache
            if (RFC_CACHE_ENABLED) {
                save_to_cache(protocol_name, buffer.data);
            }
            
            return buffer.data;
        }
        
        // Error handling with retry logic
        should_retry = 1; // Default: retry
        
        if (res == CURLE_OPERATION_TIMEDOUT) {
            fprintf(stderr, "[RFC] ⏱ Fetch timeout after %d seconds (attempt %d/%d)\n",
                   RFC_FETCH_TIMEOUT, attempt, max_retries);
            if (strlen(curl_error_buffer) > 0) {
                fprintf(stderr, "[RFC] Details: %s\n", curl_error_buffer);
            }
        } else if (res == CURLE_COULDNT_CONNECT) {
            fprintf(stderr, "[RFC] ⚠ Connection failed (attempt %d/%d)\n", attempt, max_retries);
            if (strlen(curl_error_buffer) > 0) {
                fprintf(stderr, "[RFC] Details: %s\n", curl_error_buffer);
            }
        } else if (res == CURLE_COULDNT_RESOLVE_HOST) {
            fprintf(stderr, "[RFC] ✗ Fatal: Cannot resolve host in URL: %s\n", url);
            should_retry = 0; // DNS failure is not retryable
        } else if (res == CURLE_OUT_OF_MEMORY) {
            fprintf(stderr, "[RFC] ✗ Fatal: Out of memory\n");
            should_retry = 0; // Memory exhaustion is not retryable
        } else {
            fprintf(stderr, "[RFC] Error: %s (attempt %d/%d)\n", 
                   curl_easy_strerror(res), attempt, max_retries);
            if (strlen(curl_error_buffer) > 0) {
                fprintf(stderr, "[RFC] Details: %s\n", curl_error_buffer);
            }
        }
        
        // HTTP status code analysis
        if (http_code >= 400 && http_code < 500 && http_code != 429) {
            // 4xx client errors (except 429) are not retryable
            fprintf(stderr, "[RFC] ✗ Fatal: HTTP %ld client error, retry disabled\n", http_code);
            should_retry = 0;
        } else if (http_code == 429) {
            fprintf(stderr, "[RFC] ⚠ HTTP 429 Rate Limited, will retry with backoff\n");
        } else if (http_code >= 500) {
            fprintf(stderr, "[RFC] ⚠ HTTP %ld server error, will retry\n", http_code);
        }
        
        // Don't retry if this is the last attempt
        if (attempt >= max_retries) {
            should_retry = 0;
        }
    }
    
    // All retries failed
    fprintf(stderr, "[RFC] ✗ Failed to fetch RFC for %s after %d attempts\n", 
           protocol_name, max_retries);
    if (buffer.data) free(buffer.data);
    return NULL;
}

/* ============================================
 * RFC Knowledge Extraction
 * ============================================ */

static const char* get_command_pattern(const char *protocol_name) {
    if (strcasecmp(protocol_name, "FTP") == 0) return RFC_COMMAND_PATTERN_FTP;
    if (strcasecmp(protocol_name, "SMTP") == 0) return RFC_COMMAND_PATTERN_SMTP;
    if (strcasecmp(protocol_name, "RTSP") == 0) return RFC_COMMAND_PATTERN_RTSP;
    if (strcasecmp(protocol_name, "SIP") == 0) return RFC_COMMAND_PATTERN_SIP;
    if (strcasecmp(protocol_name, "HTTP") == 0) return RFC_COMMAND_PATTERN_HTTP;
    return NULL;
}

static const char* get_response_pattern(const char *protocol_name) {
    if (strcasecmp(protocol_name, "FTP") == 0) return RFC_RESPONSE_PATTERN_FTP;
    if (strcasecmp(protocol_name, "SMTP") == 0) return RFC_RESPONSE_PATTERN_SMTP;
    if (strcasecmp(protocol_name, "RTSP") == 0) return RFC_RESPONSE_PATTERN_RTSP;
    if (strcasecmp(protocol_name, "SIP") == 0) return RFC_RESPONSE_PATTERN_SIP;
    if (strcasecmp(protocol_name, "HTTP") == 0) return RFC_RESPONSE_PATTERN_HTTP;
    return NULL;
}

char** extract_rfc_commands(const char *rfc_text, const char *protocol_name, size_t *count) {
    *count = 0;
    if (!rfc_text || !protocol_name) return NULL;
    
    const char *pattern = get_command_pattern(protocol_name);
    if (!pattern) return NULL;
    
    int errornumber;
    PCRE2_SIZE erroroffset;
    pcre2_code *re = pcre2_compile(
        (PCRE2_SPTR)pattern,
        PCRE2_ZERO_TERMINATED,
        PCRE2_MULTILINE,
        &errornumber,
        &erroroffset,
        NULL
    );
    
    if (!re) {
        fprintf(stderr, "[!] Failed to compile regex for %s commands\n", protocol_name);
        return NULL;
    }
    
    // Extract matches
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(re, NULL);
    size_t capacity = 50;
    char **commands = malloc(capacity * sizeof(char*));
    
    const char *subject = rfc_text;
    size_t subject_len = strlen(rfc_text);
    size_t offset = 0;
    
    while (offset < subject_len) {
        int rc = pcre2_match(re, (PCRE2_SPTR)subject, subject_len, offset, 0, match_data, NULL);
        if (rc < 0) break;
        
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
        size_t match_len = ovector[1] - ovector[0];
        
        // Extract command
        char *cmd = malloc(match_len + 1);
        strncpy(cmd, subject + ovector[0], match_len);
        cmd[match_len] = '\0';
        
        // Remove duplicates
        int is_duplicate = 0;
        for (size_t i = 0; i < *count; i++) {
            if (strcmp(commands[i], cmd) == 0) {
                is_duplicate = 1;
                break;
            }
        }
        
        if (!is_duplicate) {
            if (*count >= capacity) {
                capacity *= 2;
                commands = realloc(commands, capacity * sizeof(char*));
            }
            commands[(*count)++] = cmd;
        } else {
            free(cmd);
        }
        
        offset = ovector[1];
    }
    
    pcre2_match_data_free(match_data);
    pcre2_code_free(re);
    
    printf("[+] Extracted %zu commands from RFC for %s\n", *count, protocol_name);
    return commands;
}

char** extract_rfc_response_codes(const char *rfc_text, const char *protocol_name, size_t *count) {
    *count = 0;
    if (!rfc_text || !protocol_name) return NULL;
    
    const char *pattern = get_response_pattern(protocol_name);
    if (!pattern) return NULL;
    
    // Similar implementation to extract_rfc_commands
    // (Code omitted for brevity - follows same pattern)
    
    printf("[+] Extracted %zu response codes from RFC for %s\n", *count, protocol_name);
    return NULL; // Placeholder
}

char* extract_rfc_state_machine(const char *rfc_text, const char *protocol_name) {
    if (!rfc_text || !protocol_name) return NULL;
    
    // Search for state machine diagrams or descriptions
    // Keywords: "state", "transition", "sequence", "flow"
    
    // For now, return a simplified extraction
    // In production, this would parse state transition tables
    
    printf("[*] Extracting state machine from RFC for %s...\n", protocol_name);
    return ck_strdup((u8*)"State machine extraction not yet implemented");
}

/* ============================================
 * Enhanced Prompt Construction
 * ============================================ */

char* construct_prompt_with_rfc(
    const char *protocol_name,
    const char *prompt_template,
    int include_commands,
    int include_responses,
    int include_state_machine
) {
    if (!protocol_name || !prompt_template) return NULL;
    
    // Fetch RFC text
    char *rfc_text = fetch_rfc_text(protocol_name);
    if (!rfc_text) {
        fprintf(stderr, "[!] Failed to fetch RFC for %s, using template only\n", protocol_name);
        return ck_strdup((u8*)prompt_template);
    }
    
    // Build enhanced prompt
    size_t prompt_size = strlen(prompt_template) + strlen(rfc_text) + 4096;
    char *enhanced_prompt = malloc(prompt_size);
    int offset = 0;
    
    offset += snprintf(enhanced_prompt + offset, prompt_size - offset,
        "%s\n\nRFC Knowledge for %s:\n\n", prompt_template, protocol_name);
    
    // Add commands
    if (include_commands) {
        size_t cmd_count;
        char **commands = extract_rfc_commands(rfc_text, protocol_name, &cmd_count);
        
        if (commands && cmd_count > 0) {
            offset += snprintf(enhanced_prompt + offset, prompt_size - offset,
                "Protocol Commands: ");
            
            for (size_t i = 0; i < cmd_count && i < 20; i++) {
                offset += snprintf(enhanced_prompt + offset, prompt_size - offset,
                    "%s%s", commands[i], (i < cmd_count - 1) ? ", " : "");
                free(commands[i]);
            }
            offset += snprintf(enhanced_prompt + offset, prompt_size - offset, "\n\n");
            free(commands);
        }
    }
    
    // Add RFC excerpt (first 2000 chars)
    size_t rfc_excerpt_len = strlen(rfc_text) > 2000 ? 2000 : strlen(rfc_text);
    offset += snprintf(enhanced_prompt + offset, prompt_size - offset,
        "RFC Excerpt:\n%.*s\n\n", (int)rfc_excerpt_len, rfc_text);
    
    free(rfc_text);
    
    return enhanced_prompt;
}

/* ============================================
 * Cleanup Functions
 * ============================================ */

void cleanup_rfc_cache(void) {
    // Remove all cached RFC files
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", RFC_CACHE_DIR);
    system(cmd);
    printf("[*] Cleaned RFC cache\n");
}
