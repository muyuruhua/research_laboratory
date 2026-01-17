#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#define DEBUG_MODE 1

/**
 * @file testLLM.c
 * @brief 与大型语言模型（LLM）API交互的示例代码。
 * export KEY="sk-ILojcXJTq7HKk5RJ232858Aa05C24128830bDc12610d3c0d"
 * gcc -o testLLM testLLM.c -lcurl -Wall -g && ./testLLM
 * 
 */

// --- 新增的全局初始化和清理函数 ---

/**
 * @brief 在 main 函数执行前自动调用，用于初始化 libcurl 全局环境。
 * 
 * 使用 __attribute__((constructor)) 是 GCC 的一个扩展，它告诉编译器
 * 将这个函数标记为构造函数，在 main() 函数执行之前自动运行。
 */
__attribute__((constructor))
static void global_init() {
    // CURL_GLOBAL_ALL 会初始化所有可能需要的子系统，如 SSL, zlib 等。
    // 这是最常用和最安全的初始化方式。
    curl_global_init(CURL_GLOBAL_ALL);
}

/**
 * @brief 在程序退出时自动调用，用于清理 libcurl 全局环境。
 * 
 * 使用 __attribute__((destructor)) 是 GCC 的一个扩展，它告诉编译器
 * 将这个函数标记为析构函数，在 main() 函数返回后、程序退出前自动运行。
 */
__attribute__((destructor))
static void global_cleanup() {
    // 与 curl_global_init() 配对使用，释放所有全局资源。
    curl_global_cleanup();
}

// --- 以下是你原有的代码，无需任何修改 ---

const char* get_api_key() {
    const char* key = getenv("KEY");
    return (key && strlen(key) > 0) ? key : NULL;
}

char* json_escape_string(const char* input) {
    if (!input) return strdup("");
    size_t len = strlen(input);
    char* output = calloc(len * 6 + 1, sizeof(char));
    const char* src = input; char* dst = output;
    while (*src) {
        if (*src == '"') { strcpy(dst, "\\\""); dst += 2; }
        else if (*src == '\\') { strcpy(dst, "\\\\"); dst += 2; }
        else if (*src == '\n') { strcpy(dst, "\\n"); dst += 2; }
        else if (*src == '\r') { strcpy(dst, "\\r"); dst += 2; }
        else if ((unsigned char)*src < 32) dst += sprintf(dst, "\\u%04x", (unsigned char)*src);
        else *dst++ = *src;
        src++;
    }
    *dst = '\0';
    return output;
}

char* extract_content_from_json(const char* json_str) {
    if (!json_str) return NULL;
    const char* key_pos = strstr(json_str, "\"content\"");
    if (!key_pos) return NULL;
    const char* colon_pos = strchr(key_pos, ':');
    if (!colon_pos) return NULL;
    const char* start_quote = strchr(colon_pos, '"');
    if (!start_quote) return NULL; 
    start_quote++;
    
    const char* ptr = start_quote;
    const char* end_quote = NULL;
    while (*ptr) {
        if (*ptr == '\\') { ptr += 2; continue; }
        if (*ptr == '"') { end_quote = ptr; break; }
        ptr++;
    }
    if (!end_quote) return NULL;
    
    size_t len = end_quote - start_quote;
    char* raw = malloc(len + 1);
    strncpy(raw, start_quote, len);
    raw[len] = '\0';
    
    char* final = malloc(len + 1);
    char* w = final; char* r = raw;
    while (*r) {
        if (*r == '\\' && *(r+1)) {
            r++;
            switch (*r) {
                case 'n': *w++ = '\n'; break;
                case 'r': *w++ = '\r'; break;
                case 't': *w++ = '\t'; break;
                case '"': *w++ = '"'; break;
                case '\\': *w++ = '\\'; break;
                default: *w++ = *r;
            }
        } else {
            *w++ = *r;
        }
        r++;
    }
    *w = '\0';
    free(raw);
    return final;
}

static size_t write_cb(void* contents, size_t size, size_t nmemb, char** response) {
    size_t total = size * nmemb;
    char* new_res = realloc(*response, (*response ? strlen(*response) : 0) + total + 1);
    if (!new_res) return 0;
    *response = new_res;
    if (total > 0) strncat(*response, (char*)contents, total);
    return total;
}

char* chat_with_llm(char* prompt, char* model, int tries, float temperature) {
    if (!get_api_key()) return NULL;
    CURL* curl = curl_easy_init();
    if (!curl) return NULL;
    if (tries < 1) tries = 1;

    struct curl_slist* headers = curl_slist_append(NULL, "Content-Type: application/json");
    char auth[256]; 
    snprintf(auth, sizeof(auth), "Authorization: Bearer %s", get_api_key());
    headers = curl_slist_append(headers, auth);
    
    char* esc_prompt = json_escape_string(prompt);
    size_t jsize = strlen(esc_prompt) + 2048;
    char* data = malloc(jsize);
    
    snprintf(data, jsize, 
             "{\"model\":\"%s\",\"messages\":[{\"role\":\"user\",\"content\":\"%s\"}],\"temperature\":%.2f}", 
             model, esc_prompt, temperature);
    
    char* resp = NULL;
    char* content = NULL;
    CURLcode res;
    long http_code = 0;

    curl_easy_setopt(curl, CURLOPT_URL, "https://free.v36.cm/v1/chat/completions");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    
    for (int i = 0; i < tries; i++) {
        if (resp) { free(resp); resp = NULL; }
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
        res = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        
        if (res == CURLE_OK && http_code == 200) {
            content = extract_content_from_json(resp);
            if (content) break; 
        }
        if (DEBUG_MODE) {
            printf("[DEBUG] Attempt %d/%d failed. Code: %ld\n", i + 1, tries, http_code);
        }
    }
    
    curl_easy_cleanup(curl);
    curl_slist_free_all(headers);
    free(esc_prompt); free(data); free(resp);
    return content;
}

// 示例使用
int main() {
    // 设置环境变量（在实际使用中，应该在shell中设置）
    // setenv("KEY", "sk-ILojcXJTq7HKk5RJ232858Aa05C24128830bDc12610d3c0d", 1);
    
    char* prompt = "You are an expert in networking protocols. For the RTSP protocol, "
                  "the typical sequence is: DESCRIBE, SETUP, PLAY. Please explain where "
                  "SET_PARAMETER and TEARDOWN should be placed in this sequence.";
    
    printf("Sending request to LLM API...\n");
    
    // 调用封装后的函数
    char* response = chat_with_llm(prompt, "gpt-4o-mini", 3, 0.7);
    
    if (response) {
        printf("\n=== LLM Response ===\n");
        printf("%s\n", response);
        free(response);
    }
    
    return 0;
}