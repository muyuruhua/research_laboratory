#define _GNU_SOURCE // asprintf
#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <math.h>

#include "chat-llm.h"
#include "knowledge-level.h"
#include "alloc-inl.h"
#include "hash.h"

// -lcurl -ljson-c -lpcre2-8
// apt install libcurl4-openssl-dev libjson-c-dev libpcre2-dev libpcre2-8-0

#define MAX_TOKENS 4096
#define CONFIDENT_TIMES 3

struct MemoryStruct
{
    char *memory;
    size_t size;
};

static size_t chat_with_llm_helper(void *contents, size_t size, size_t nmemb, void *userp)
{
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    if (size && nmemb > SIZE_MAX / size) return 0;
    size_t realsize = size * nmemb;
    if (mem->size == SIZE_MAX || realsize > SIZE_MAX - mem->size - 1) return 0;
    char *grown = realloc(mem->memory, mem->size + realsize + 1);
    if (grown == NULL)
    {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }
    mem->memory = grown;

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

/* forward declaration for validator used in llm_handle_plateau */
static int is_garbage_response(const char *response, size_t len);

/* --- curl global lifecycle (call once from main thread) --- */
void chat_llm_apply_sampling_env(void); /* defined below */
void chat_llm_global_init(void)  {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    chat_llm_apply_sampling_env();
}
void chat_llm_global_cleanup(void) { curl_global_cleanup(); }

/* Per-call token usage — populated from the API "usage" object.
 * __thread: each enrichment worker thread gets its own copy so that
 * concurrent enrich_sequence() calls don't clobber each other.
 * In the forked plateau-handler child, TLS is inherited and works
 * normally (single-threaded child). */
__thread unsigned long long llm_last_prompt_tokens     = 0;
__thread unsigned long long llm_last_completion_tokens = 0;

/* ── v3 (P0-2/P1-7): per-call ledger + campaign-wide caps ──────────
 * llm-calls.jsonl records EVERY gateway call (attempts, retries,
 * failures, all call classes) with the served model echoed by the
 * service — the two audit fields the retrospective data could not
 * provide.  Caps: CHATAFL_LLM_TOTAL_CALL_CAP / CHATAFL_TOKEN_CAP are
 * enforced centrally here (-1 / unset = unlimited), so a recorded cap
 * is a real cap, not a declaration. */
__thread char llm_last_served_model[128] = {0};
static char chat_llm_calls_path[4096] = {0};
static char chat_llm_archive_dir[4096] = {0};  /* full req/resp sidecars */
static unsigned long long llm_calls_seq = 0;
static unsigned long long llm_cum_calls = 0;    /* every attempt sent */
static unsigned long long llm_cum_tokens = 0;   /* billed prompt+completion */
static long llm_cap_total_calls = -1;           /* CHATAFL_LLM_TOTAL_CALL_CAP */
static long llm_cap_total_tokens = -1;          /* CHATAFL_TOKEN_CAP */
#include <pthread.h>
#include <sys/time.h>
static pthread_mutex_t g_llm_calls_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread char g_llm_last_req[65536];   /* last POST body (this thread) */
static __thread char g_llm_last_resp[262144]; /* last raw response (this thread) */

void chat_llm_set_archive_dir(const char *d) {
    if (d && *d)
        snprintf(chat_llm_archive_dir, sizeof(chat_llm_archive_dir), "%s", d);
}

void chat_llm_set_calls_log(const char *path) {
    if (path && *path)
        snprintf(chat_llm_calls_path, sizeof(chat_llm_calls_path), "%s", path);
}

unsigned long long chat_llm_cum_calls(void) {
    pthread_mutex_lock(&g_llm_calls_mutex);
    unsigned long long value = llm_cum_calls;
    pthread_mutex_unlock(&g_llm_calls_mutex);
    return value;
}
unsigned long long chat_llm_cum_tokens(void) {
    pthread_mutex_lock(&g_llm_calls_mutex);
    unsigned long long value = llm_cum_tokens;
    pthread_mutex_unlock(&g_llm_calls_mutex);
    return value;
}
long chat_llm_cap_calls(void)   { return llm_cap_total_calls; }
long chat_llm_cap_tokens(void)  { return llm_cap_total_tokens; }

static unsigned long long chat_llm_now_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (unsigned long long)tv.tv_sec * 1000ULL + tv.tv_usec / 1000;
}

/* v3.1 (P1-7): full request/response provenance.  Prompts and replies are
 * written as sidecar files <seq>.req/.resp next to llm-calls.jsonl so the
 * ledger stays parseable while the complete exchanges remain auditable
 * (gateway nondeterminism / replay). */
static void chat_llm_archive(unsigned long long seq, const char *req_json,
                             const char *resp) {
    if (!chat_llm_archive_dir[0]) return;
    if (req_json && *req_json) {
        char p[4352]; snprintf(p, sizeof(p), "%s/%llu.req", chat_llm_archive_dir, seq);
        FILE *f = fopen(p, "w");
        if (f) { fputs(req_json, f); fclose(f); }
    }
    if (resp && *resp) {
        char p[4352]; snprintf(p, sizeof(p), "%s/%llu.resp", chat_llm_archive_dir, seq);
        FILE *f = fopen(p, "w");
        if (f) { fputs(resp, f); fclose(f); }
    }
}

static void chat_llm_log_call(const char *status, const char *model_req,
                              long latency_ms,
                              unsigned long long pt, unsigned long long ct,
                              const char *endpoint) {
    if (!chat_llm_calls_path[0]) return;
    pthread_mutex_lock(&g_llm_calls_mutex);
    unsigned long long seq = llm_calls_seq + 1;
    chat_llm_archive(seq, g_llm_last_req, g_llm_last_resp);
    FILE *f = fopen(chat_llm_calls_path, "a");
    if (f) {
        seq = ++llm_calls_seq;
        json_object *record = json_object_new_object();
        if (record) {
            json_object_object_add(record, "seq", json_object_new_int64(seq));
            json_object_object_add(record, "time_ms", json_object_new_int64(chat_llm_now_ms()));
            json_object_object_add(record, "status", json_object_new_string(status ? status : "unknown"));
            json_object_object_add(record, "model_requested", json_object_new_string(model_req ? model_req : ""));
            json_object_object_add(record, "model_served", json_object_new_string(llm_last_served_model));
            json_object_object_add(record, "latency_ms", json_object_new_int64(latency_ms));
            json_object_object_add(record, "prompt_tokens", json_object_new_int64(pt));
            json_object_object_add(record, "completion_tokens", json_object_new_int64(ct));
            json_object_object_add(record, "endpoint", json_object_new_string(endpoint ? endpoint : ""));
            json_object_object_add(record, "cum_calls", json_object_new_int64(llm_cum_calls));
            json_object_object_add(record, "cum_tokens", json_object_new_int64(llm_cum_tokens));
            json_object_object_add(record, "archived", json_object_new_boolean(chat_llm_archive_dir[0] != 0));
            fprintf(f, "%s\n", json_object_to_json_string_ext(record, JSON_C_TO_STRING_PLAIN));
            json_object_put(record);
        }
        fclose(f);
    }
    pthread_mutex_unlock(&g_llm_calls_mutex);
}

/* ── Auditable LLM configuration (paper §九: matched configs) ──────
 * Sampling parameters are resolved once from the environment so every
 * call uses identical settings, and run-config.jsonl can record them
 * via the getters below. */
static double llm_cfg_top_p     = 1.0;
static int    llm_cfg_max_tokens = MAX_TOKENS;
static char   llm_cfg_model[128] = {0};

double llm_active_top_p(void)     { return llm_cfg_top_p; }
int    llm_active_max_tokens(void){ return llm_cfg_max_tokens; }
const char *llm_active_model(void) {
    if (llm_cfg_model[0]) return llm_cfg_model;
    const char *m = getenv("LLM_MODEL");
    return (m && *m) ? m : LLM_DEFAULT_MODEL;
}

void chat_llm_apply_sampling_env(void) {
    const char *tp = getenv("CHATAFL_TOP_P");
    if (tp && *tp) {
        double v = atof(tp);
        if (v > 0.0 && v <= 1.0) llm_cfg_top_p = v;
    }
    const char *mt = getenv("CHATAFL_MAX_TOKENS");
    if (mt && *mt) {
        int v = atoi(mt);
        if (v > 0 && v <= 32768) llm_cfg_max_tokens = v;
    }
    const char *m = getenv("LLM_MODEL");
    if (m && *m) {
        snprintf(llm_cfg_model, sizeof(llm_cfg_model), "%s", m);
    }
    /* v3 campaign-wide caps (resolved once; enforced per call). */
    const char *cc = getenv("CHATAFL_LLM_TOTAL_CALL_CAP");
    if (cc && *cc) {
        long v = atol(cc);
        if (v > 0) llm_cap_total_calls = v;
    }
    const char *tc = getenv("CHATAFL_TOKEN_CAP");
    if (tc && *tc) {
        long v = atol(tc);
        if (v > 0) llm_cap_total_tokens = v;
    }
}

/* Parse the entire document, including trailing bytes, before sending it. */
static json_object *chat_llm_parse_json(const char *text)
{
    if (!text || strlen(text) >= INT_MAX) return NULL;
    struct json_tokener *tok = json_tokener_new();
    if (!tok) return NULL;
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
    json_object *value = json_tokener_parse_ex(tok, text, (int)strlen(text) + 1);
    if (json_tokener_get_error(tok) != json_tokener_success) {
        if (value) json_object_put(value);
        value = NULL;
    }
    json_tokener_free(tok);
    return value;
}

static int chat_llm_retryable_transport(CURLcode result)
{
    switch (result) {
    case CURLE_COULDNT_RESOLVE_HOST:
    case CURLE_COULDNT_RESOLVE_PROXY:
    case CURLE_COULDNT_CONNECT:
    case CURLE_OPERATION_TIMEDOUT:
    case CURLE_SSL_CONNECT_ERROR:
    case CURLE_SEND_ERROR:
    case CURLE_RECV_ERROR:
    case CURLE_GOT_NOTHING:
    case CURLE_PARTIAL_FILE:
    case CURLE_HTTP2:
    case CURLE_HTTP2_STREAM:
        return 1;
    default:
        return 0;
    }
}

/* Reserve every attempt, including retries, under the enrichment-worker lock. */
static int chat_llm_reserve_call(void)
{
    pthread_mutex_lock(&g_llm_calls_mutex);
    int allowed = (llm_cap_total_calls < 0 || llm_cum_calls < (unsigned long long)llm_cap_total_calls) &&
                  (llm_cap_total_tokens < 0 || llm_cum_tokens < (unsigned long long)llm_cap_total_tokens);
    if (allowed) ++llm_cum_calls;
    pthread_mutex_unlock(&g_llm_calls_mutex);
    return allowed;
}

char *chat_with_llm(char *prompt, char *model, int tries, float temperature)
{
    /* Keep the public signature: the campaign model is resolved at init. */
    (void)model;
    llm_last_prompt_tokens = 0;
    llm_last_completion_tokens = 0;
    llm_last_served_model[0] = '\0';
    g_llm_last_req[0] = g_llm_last_resp[0] = '\0';
    const char *no_llm = getenv("CHATAFL_NO_LLM");
    if (no_llm && *no_llm && strcmp(no_llm, "0") != 0) return NULL;
    if (tries <= 0 || !isfinite(temperature)) return NULL;

    const char *env_base = getenv("CHATAFL_LLM_BASE");
    const char *url = (env_base && *env_base) ? env_base
                    : "https://www.cctq.ai/v1/chat/completions";
    const char *api_key = getenv("KEY");
    if (!api_key || !*api_key) {
        fprintf(stderr, "[LLM] KEY is not set or is empty; request skipped.\n");
        return NULL;
    }
    if (strpbrk(api_key, "\r\n")) {
        fprintf(stderr, "[LLM] KEY contains an invalid newline; request skipped.\n");
        return NULL;
    }

    json_object *messages = chat_llm_parse_json(prompt);
    if (!messages || !json_object_is_type(messages, json_type_array) ||
        json_object_array_length(messages) == 0) {
        fprintf(stderr, "[LLM] Prompt must be a nonempty JSON messages array; request skipped.\n");
        if (messages) json_object_put(messages);
        return NULL;
    }
    json_object *request = json_object_new_object();
    if (!request) {
        json_object_put(messages);
        return NULL;
    }
    const char *llm_model = llm_active_model();
    json_object_object_add(request, "model", json_object_new_string(llm_model));
    json_object_object_add(request, "messages", messages);
    json_object_object_add(request, "max_tokens", json_object_new_int(llm_cfg_max_tokens));
    json_object_object_add(request, "temperature", json_object_new_double(temperature));
    json_object_object_add(request, "top_p", json_object_new_double(llm_cfg_top_p));
    const char *data = json_object_to_json_string_ext(request, JSON_C_TO_STRING_PLAIN);

    char *auth_header = NULL;
    if (asprintf(&auth_header, "Authorization: Bearer %s", api_key) < 0) {
        json_object_put(request);
        return NULL;
    }
    struct curl_slist *headers = NULL;
    const char *header_values[] = {auth_header, "Content-Type: application/json", "Accept: application/json"};
    for (size_t i = 0; i < sizeof(header_values) / sizeof(header_values[0]); ++i) {
        struct curl_slist *next = curl_slist_append(headers, header_values[i]);
        if (!next) {
            curl_slist_free_all(headers);
            free(auth_header);
            json_object_put(request);
            return NULL;
        }
        headers = next;
    }
    free(auth_header);

    if (strstr(prompt, "protocol") && strstr(prompt, "templates")) {
        fprintf(stderr, "\n=== LLM REQUEST DEBUG ===\nURL: %s\nData length: %zu bytes\n"
                        "First 500 chars of data:\n%.500s\n========================\n\n",
                url, strlen(data), data);
    }
    char *answer = NULL;
    for (int attempt = 0; attempt < tries; ++attempt) {
        snprintf(g_llm_last_req, sizeof(g_llm_last_req), "%s", data);
        g_llm_last_resp[0] = '\0';
        llm_last_prompt_tokens = llm_last_completion_tokens = 0;
        llm_last_served_model[0] = '\0';
        struct MemoryStruct chunk = {calloc(1, 1), 0};
        CURL *curl = curl_easy_init();
        if (!chunk.memory || !curl) {
            free(chunk.memory);
            if (curl) curl_easy_cleanup(curl);
            break;
        }
        char curl_error[CURL_ERROR_SIZE] = {0};
        long timeout_ms = 120000L;
        const char *lt = getenv("CHATAFL_LLM_TIMEOUT_MS");
        if (lt && *lt) {
            long ms = atol(lt);
            if (ms >= 10000 && ms <= 900000) timeout_ms = ms;
        }
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)strlen(data));
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, chat_with_llm_helper);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_error);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout_ms);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 60L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

        if (!chat_llm_reserve_call()) {
            curl_easy_cleanup(curl);
            free(chunk.memory);
            chat_llm_log_call("cap-refused", llm_model, 0, 0, 0, url);
            break;
        }
        unsigned long long started = chat_llm_now_ms();
        CURLcode res = curl_easy_perform(curl);
        long latency = (long)(chat_llm_now_ms() - started);
        long http_status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
        snprintf(g_llm_last_resp, sizeof(g_llm_last_resp), "%s", chunk.memory);

        const char *call_status = "transport-error";
        int retry = 0;
        if (res != CURLE_OK) {
            fprintf(stderr, "[LLM] Transport error (curl=%d, HTTP=%ld): %s\n",
                    res, http_status, *curl_error ? curl_error : curl_easy_strerror(res));
            retry = chat_llm_retryable_transport(res);
        } else {
            json_object *response = chat_llm_parse_json(chunk.memory);
            int is_object = json_object_is_type(response, json_type_object);
            json_object *value = NULL, *usage = NULL;
            if (is_object && json_object_object_get_ex(response, "model", &value) &&
                json_object_is_type(value, json_type_string))
                snprintf(llm_last_served_model, sizeof(llm_last_served_model), "%s", json_object_get_string(value));
            if (is_object && json_object_object_get_ex(response, "usage", &usage) &&
                json_object_is_type(usage, json_type_object)) {
                if (json_object_object_get_ex(usage, "prompt_tokens", &value) &&
                    json_object_is_type(value, json_type_int) && json_object_get_int64(value) >= 0)
                    llm_last_prompt_tokens = (unsigned long long)json_object_get_int64(value);
                if (json_object_object_get_ex(usage, "completion_tokens", &value) &&
                    json_object_is_type(value, json_type_int) && json_object_get_int64(value) >= 0)
                    llm_last_completion_tokens = (unsigned long long)json_object_get_int64(value);
            }
            pthread_mutex_lock(&g_llm_calls_mutex);
            llm_cum_tokens += llm_last_prompt_tokens + llm_last_completion_tokens;
            pthread_mutex_unlock(&g_llm_calls_mutex);

            json_object *api_error = NULL;
            int has_error = is_object && json_object_object_get_ex(response, "error", &api_error) && api_error;
            if (http_status < 200 || http_status >= 300 || has_error) {
                call_status = "api-error";
                fprintf(stderr, "[LLM] API error (HTTP=%ld): %s\n", http_status, chunk.memory);
                retry = http_status == 408 || http_status == 429 || http_status == 500 ||
                        http_status == 502 || http_status == 503 || http_status == 504;
            } else if (!is_object) {
                call_status = "invalid-response";
                fprintf(stderr, "[LLM] Invalid JSON response (HTTP=%ld): %s\n", http_status, chunk.memory);
            } else {
                json_object *choices = NULL, *message = NULL, *content = NULL;
                if (json_object_object_get_ex(response, "choices", &choices) &&
                    json_object_is_type(choices, json_type_array) && json_object_array_length(choices) > 0) {
                    json_object *first = json_object_array_get_idx(choices, 0);
                    if (json_object_is_type(first, json_type_object) &&
                        json_object_object_get_ex(first, "message", &message) &&
                        json_object_is_type(message, json_type_object) &&
                        json_object_object_get_ex(message, "content", &content) &&
                        json_object_is_type(content, json_type_string)) {
                        const char *text = json_object_get_string(content);
                        if (*text == '\n') ++text;
                        if (*text) answer = strdup(text);
                    }
                }
                call_status = answer ? "ok" : "empty-content";
                if (!answer)
                    fprintf(stderr, "[LLM] Missing or invalid choices[0].message.content (HTTP=%ld): %s\n",
                            http_status, chunk.memory);
            }
            if (response) json_object_put(response);
        }
        chat_llm_log_call(call_status, llm_model, latency,
                          llm_last_prompt_tokens, llm_last_completion_tokens, url);
        /* Every path releases the handle and buffer before retrying or returning. */
        curl_easy_cleanup(curl);
        free(chunk.memory);
        if (answer || !retry || attempt + 1 == tries) break;
        sleep(2);
    }
    curl_slist_free_all(headers);
    json_object_put(request);
    return answer;
}

char *construct_prompt_stall(char *protocol_name, char *examples, char *history)
{
    /* Note: state_ctx is embedded via llm_handle_plateau before calling this;
     * this base template is kept for backward compatibility. */
    char *template = "You are an expert protocol fuzzing assistant analyzing the %s protocol. "
                     "The fuzzer has reached a PLATEAU - no new code paths have been discovered recently.\n\n"
                     "**Communication History (most recent interactions):**\n\"\"\"%s\"\"\"\n\n"
                     "**Example Request Formats:**\n%s\n\n"
                     "**Your Task:**\n"
                     "1. Analyze the server's responses to identify:\n"
                     "   - Repeated or stuck patterns\n"
                     "   - Error messages that suggest unexplored features\n"
                     "   - State transitions that haven't been tested\n"
                     "   - Commands that might have optional parameters\n"
                     "2. Suggest ONE specific request that:\n"
                     "   - Explores a DIFFERENT code path (not just repeating recent commands)\n"
                     "   - Tests edge cases: unusual values, boundary conditions, rare features\n"
                     "   - Tries advanced protocol features if basic commands are exhausted\n"
                     "   - Uses different parameter combinations or formats\n\n"
                     "**Strategy Priorities:**\n"
                     "- If seeing permission errors: try different authentication states or paths\n"
                     "- If seeing parsing errors: try malformed but protocol-valid inputs\n"
                     "- If commands succeed: try rare optional flags, extended syntax, or protocol extensions\n"
                     "- Consider: uncommon commands, unusual sequences, protocol-specific edge cases\n\n"
                     "**Response Format (STRICT JSON):**\n"
                     "{\n"
                     "  \"analysis\": \"Identify the pattern/bottleneck and explain why this specific request should break through\",\n"
                     "  \"suggested_request\": \"EXACT_COMMAND with_parameters\\r\\n\"\n"
                     "}\n\n"
                     "Do NOT include markdown, code blocks, or any non-JSON text.";

    char *prompt = NULL;
    asprintf(&prompt, template, protocol_name, history, examples);

    // Use json-c library to build complete JSON array with proper escaping
    struct json_object *messages_array = json_object_new_array();
    
    struct json_object *system_msg = json_object_new_object();
    json_object_object_add(system_msg, "role", json_object_new_string("system"));
    json_object_object_add(system_msg, "content", json_object_new_string("You are a protocol fuzzing assistant that returns only valid JSON."));
    json_object_array_add(messages_array, system_msg);
    
    struct json_object *user_msg = json_object_new_object();
    json_object_object_add(user_msg, "role", json_object_new_string("user"));
    json_object_object_add(user_msg, "content", json_object_new_string(prompt));
    json_object_array_add(messages_array, user_msg);
    
    const char *json_str = json_object_to_json_string(messages_array);
    char *final_prompt = strdup(json_str);
    
    json_object_put(messages_array);
    free(prompt);

    return final_prompt;
}

/*
 * construct_prompt_stall_original:
 * Exact replica of ChatAFL baseline's construct_prompt_stall template.
 * Used ONLY when CHATAFL_NO_STATE_PROMPT ablation is active so the
 * ablation precisely measures the contribution of Opt's improved
 * prompt engineering (richer template + state-context + actions[]).
 *
 * Differences from Opt's construct_prompt_stall:
 *   - Template text: ChatAFL's original wording ("the communication
 *     history between the client and the server is as follows...")
 *   - System prompt: "You are a helpful assistant." (not "protocol
 *     fuzzing assistant that returns only valid JSON")
 *   - No structured task / strategy / response-format sections
 *
 * We still use json-c for JSON escaping (rather than ChatAFL's raw
 * asprintf) because that is a correctness fix (G1), not an
 * algorithmic contribution.
 */
char *construct_prompt_stall_original(char *protocol_name, char *examples,
                                      char *history)
{
    char *template =
        "In the %s protocol, the communication history between the "
        "%s client and the %s server is as follows."
        "The next proper client request that can affect the server's "
        "state are:\n\n"
        "Desired format of real client requests:\n"
        "%s"
        "Communication History:\n"
        "\"\"\"\n%s\"\"\"";

    char *prompt = NULL;
    asprintf(&prompt, template,
             protocol_name, protocol_name, protocol_name,
             examples ? examples : "",
             history  ? history  : "");

    /* Build JSON messages array with json-c (safe escaping). */
    struct json_object *messages_array = json_object_new_array();

    struct json_object *system_msg = json_object_new_object();
    json_object_object_add(system_msg, "role",
                           json_object_new_string("system"));
    json_object_object_add(system_msg, "content",
                           json_object_new_string("You are a helpful assistant."));
    json_object_array_add(messages_array, system_msg);

    struct json_object *user_msg = json_object_new_object();
    json_object_object_add(user_msg, "role",
                           json_object_new_string("user"));
    json_object_object_add(user_msg, "content",
                           json_object_new_string(prompt));
    json_object_array_add(messages_array, user_msg);

    const char *json_str = json_object_to_json_string(messages_array);
    char *final_prompt = strdup(json_str);

    json_object_put(messages_array);
    free(prompt);

    return final_prompt;
}

/*
 * llm_handle_plateau: state-aware plateau handler.
 * - Builds a rich prompt embedding state coverage stats (state_ctx)
 * - Asks LLM to return either suggested_request OR actions[]
 * - Passes response back as raw JSON for parent-side validation
 * state_ctx: JSON string like {"nodes":N,"edges":M,"growth_rate":X,...}, may be NULL
 */

/* Fix-23: Per-protocol format constraints injected into the plateau prompt.
 * Without this, LLM generates <<VALUE>> placeholders or wrong wire format
 * for SIP (kamailio) and DAAP (forked-daapd), producing protocol-rejected
 * suggestions that waste the entire plateau LLM call.
 *
 * Each entry: { protocol_name, format_constraint_paragraph }
 * The constraint is injected between the strategy description and the
 * "Decision Guide" so it has high attention weight. */
typedef struct { const char *name; const char *constraint; } ProtocolFormatConstraint;
static const ProtocolFormatConstraint PLATEAU_FORMAT_CONSTRAINTS[] = {
    {"SIP",
     "**SIP FORMAT CONSTRAINT (MANDATORY):**\n"
     "ALL suggested_request values MUST be complete SIP messages with REAL values.\n"
     "Mandatory headers: Via, From, To, CSeq, Call-ID, Max-Forwards, Content-Length.\n"
     "Use concrete values like: Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKabc123\n"
     "NEVER use <<VALUE>>, <<placeholder>>, or any placeholder syntax.\n"
     "Example: \"REGISTER sip:127.0.0.1 SIP/2.0\\r\\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK123\\r\\n"
     "From: <sip:alice@127.0.0.1>;tag=abc\\r\\nTo: <sip:alice@127.0.0.1>\\r\\n"
     "Call-ID: xyz@127.0.0.1\\r\\nCSeq: 1 REGISTER\\r\\nMax-Forwards: 70\\r\\nContent-Length: 0\\r\\n\\r\\n\"\n\n"},
    {"DAAP",
     "**DAAP FORMAT CONSTRAINT (MANDATORY):**\n"
     "ALL suggested_request values MUST be complete HTTP/1.1 GET requests with REAL integer values.\n"
     "session-id is a positive integer (use 1831879645 as default if unknown).\n"
     "revision-number starts at 1 and increments. pairing-guid is 0x0000000000000001.\n"
     "NEVER use <<session-id>>, <<VALUE>>, or any placeholder syntax.\n"
     "Example: \"GET /databases?session-id=1831879645&revision-number=1 HTTP/1.1\\r\\n"
     "Host: localhost:3689\\r\\nClient-DAAP-Version: 3.12\\r\\nAccept: */*\\r\\n\\r\\n\"\n\n"},
    {"FTP",
     "**FTP FORMAT CONSTRAINT:**\n"
     "suggested_request must be a single FTP command with REAL values (no <<VALUE>> placeholders).\n"
     "The command must end with \\r\\n. Use concrete paths like /pub, /tmp, filenames like test.txt.\n"
     "Example: \"STOR test.txt\\r\\n\" or \"CWD /pub\\r\\n\" or \"SITE CHMOD 755 /pub\\r\\n\"\n\n"},
    {"SMTP",
     "**SMTP FORMAT CONSTRAINT:**\n"
     "suggested_request must be a complete SMTP command sequence with REAL email addresses.\n"
     "NEVER use <<USERNAME>>, <<ADDRESS>>, or <<VALUE>> placeholders.\n"
     "Use concrete values: domains like test.com, addresses like user@test.com.\n"
     "Example: \"EHLO fuzzer.test\\r\\nMAIL FROM:<fuzz@test.com>\\r\\nRCPT TO:<victim@localhost>\\r\\n\"\n\n"},
    {"MQTT",
     "**MQTT FORMAT CONSTRAINT (MANDATORY):**\n"
     "Output each MQTT packet as one line in text form: TYPE Key=Value Key=Value.\n"
     "Valid types: CONNECT, PUBLISH, SUBSCRIBE, UNSUBSCRIBE, PUBACK, PUBREC, PUBREL, PUBCOMP, PINGREQ, DISCONNECT.\n"
     "CONNECT fields: ClientId, CleanSession (0/1), KeepAlive (int), WillTopic, WillMsg, User, Pass.\n"
     "PUBLISH fields: Topic, QoS (0/1/2), Retain (0/1), Payload, PacketId (int).\n"
     "SUBSCRIBE fields: PacketId, Topic, QoS.  UNSUBSCRIBE fields: PacketId, Topic.\n"
     "Example: \"CONNECT ClientId=fuzz_plateau CleanSession=1 KeepAlive=60\\n"
     "SUBSCRIBE PacketId=1 Topic=test/# QoS=1\\n"
     "PUBLISH Topic=test/a QoS=1 Retain=0 PacketId=2 Payload=hello\\n"
     "DISCONNECT\\n\"\n"
     "NEVER use binary, hex, or <<VALUE>> placeholders. Use CONCRETE values only.\n\n"},
    {NULL, NULL}
};

/* Stage-3 (CHATAFL_ATTACK_PROMPT, 2026-08-21): per-protocol vulnerability
 * patterns distilled from papers/漏洞发现经验 (papers/ChatAFLBugDetect.txt
 * Table VII / MBFuzzerBugDetect.txt / vulnerabilities.txt, 11 CVEs).
 *
 * DE-INJECTION (2026-10-10): this is per-target CVE knowledge — compiled
 * ONLY under CHATAFL_EMBED_CVE_CATALOG (make L3=1) and injected ONLY at
 * CHATAFL_KNOWLEDGE_LEVEL=3 (or an explicit CHATAFL_ATTACK_PROMPT env
 * override, which is inert in catalog-free builds).  The paper main arm
 * (level 1) gets the target-agnostic bug-class primitives below instead.
 */
#ifdef CHATAFL_EMBED_CVE_CATALOG
typedef struct { const char *name; const char *patterns; } ProtocolVulnPattern;
static const ProtocolVulnPattern PLATEAU_VULN_PATTERNS[] = {
    {"RTSP",
     "**RTSP BUG PATTERNS TO TRY (from real CVEs):**\n"
     "- PLAY then PAUSE then PLAY on a live session; then TEARDOWN and send more data\n"
     "- Repeat SETUP on the SAME stream with different client_port values\n"
     "- DESCRIBE with nested/deep URLs like rtsp://host/a/../a/../track1\n"
     "- SETUP with malformed Transport headers: unbalanced quotes, duplicate modes, ssrc= overflow\n"
     "- Large RTP interleaved frames: $<channel><big-length> after PLAY\n"},
    {"FTP",
     "**FTP BUG PATTERNS TO TRY (from real CVEs):**\n"
     "- CWD into very long paths (1000+ chars), deep ../ chains, then PWD/LIST\n"
     "- RNFR then RNTO with ../ traversal targets\n"
     "- State changes (DELE/MKD/STOR) immediately after a failed login sequence\n"},
    {"SIP",
     "**SIP BUG PATTERNS TO TRY (from real CVEs):**\n"
     "- INVITE with nested/duplicated Via or From headers (branch= repetition)\n"
     "- CANCEL and BYE for unknown Call-IDs; ACK with mismatched CSeq\n"
     "- SUBSCRIBE/NOTIFY without prior REGISTER or auth\n"},
    {"SMTP",
     "**SMTP BUG PATTERNS TO TRY (from real CVEs):**\n"
     "- AUTH PLAIN/LOGIN with oversized base64 blobs (1000+ chars)\n"
     "- MAIL FROM/RCPT TO with oversized local parts and nested <> paths\n"
     "- RSET mid-DATA; BDAT chunks with mismatched sizes\n"},
    {"MQTT",
     "**MQTT BUG PATTERNS TO TRY (from real CVEs):**\n"
     "- Subscribe then publish on a 200+ char topic; same for $shared/group/ topics\n"
     "- Persistent sessions: CONNECT CleanSession=0, SUBSCRIBE, DISCONNECT, reconnect, RESUBSCRIBE\n"
     "- Subscribe to $SYS/# and +/+/+ wildcards; retained publish on delivery\n"
     "- QoS 2 duplicate PUBREL with the same PacketId\n"},
    {"DAAP",
     "**DAAP BUG PATTERNS TO TRY:**\n"
     "- Reuse stale session-id after /logout; revision-number jumps and wraparounds\n"
     "- Very long database/playlist id query strings\n"},
    {NULL, NULL}
};
#endif /* CHATAFL_EMBED_CVE_CATALOG */

/* Bug-class generative primitives (de-injection 2026-10-10).
 *
 * Replaces the CVE-pattern bias for the paper main arm
 * (CHATAFL_KNOWLEDGE_LEVEL>=1).  This is target-agnostic generative
 * theory with public CWE grounding — no CVE, no target, no trigger
 * sequence is encoded; each primitive instantiates on whatever protocol
 * the LLM already knows from the seed examples and the learned state
 * data in the same prompt.  Injected at the same high-attention spot as
 * the Fix-23 constraint; the output path (JSON validation + P/U/R/G
 * admission) is unchanged. */
static const char PLATEAU_BUGCLASS_PRIMITIVES[] =
    "**BUG-CLASS GENERATIVE PRIMITIVES (target-agnostic):**\n"
    "- Lifecycle violation (CWE-416/672): after a resource-releasing step "
    "(teardown/logout/abort/delete/close), keep sending requests that "
    "re-enter the released resource; also alternate inverse transitions "
    "many times.\n"
    "- Repetition & amplification (CWE-401/772): repeat the same "
    "resource-acquiring request on one session/id far beyond normal "
    "counts.\n"
    "- Boundary stress (CWE-120/190): extreme field lengths, deep "
    "nesting, and numeric type limits (0, -1, INT_MAX, INT_MAX+1, "
    "4294967295) in any length/count/timeout/sequence field.\n"
    "- Structural asymmetry (CWE-1284/1286): unbalanced quotes/brackets/"
    "escapes; escape-decode mismatch (parser consumes 2 bytes, stores 1) "
    "amplified by long escape runs.\n"
    "- Identity confusion (CWE-284/672): stale or replayed tokens/ids "
    "from earlier steps, duplicate identifiers, cross-session or "
    "cross-connection references.\n\n";

/* Unified gate (knowledge-level.h); legacy CHATAFL_ATTACK_PROMPT still
 * overrides for historical ablation scripts (inert in catalog-free
 * builds). */
#define attack_prompt_enabled() kl_attack_prompt_on()

char *llm_handle_plateau(const char *protocol_name, const char *examples,
                         const char *history, const char *state_ctx) {
    if (!protocol_name) return NULL;

    /* Look up per-protocol format constraint for plateau prompt (Fix-23) */
    const char *proto_constraint = "";
    for (int ci = 0; PLATEAU_FORMAT_CONSTRAINTS[ci].name != NULL; ci++) {
        if (strcasecmp(protocol_name, PLATEAU_FORMAT_CONSTRAINTS[ci].name) == 0) {
            proto_constraint = PLATEAU_FORMAT_CONSTRAINTS[ci].constraint;
            break;
        }
    }

    /* Plateau bias paragraph: CVE patterns at level 3 (catalog builds
     * only), bug-class primitives at level 1+ (all builds).  Injected
     * next to the Fix-23 constraint so both land in the high-attention
     * region; the output path below is untouched. */
    const char *vuln_patterns = "";
    if (attack_prompt_enabled()) {
#ifdef CHATAFL_EMBED_CVE_CATALOG
        for (int ci = 0; PLATEAU_VULN_PATTERNS[ci].name != NULL; ci++) {
            if (strcasecmp(protocol_name, PLATEAU_VULN_PATTERNS[ci].name) == 0) {
                vuln_patterns = PLATEAU_VULN_PATTERNS[ci].patterns;
                break;
            }
        }
#endif /* CHATAFL_EMBED_CVE_CATALOG */
    } else if (kl_bugclass_enabled()) {
        vuln_patterns = PLATEAU_BUGCLASS_PRIMITIVES;
    }

    const char *mqtt_state_hint = "";
    if (strcasecmp(protocol_name, "MQTT") == 0) {
        mqtt_state_hint =
            "**MQTT-SPECIFIC EXPLORATION HINTS:**\n"
            "- Prioritize reconnect edges (CONNECT after DISCONNECT), duplicate CONNECT, and missing PacketId cases.\n"
            "- Use QoS 1/2 handshake chains, wildcard topics, retain toggles, and will/auth boundaries to force response diversity.\n"
            "- If the same request reaches a stable state, bias toward a nearby MQTT-only variant that changes QoS, topic scope, or session flags.\n\n";
    }

    /* Build state-aware prompt text */
    char *state_section = NULL;
    if (state_ctx && strlen(state_ctx) > 2) {
        asprintf(&state_section,
            "**Current Fuzzer State (IMPORTANT - use this to guide your suggestion):**\n"
            "%s\n\n"
            "Focus on protocol states with LOW coverage (low edge count). "
            "If growth_rate is near 0, the fuzzer is completely stuck - be creative.\n\n",
            state_ctx);
    } else {
        state_section = strdup("");
    }

    /* Build the full state-aware prompt string */
    char *raw_prompt = NULL;
    asprintf(&raw_prompt,
        "You are an expert protocol fuzzing assistant analyzing the %s protocol.\n"
        "The fuzzer has reached a PLATEAU - no new code paths have been discovered recently.\n\n"
        "%s"
        "**STATE DATA EXPLANATION:**\n"
        "The `states` array lists protocol states sorted by effectiveness (LOWEST first = most stuck).\n"
        "Each state has:\n"
        "  - id: use this exact number in set_target_state or prioritize_seeds\n"
        "  - paths: total execution paths covering this state\n"
        "  - paths_discovered: NEW paths found when fuzzing this state (low = stuck)\n"
        "  - selected_times: how many times fuzzer targeted this state\n"
        "  - fuzzs: total fuzzing attempts on this state\n"
        "  - seed_ids: exact seed indices reachable from this state (use in prioritize_seeds)\n"
        "  - is_error: true if state represents a server error response (4xx/5xx) — avoid targeting these\n"
        "  - productivity: paths_discovered / selected_times ratio (low = stuck, high = productive)\n\n"
        "**Communication History (most recent interactions):**\n\"\"\"%s\"\"\"\n\n"
        "**Example Request Formats:**\n%s\n\n"
        "%s"  /* Fix-23: per-protocol format constraint injected here */
        "%s"  /* Stage-3: CVE bug-pattern bias (CHATAFL_ATTACK_PROMPT) */
        "**Your Task:** Choose ONE strategy and return ONLY valid JSON:\n\n"
        "Strategy A - Send a new specific request:\n"
        "  {\"analysis\":\"...\", \"suggested_request\":\"EXACT_CMD\\r\\n\"}\n\n"
        "Strategy B - State-aware seed/state actions (use REAL ids from the states[] data above):\n"
        "  {\"analysis\":\"...\", \"actions\":[\n"
        "    {\"type\":\"set_target_state\", \"state_id\":ID},\n"
        "    {\"type\":\"prioritize_seeds\", \"seed_ids\":[N1,N2,N3]},\n"
        "    {\"type\":\"propose_mutations\", \"seed_id\":N, \"ops\":[\n"
        "       {\"op\":\"flip\",\"pos\":P,\"len\":L},\n"
        "       {\"op\":\"insert\",\"pos\":P,\"bytes_base64\":\"BASE64\"}\n"
        "    ]}\n"
        "  ]}\n\n"
        "**Decision Guide:**\n"
        "- growth_rate=0 AND states[0].paths_discovered=0: use set_target_state to switch to a DIFFERENT state\n"
        "- One state has high selected_times but low paths_discovered: use set_target_state + prioritize_seeds for that state\n"
        "- States with is_error=true AND productivity<0.01: SKIP these — they are error dead-ends (4xx/5xx)\n"
        "- States with seeds_count=0: cannot be targeted, skip them\n"
        "- Prefer states with is_error=false AND highest productivity — they are most likely to yield new coverage\n"
        "- Use the EXACT state id and seed_ids numbers from the states[] data — do NOT invent IDs\n"
        "- Strategy A (suggested_request) is best when history shows unrecognized commands\n"
        "- IMPORTANT: Always include at least one propose_mutations action alongside any\n"
        "  set_target_state or prioritize_seeds. Pure scheduling redirection without new\n"
        "  candidate proposals bypasses the admission validation pipeline entirely.\n\n"
        "%s"
        "Respond with ONLY valid JSON. No markdown, no code blocks, no explanation outside JSON.",
        protocol_name,
        state_section ? state_section : "",
        history ? history : "",
        examples ? examples : "",
        proto_constraint,    /* Fix-23: inject protocol-specific format constraint */
        vuln_patterns,       /* Stage-3: inject CVE-pattern bias when gated on */
        mqtt_state_hint);
    free(state_section);
    if (!raw_prompt) return NULL;

    /* Wrap in messages array for chat API */
    struct json_object *messages_array = json_object_new_array();
    struct json_object *system_msg = json_object_new_object();
    json_object_object_add(system_msg, "role", json_object_new_string("system"));
    json_object_object_add(system_msg, "content", json_object_new_string("You are a helpful protocol fuzzing assistant."));
    json_object_array_add(messages_array, system_msg);
    struct json_object *user_msg = json_object_new_object();
    json_object_object_add(user_msg, "role", json_object_new_string("user"));
    json_object_object_add(user_msg, "content", json_object_new_string(raw_prompt));
    json_object_array_add(messages_array, user_msg);
    free(raw_prompt);
    char *prompt = strdup(json_object_to_json_string(messages_array));
    json_object_put(messages_array);
    if (!prompt) return NULL;

    char *resp = chat_with_llm(prompt, LLM_DEFAULT_MODEL, STALL_RETRIES, 1.2);
    free(prompt);
    if (!resp) return NULL;

    if (is_garbage_response(resp, strlen(resp))) {
        free(resp);
        return NULL;
    }

    /* Try to parse resp as direct JSON first (LLM returned actions[] or suggested_request) */
    struct json_object *jtry = json_tokener_parse(resp);
    if (jtry) {
        /* LLM returned valid JSON directly — pass through as-is */
        const char *raw = json_object_to_json_string(jtry);
        char *out = strdup(raw);
        json_object_put(jtry);
        free(resp);
        return out;
    }

    /* Fallback: try to extract suggested_request from plain text */
    char *stall_message = extract_stalled_message(resp, strlen(resp));
    free(resp);
    if (!stall_message) return NULL;

    char *formatted = format_request_message(stall_message);
    if (!formatted) return NULL;

    /* Wrap into JSON for strict parent-side validation */
    struct json_object *jroot = json_object_new_object();
    json_object_object_add(jroot, "suggested_request", json_object_new_string(formatted));
    const char *json_str = json_object_to_json_string(jroot);
    char *out = strdup(json_str);
    json_object_put(jroot);
    free(formatted);
    return out;
}

/* Lookup table of per-protocol few-shot examples for grammar prompts.
 * Each entry shows ONE representative message of that protocol using the
 * exact <<VALUE>> template format so the LLM knows the expected output style.
 *
 * These strings are passed to json_object_new_string() which auto-escapes.
 * Use NATURAL C string escaping:
 *   \n       -> real newline  (json-c emits \n in JSON -> API sees newline)
 *   "        -> quote char    (json-c emits \" in JSON -> API sees ")
 *   \\r\\n   -> 4 chars \r\n (json-c emits \\r\\n  -> API sees \r\n text)
 */
typedef struct {
    const char *name;
    /* msg_type : short human-readable name of the示例 message type */
    const char *msg_type;
    /* example : the full "For the X protocol, the Y template is:\nY: [...]" string */
    const char *example;
} ProtocolExampleEntry;

static const ProtocolExampleEntry PROTOCOL_EXAMPLE_TABLE[] = {
    {"FTP",  "USER",
     "For the FTP protocol, the USER client request template is:\n"
     "USER: [\"USER <<VALUE>>\\r\\n\"]"},
    {"SMTP", "EHLO",
     "For the SMTP protocol, the EHLO client request template is:\n"
     "EHLO: [\"EHLO <<VALUE>>\\r\\n\"]"},
    {"RTSP", "DESCRIBE",
     "For the RTSP protocol, the DESCRIBE client request template is:\n"
     "DESCRIBE: [\"DESCRIBE <<VALUE>>\\r\\n\","
     "\"CSeq: <<VALUE>>\\r\\n\","
     "\"User-Agent: <<VALUE>>\\r\\n\","
     "\"Accept: <<VALUE>>\\r\\n\","
     "\"\\r\\n\"]"},
    {"HTTP", "GET",
     "For the HTTP protocol, the GET client request template is:\n"
     "GET: [\"GET <<VALUE>> HTTP/1.1\\r\\n\","
     "\"Host: <<VALUE>>\\r\\n\","
     "\"\\r\\n\"]"},
    {"SIP",  "REGISTER",
     "For the SIP protocol, the REGISTER client request template is:\n"
     "REGISTER: [\"REGISTER sip:<<VALUE>> SIP/2.0\\r\\n\","
     "\"Via: SIP/2.0/UDP <<VALUE>>\\r\\n\","
     "\"From: <sip:<<VALUE>>>\\r\\n\","
     "\"To: <sip:<<VALUE>>>\\r\\n\","
     "\"CSeq: <<VALUE>> REGISTER\\r\\n\","
     "\"\\r\\n\"]"},
    {"DAAP", "login",
     "For the DAAP protocol, the login client request template is:\n"
     "login: [\"GET /login?pairing-guid=<<VALUE>> HTTP/1.1\\r\\n\","
     "\"Host: <<VALUE>>\\r\\n\","
     "\"Client-DAAP-Version: <<VALUE>>\\r\\n\","
     "\"\\r\\n\"]"},
    {"MQTT", "CONNECT",
     "For the MQTT protocol, messages are described in text form (one per line).\n"
     "CONNECT: [\"CONNECT <<VALUE>>\\r\\n\","
     "\"ClientId: <<VALUE>>\\r\\n\","
     "\"CleanSession: <<VALUE>>\\r\\n\","
        "\"KeepAlive: <<VALUE>>\\r\\n\"]\n"
        "Prefer MQTT state-edge sequences such as CONNECT -> SUBSCRIBE -> PUBLISH -> UNSUBSCRIBE -> DISCONNECT,"
        " and include QoS 0/1/2, reconnect, will, auth, wildcard-topic, and duplicate-CONNECT variations."},
    {"DNS",  "QUERY",
     "For the DNS protocol, the QUERY request template is:\n"
     "QUERY: [\"<<VALUE>>\\x01\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00<<VALUE>>\"]"},
    {NULL, NULL, NULL}
};

char *construct_prompt_for_templates(char *protocol_name, char **final_msg)
{
    /* Find the same-protocol example to use as the few-shot anchor.
     * Showing the LLM one concrete example of the TARGET protocol guides it
     * to produce responses for the same command set rather than generic text. */
    const char *anchor_example = NULL;
    const char *anchor_msg_type = NULL;
    for (int i = 0; PROTOCOL_EXAMPLE_TABLE[i].name != NULL; i++) {
        if (strcasecmp(protocol_name, PROTOCOL_EXAMPLE_TABLE[i].name) == 0) {
            anchor_example  = PROTOCOL_EXAMPLE_TABLE[i].example;
            anchor_msg_type = PROTOCOL_EXAMPLE_TABLE[i].msg_type;
            break;
        }
    }
    /* Fallback for unknown protocols: use a generic format hint */
    if (anchor_example == NULL) {
        anchor_example  = PROTOCOL_EXAMPLE_TABLE[2].example; /* RTSP as generic shape */
        anchor_msg_type = "request";
    }

    char *msg = NULL;
    asprintf(&msg,
             "%s\n"
             "Following the same format above, for the %s protocol, "
             "list ALL client request message templates (not just %s):",
             anchor_example, protocol_name, anchor_msg_type);
    *final_msg = msg;
    
    // FIXED: Use json-c library to build complete JSON array with proper escaping
    struct json_object *messages_array = json_object_new_array();
    
    struct json_object *system_msg = json_object_new_object();
    json_object_object_add(system_msg, "role", json_object_new_string("system"));
    json_object_object_add(system_msg, "content", json_object_new_string("You are a helpful assistant."));
    json_object_array_add(messages_array, system_msg);
    
    struct json_object *user_msg = json_object_new_object();
    json_object_object_add(user_msg, "role", json_object_new_string("user"));
    json_object_object_add(user_msg, "content", json_object_new_string(msg));
    json_object_array_add(messages_array, user_msg);
    
    const char *json_str = json_object_to_json_string(messages_array);
    char *prompt_grammars = strdup(json_str);
    
    json_object_put(messages_array);

    return prompt_grammars;
}

char *construct_prompt_for_remaining_templates(char *protocol_name, char *first_question, char *first_answer)
{
    char *second_question = NULL;
    asprintf(&second_question, "For the %s protocol, other templates of client requests are:", protocol_name);

    // FIXED: Use json-c library to build complete JSON array with proper escaping
    struct json_object *messages_array = json_object_new_array();
    
    // System message
    struct json_object *system_msg = json_object_new_object();
    json_object_object_add(system_msg, "role", json_object_new_string("system"));
    json_object_object_add(system_msg, "content", json_object_new_string("You are a helpful assistant."));
    json_object_array_add(messages_array, system_msg);
    
    // First user question
    struct json_object *user_msg1 = json_object_new_object();
    json_object_object_add(user_msg1, "role", json_object_new_string("user"));
    json_object_object_add(user_msg1, "content", json_object_new_string(first_question));
    json_object_array_add(messages_array, user_msg1);
    
    // Assistant answer
    struct json_object *assistant_msg = json_object_new_object();
    json_object_object_add(assistant_msg, "role", json_object_new_string("assistant"));
    json_object_object_add(assistant_msg, "content", json_object_new_string(first_answer));
    json_object_array_add(messages_array, assistant_msg);
    
    // Second user question
    struct json_object *user_msg2 = json_object_new_object();
    json_object_object_add(user_msg2, "role", json_object_new_string("user"));
    json_object_object_add(user_msg2, "content", json_object_new_string(second_question));
    json_object_array_add(messages_array, user_msg2);
    
    const char *json_str = json_object_to_json_string(messages_array);
    char *prompt = strdup(json_str);
    
    json_object_put(messages_array);
    free(second_question);

    return prompt;
}

/* Check if a string is valid UTF-8 */
static int is_valid_utf8(const char *str, size_t len) {
    size_t i = 0;
    while (i < len) {
        unsigned char c = str[i];
        int bytes = 0;
        
        if (c <= 0x7F) {
            bytes = 1;
        } else if ((c & 0xE0) == 0xC0) {
            bytes = 2;
        } else if ((c & 0xF0) == 0xE0) {
            bytes = 3;
        } else if ((c & 0xF8) == 0xF0) {
            bytes = 4;
        } else {
            return 0; // Invalid UTF-8 start byte
        }
        
        // Check continuation bytes
        for (int j = 1; j < bytes; j++) {
            if (i + j >= len || (str[i + j] & 0xC0) != 0x80) {
                return 0; // Invalid continuation byte
            }
        }
        
        i += bytes;
    }
    return 1;
}

/* Count non-ASCII characters in a string */
static size_t count_non_ascii(const char *str, size_t len) {
    size_t count = 0;
    for (size_t i = 0; i < len; i++) {
        if ((unsigned char)str[i] > 127) {
            count++;
        }
    }
    return count;
}

/* Check if LLM response appears to be garbage */
static int is_garbage_response(const char *response, size_t len) {
    if (!response || len == 0) return 1;
    
    // Check 1: Must be valid UTF-8
    if (!is_valid_utf8(response, len)) {
        fprintf(stderr, "[!] Response validation failed: Invalid UTF-8 encoding\n");
        return 1;
    }
    
    // Check 2: Non-ASCII ratio shouldn't exceed 40%
    size_t non_ascii = count_non_ascii(response, len);
    float non_ascii_ratio = (float)non_ascii / len;
    if (non_ascii_ratio > 0.4) {
        fprintf(stderr, "[!] Response validation failed: Too many non-ASCII characters (%.1f%%)\n", 
                non_ascii_ratio * 100);
        return 1;
    }
    
    // Check 3: Should not be too short (less than 10 chars)
    if (len < 10) {
        fprintf(stderr, "[!] Response validation failed: Too short (%zu bytes)\n", len);
        return 1;
    }
    
    // Check 4: For JSON responses, check basic structure
    if (response[0] == '{' || response[0] == '[') {
        // Count braces
        int open_braces = 0, close_braces = 0;
        int open_brackets = 0, close_brackets = 0;
        for (size_t i = 0; i < len; i++) {
            if (response[i] == '{') open_braces++;
            if (response[i] == '}') close_braces++;
            if (response[i] == '[') open_brackets++;
            if (response[i] == ']') close_brackets++;
        }
        
        if (open_braces != close_braces || open_brackets != close_brackets) {
            fprintf(stderr, "[!] Response validation failed: Mismatched braces/brackets " 
                    "({:%d/%d, [:%d/%d)\n", 
                    open_braces, close_braces, open_brackets, close_brackets);
            return 1;
        }
    }
    
    return 0;
}

char *extract_stalled_message(char *message, size_t message_len)
{
    if (!message || message_len == 0) {
        fprintf(stderr, "[!] extract_stalled_message: NULL or empty message\n");
        return NULL;
    }
    
    // Step 1: Validate response quality
    if (is_garbage_response(message, message_len)) {
        fprintf(stderr, "[!] LLM response failed quality validation, discarding\n");
        return NULL;
    }
    
    fprintf(stderr, "[+] LLM response passed quality validation\n");
    
    // Step 2: Try to parse as JSON (new format)
    json_object *jobj = json_tokener_parse(message);
    if (jobj) {
        fprintf(stderr, "[+] Successfully parsed LLM response as JSON\n");
        
        // Extract suggested_request field
        json_object *req_obj;
        if (json_object_object_get_ex(jobj, "suggested_request", &req_obj)) {
            const char *req_str = json_object_get_string(req_obj);
            if (req_str && strlen(req_str) > 0) {
                fprintf(stderr, "[+] Extracted suggested request: %.50s...\n", req_str);
                char *result = strdup(req_str);
                json_object_put(jobj);
                return result;
            }
        }
        
        // Also try "request" field for backward compatibility
        if (json_object_object_get_ex(jobj, "request", &req_obj)) {
            const char *req_str = json_object_get_string(req_obj);
            if (req_str && strlen(req_str) > 0) {
                fprintf(stderr, "[+] Extracted request: %.50s...\n", req_str);
                char *result = strdup(req_str);
                json_object_put(jobj);
                return result;
            }
        }
        
        json_object_put(jobj);
        fprintf(stderr, "[!] JSON parsed but no 'suggested_request' or 'request' field found\n");
    }
    
    // Step 3: Fallback to regex extraction (old format)
    fprintf(stderr, "[*] Falling back to regex extraction for non-JSON response\n");
    
    int errornumber;
    size_t erroroffset;
    // After a lot of iterations, the model consistently responds with an empty line and then a line of text
    pcre2_code *extracter = pcre2_compile("\r?\n?.*?\r?\n", PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(extracter, NULL);
    int rc = pcre2_match(extracter, message, message_len, 0, 0, match_data, NULL);
    char *res = NULL;
    if (rc >= 0)
    {
        size_t *ovector = pcre2_get_ovector_pointer(match_data);
        res = strdup(message + ovector[1]);
        fprintf(stderr, "[+] Regex extraction result: %.50s...\n", res);
    } else {
        fprintf(stderr, "[!] Regex extraction failed\n");
    }

    pcre2_match_data_free(match_data);
    pcre2_code_free(extracter);

    return res;
}

/* Extract protocol commands from LLM's natural language response
 * This parses markdown code blocks and extracts actual protocol commands
 * Filters control characters (0x00-0x1F and 0x7F, except \r\n\t)
 * Returns: cleaned protocol data or NULL if extraction fails
 */
char *extract_protocol_commands_from_response(char *llm_response)
{
    if (!llm_response || strlen(llm_response) == 0) {
        return NULL;
    }

    size_t resp_len = strlen(llm_response);
    size_t capacity = resp_len + 1;
    char *extracted = calloc(capacity, 1);
    size_t out_pos = 0;
    
    // Look for code blocks: ```...``` or just protocol commands
    char *code_start = strstr(llm_response, "```");
    char *code_end = NULL;
    
    if (code_start) {
        // Skip past the opening ```
        code_start += 3;
        // Skip optional language identifier (e.g., ```ftp or ```plaintext)
        while (*code_start && (*code_start == '\n' || *code_start == '\r' || 
               (*code_start >= 'a' && *code_start <= 'z'))) {
            if (*code_start == '\n') break;
            code_start++;
        }
        if (*code_start == '\n') code_start++;
        
        // Find closing ```
        code_end = strstr(code_start, "```");
        if (code_end) {
            // Parse line by line within the code block
            char *line_start = code_start;
            while (line_start < code_end) {
                // Skip leading whitespace
                while (line_start < code_end && (*line_start == ' ' || *line_start == '\t')) {
                    line_start++;
                }
                
                // Find end of line
                char *line_end = line_start;
                while (line_end < code_end && *line_end != '\n' && *line_end != '\r') {
                    line_end++;
                }
                
                size_t line_len = line_end - line_start;
                
                // Check if this line looks like a protocol command
                if (line_len > 0 && line_len < 1024) {
                    int is_valid = 0;
                    /* Multi-protocol: FTP, SMTP, RTSP, SIP, HTTP, DAAP, MQTT */
                    const char *proto_commands[] = {
                        /* FTP */
                        "USER","PASS","CWD","PWD","LIST","RETR","STOR","DELE",
                        "MKD","RMD","RNFR","RNTO","QUIT","SYST","TYPE","PORT",
                        "PASV","ABOR","HELP","NOOP","STAT","APPE","REST","SIZE",
                        "MDTM","FEAT","OPTS","ALLO","CDUP","SMNT","REIN","STOU",
                        "STRU","MODE","EPSV","EPRT","MLSD","MLST","SITE",
                        /* SMTP */
                        "EHLO","HELO","MAIL","RCPT","DATA","RSET","VRFY","EXPN",
                        "AUTH","STARTTLS","SAML","SOML","SEND","TURN",
                        /* RTSP */
                        "OPTIONS","DESCRIBE","SETUP","PLAY","PAUSE","TEARDOWN",
                        "GET_PARAMETER","SET_PARAMETER","ANNOUNCE","RECORD","REDIRECT",
                        /* SIP */
                        "INVITE","ACK","BYE","CANCEL","REGISTER","INFO","PRACK",
                        "SUBSCRIBE","NOTIFY","UPDATE","REFER","MESSAGE","PUBLISH",
                        /* HTTP */
                        "GET","POST","PUT","DELETE","HEAD","CONNECT","TRACE","PATCH",
                        /* MQTT (Fix-13: packet type names for binary protocol) */
                        "CONNECT","CONNACK","PUBLISH","PUBACK","PUBREC","PUBREL",
                        "PUBCOMP","SUBSCRIBE","SUBACK","UNSUBSCRIBE","UNSUBACK",
                        "PINGREQ","PINGRESP","DISCONNECT",
                        NULL
                    };
                    for (int i = 0; proto_commands[i] != NULL; i++) {
                        size_t cmd_len = strlen(proto_commands[i]);
                        if (line_len >= cmd_len &&
                            strncmp(line_start, proto_commands[i], cmd_len) == 0 &&
                            (line_len == cmd_len || line_start[cmd_len] == ' ' || line_start[cmd_len] == '\r')) {
                            is_valid = 1;
                            break;
                        }
                    }
                    
                    // Skip comment lines (starting with # or ; or //)
                    if (line_len > 0 && (line_start[0] == '#' || line_start[0] == ';' || 
                        (line_len > 1 && line_start[0] == '/' && line_start[1] == '/'))) {
                        is_valid = 0;
                    }
                    
                    if (is_valid) {
                        // Ensure we have space
                        if (out_pos + line_len + 2 >= capacity) {
                            capacity = (out_pos + line_len + 100) * 2;
                            extracted = realloc(extracted, capacity);
                        }
                        
                        // Copy the line byte-by-byte, filtering control chars and comments
                        for (size_t j = 0; j < line_len; j++) {
                            unsigned char byte = (unsigned char)line_start[j];
                            
                            // Check for inline comments (;, #, //)
                            if (byte == ';' || byte == '#' ||
                                (j + 1 < line_len && byte == '/' && line_start[j+1] == '/')) {
                                // Stop at comment - don't copy anything after this
                                break;
                            }
                            
                            // Filter control characters (0x00-0x1F and 0x7F)
                            // BUT keep \r (0x0D), \n (0x0A), \t (0x09)
                            if ((byte < 0x20 && byte != '\r' && byte != '\n' && byte != '\t') || byte == 0x7F) {
                                // Skip control characters like \x01, \x02, etc.
                                continue;
                            }
                            
                            extracted[out_pos++] = byte;
                        }
                        
                        // Trim trailing whitespace
                        while (out_pos > 0 && (extracted[out_pos-1] == ' ' || extracted[out_pos-1] == '\t')) {
                            out_pos--;
                        }
                        
                        // Add newline if not present
                        if (out_pos > 0 && extracted[out_pos-1] != '\n') {
                            extracted[out_pos++] = '\n';
                        }
                    }
                }
                
                // Move to next line
                line_start = line_end;
                while (line_start < code_end && (*line_start == '\n' || *line_start == '\r')) {
                    line_start++;
                }
            }
        }
    }
    
    // If no code block found or extraction failed, try to extract commands from entire response
    if (out_pos == 0) {
        char *line_start = llm_response;
        char *response_end = llm_response + resp_len;
        
        while (line_start < response_end) {
            // Skip leading whitespace
            while (line_start < response_end && (*line_start == ' ' || *line_start == '\t')) {
                line_start++;
            }
            
            char *line_end = line_start;
            while (line_end < response_end && *line_end != '\n' && *line_end != '\r') {
                line_end++;
            }
            
            size_t line_len = line_end - line_start;
            
            if (line_len > 0 && line_len < 1024) {
                /* Multi-protocol: FTP, SMTP, RTSP, SIP, HTTP, DAAP, MQTT */
                const char *proto_commands[] = {
                    /* FTP */
                    "USER","PASS","CWD","PWD","LIST","RETR","STOR","DELE",
                    "MKD","RMD","RNFR","RNTO","QUIT","SYST","TYPE","PORT",
                    "PASV","ABOR","HELP","NOOP","STAT","APPE","REST","SIZE",
                    "MDTM","FEAT","OPTS","ALLO","CDUP","SMNT","REIN","STOU",
                    "STRU","MODE","EPSV","EPRT","MLSD","MLST","SITE",
                    /* SMTP */
                    "EHLO","HELO","MAIL","RCPT","DATA","RSET","VRFY","EXPN",
                    "AUTH","STARTTLS","SAML","SOML","SEND","TURN",
                    /* RTSP */
                    "OPTIONS","DESCRIBE","SETUP","PLAY","PAUSE","TEARDOWN",
                    "GET_PARAMETER","SET_PARAMETER","ANNOUNCE","RECORD","REDIRECT",
                    /* SIP */
                    "INVITE","ACK","BYE","CANCEL","REGISTER","INFO","PRACK",
                    "SUBSCRIBE","NOTIFY","UPDATE","REFER","MESSAGE","PUBLISH",
                    /* HTTP */
                    "GET","POST","PUT","DELETE","HEAD","CONNECT","TRACE","PATCH",
                    NULL
                };
                for (int i = 0; proto_commands[i] != NULL; i++) {
                    size_t cmd_len = strlen(proto_commands[i]);
                    if (line_len >= cmd_len &&
                        strncmp(line_start, proto_commands[i], cmd_len) == 0 &&
                        (line_len == cmd_len || line_start[cmd_len] == ' ' || line_start[cmd_len] == '\r')) {
                        
                        if (out_pos + line_len + 2 >= capacity) {
                            capacity = (out_pos + line_len + 100) * 2;
                            extracted = realloc(extracted, capacity);
                        }
                        
                        // Copy byte-by-byte with control character filtering
                        for (size_t j = 0; j < line_len; j++) {
                            unsigned char byte = (unsigned char)line_start[j];
                            
                            // Check for inline comments
                            if (byte == ';' || byte == '#' ||
                                (j + 1 < line_len && byte == '/' && line_start[j+1] == '/')) {
                                break;
                            }
                            
                            // Filter control characters (keep \r, \n, \t only)
                            if ((byte < 0x20 && byte != '\r' && byte != '\n' && byte != '\t') || byte == 0x7F) {
                                continue;
                            }
                            
                            extracted[out_pos++] = byte;
                        }
                        
                        // Trim trailing whitespace
                        while (out_pos > 0 && (extracted[out_pos-1] == ' ' || extracted[out_pos-1] == '\t')) {
                            out_pos--;
                        }
                        
                        // Add newline if not present
                        if (out_pos > 0 && extracted[out_pos-1] != '\n') {
                            extracted[out_pos++] = '\n';
                        }
                        break;
                    }
                }
            }
            
            // Move to next line
            line_start = line_end;
            while (line_start < response_end && (*line_start == '\n' || *line_start == '\r')) {
                line_start++;
            }
        }
    }
    
    // Finalize the result
    if (out_pos == 0) {
        free(extracted);
        return NULL;
    }
    
    extracted[out_pos] = '\0';
    return extracted;
}

char *format_request_message(char *message)
{

    int message_len = strlen(message);
    int max_len = message_len;
    int res_len = 0;
    char *res = calloc(message_len, sizeof(char));
    for (int i = 0; i < message_len; i++)
    {
        // If an \n is not padded with an \r before, we add it
        if (message[i] == '\n' && (i == 0 || (message[i - 1] != '\r')))
        {
            if (res_len == max_len)
            {
                res = realloc(res, max_len + 10);
                max_len += 10;
            }
            res[res_len++] = '\r';
        }

        if (res_len == max_len)
        {
            res = realloc(res, max_len + 10);
            max_len += 10;
        }
        res[res_len++] = message[i];
    }

    // Add \r\n\r\n to ensure that the packet is accepted
    for (int i = 0; i < 2; i++)
    {
        if (res_len == max_len)
        {
            res = realloc(res, max_len + 10);
            max_len += 10;
        }
        res[res_len++] = '\r';
        if (res_len == max_len)
        {
            res = realloc(res, max_len + 10);
            max_len += 10;
        }
        res[res_len++] = '\n';
    }

    if (res_len == max_len)
    {
        res = realloc(res, max_len + 1);
        max_len++;
    }
    res[res_len++] = '\0';
    free(message);
    return res;
}

char *construct_prompt_for_protocol_message_types(char *protocol_name)
{
    /***
     * Prompt to ask the protocol states as follow:
     * ```
     * In the RTSP protocol, the protocol states are:
     *
     * Desired format:
     * <comma_separated_list_of_states_in_uppercase>
     * ```
     * ***/
    char *prompt = NULL;

    // transfer the prompt into string
    asprintf(&prompt, "In the %s protocol, the message types are: \\n\\nDesired format:\\n<comma_separated_list_of_states_in_uppercase_and_without_whitespaces>", protocol_name);

    return prompt;
}

char *construct_prompt_for_requests_to_states(const char *protocol_name,
                                              const char *protocol_state,
                                              const char *example_requests)
{
    /***
     Prompt to ask the sequence of client requests to reach a protocol state as follows:
        ```
        In the RTSP protocol, if the server just starts, to reach the PLAYING state, the sequence of client requests can be:
        DESCRIBE rtsp://127.0.0.1:8554/aacAudioTest RTSP/1.0
        CSeq: 2
        User-Agent: ./testRTSPClient (LIVE555 Streaming Media v2018.08.28)
        Accept: application/sdp

        SETUP rtsp://127.0.0.1:8554/aacAudioTest/track1 RTSP/1.0
        CSeq: 3
        User-Agent: ./testRTSPClient (LIVE555 Streaming Media v2018.08.28)
        Transport: RTP/AVP;unicast;client_port=38784-38785

        PLAY rtsp://127.0.0.1:8554/aacAudioTest/ RTSP/1.0
        CSeq: 4
        User-Agent: ./testRTSPClient (LIVE555 Streaming Media v2018.08.28)
        Session: 000022B8
        Range: npt=0.000-

        Similarly, in the RTSP protocol, if the server just starts, to reach the RECORD state, the sequence of client requests can be:
     ***/

    // Transfer formats of example_requests
    json_object *example_requests_json = json_object_new_string(example_requests);
    const char *example_requests_json_str = json_object_to_json_string(example_requests_json);

    json_object *protocol_state_json = json_object_new_string(protocol_state);
    const char *protocol_state_json_str = json_object_to_json_string(protocol_state_json);

    char *prompt = NULL;

    int example_request_len = strlen(example_requests_json_str) - 2;
    if (example_request_len > EXAMPLE_SEQUENCE_PROMPT_LENGTH)
    {
        example_request_len = EXAMPLE_SEQUENCE_PROMPT_LENGTH;
    }

    // Build content string
    char *content = NULL;
    asprintf(&content,
             "In the %s protocol, if the server just starts, to reach the INIT state, the sequence of client requests can be:\n"
             "%.*s\nSimilarly, in the %s protocol, if the server just starts, to reach the %.*s state, the sequence of client requests can be:\n",
             protocol_name,
             example_request_len,
             example_requests_json_str + 1,
             protocol_name,
             (int)strlen(protocol_state_json_str) - 2,
             protocol_state_json_str + 1);

    // Use json-c to properly construct the entire JSON structure
    json_object *messages_array = json_object_new_array();
    
    json_object *system_msg = json_object_new_object();
    json_object_object_add(system_msg, "role", json_object_new_string("system"));
    json_object_object_add(system_msg, "content", json_object_new_string("You are a helpful assistant."));
    json_object_array_add(messages_array, system_msg);
    
    json_object *user_msg = json_object_new_object();
    json_object_object_add(user_msg, "role", json_object_new_string("user"));
    json_object_object_add(user_msg, "content", json_object_new_string(content));
    json_object_array_add(messages_array, user_msg);
    
    const char *json_str = json_object_to_json_string(messages_array);
    prompt = strdup(json_str);
    
    json_object_put(messages_array);
    free(content);
    json_object_put(protocol_state_json);
    json_object_put(example_requests_json);

    return prompt;
}

void extract_message_grammars(char *answers, klist_t(gram) * grammar_list)
{

    char *ptr = answers;
    int len = strlen(answers);

    while (ptr < answers + len)
    {
        char *start = strchr(ptr, '[');
        if (start == NULL)
            break;
        char *end = strchr(start, ']');
        if (end == NULL)
            break;
        int count = end - start + 1;
        char *temp = (char *)ck_alloc(count + 1);
        strncpy(temp, start, count);
        temp[count] = '\0';
        ptr = end + 1;

        // conver temp to json object and save it to the list
        json_object *jobj = json_tokener_parse(temp);
        *kl_pushp(gram, grammar_list) = jobj;

        // printf("%s\n", temp);
    }
}

int parse_pattern(pcre2_code *replacer, pcre2_match_data *match_data, const char *str, size_t len, char *pattern)
{
    strcat(pattern, "(?:");
    // offset == 3;
    int rc = pcre2_match(replacer, str, len, 0, 0, match_data, NULL);

    if (rc < 0)
    {
        switch (rc)
        {
        case PCRE2_ERROR_NOMATCH:
            // printf("No match for %s!\n", str);
            break;
        default:
            // printf("Matching error %d\n", rc);
            break;
        }
        pcre2_match_data_free(match_data);
        pcre2_code_free(replacer);
        return 0;
    }
    // printf("RC is %d\n",rc);
    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
    // for(int i = 1; i<rc;i++){
    //     printf("Start %d, end %d\n",ovector[2*i],ovector[2*i+1]);
    // }

    if (rc == 4)
    { // matched the first option - there is a special value
        strncat(pattern, str + ovector[2], ovector[3] - ovector[2]);
        // offset += ovector[3] - ovector[2];

        strcat(pattern, "(.*)");
        // offset += 3;

        strncat(pattern, str + ovector[6], ovector[7] - ovector[6]);
        // offset += ovector[7] - ovector[6];
    }
    else if (rc == 5)
    {
        // matched the second option - there is no special value
        strncat(pattern, str + ovector[8], ovector[9] - ovector[8]);
        // offset += ovector[9] - ovector[8];
    }
    else
    {
        FATAL("Regex groups were updated but not the handling code.");
    }
    strcat(pattern, ")");
    return 1;
}

// If successful, puts 2 patterns in the patterns array, the first one is the header, the second is the fields
// Else returns an array with the first element being NULL
char *extract_message_pattern(const char *header_str, khash_t(field_table) * field_table, pcre2_code **patterns, int debug_file, const char *debug_file_name)
{
    int errornumber;
    size_t erroroffset;
    char header_pattern[128] = {0};
    char fields_pattern[1024] = {0};
    pcre2_code *replacer = pcre2_compile("(?:(.*)(?:<<(.*)>>)(.*))|(.+)", PCRE2_ZERO_TERMINATED, PCRE2_DOTALL, &errornumber, &erroroffset, NULL);
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(replacer, NULL);
    char *message_type = NULL;
    // int offset = 0;
    /**
     * Example output
     * patterns[0] = (?:PLAY (.*)\r\n)
     * patterns[1] = (?|(?:CSeq: (.*)\r\n)|(?:User-Agent: (.*)\r\n)|(?:Range: (.*)\r\n)|(?:\r\n))
     */

    {
        // We use the string in such an escaped format for easier debugging as the regex library supports parsing it properly
        // The string contains quotations so they are ignored
        header_str++;

        int message_len = 0;
        while (header_str[message_len] != '\0' 
        && header_str[message_len] != ' ' 
        && header_str[message_len] != '\n' 
        && header_str[message_len] != '\r' 
        && header_str[message_len] != '\\' )
        {
            message_len++;
        }
        message_type = ck_alloc(message_len + 1);
        memcpy(message_type, header_str, message_len);
        message_type[message_len] = '\0';

        size_t len = strlen(header_str) - 1;
        strcat(header_pattern, "^"); // Ensure that it captures the start of the string
        if (!parse_pattern(replacer, match_data, header_str, len, header_pattern))
        {
            patterns[0] = NULL;
            return NULL;
        }
    }

    int first = 1;

    strcat(fields_pattern, "(?|");
    for (khiter_t field_t_iter = kh_begin(field_table); field_t_iter != kh_end(field_table); ++field_t_iter)
    {
        if (!kh_exist(field_table, field_t_iter) || kh_value(field_table, field_t_iter) < (TEMPLATE_CONSISTENCY_COUNT / 2 + (TEMPLATE_CONSISTENCY_COUNT % 2)))
            continue;

        if (!first)
        {
            strcat(fields_pattern, "|");
        }
        else
        {
            first = 0;
        }

        json_object *field_v = json_object_new_string(kh_key(field_table, field_t_iter));
        const char *str = json_object_to_json_string(field_v);
        // We use the string in such an escaped format for easier debugging as the regex library supports parsing it properly
        // The string contains quotations so they are ignored
        str++;
        size_t len = strlen(str) - 1;
        int matched = parse_pattern(replacer, match_data, str, len, fields_pattern);
        json_object_put(field_v);
        if (!matched)
        {
            patterns[0] = NULL;
            return NULL;
        }
    }

    strcat(fields_pattern, ")");

    if (first == 1)
    { // convert from (?|) to (.+) when the group is empty
        fields_pattern[1] = '.';
        fields_pattern[2] = '+';
    }

    pcre2_match_data_free(match_data);
    pcre2_code_free(replacer);
    printf("Header pattern is %s\n", header_pattern);
    printf("Fields pattern is %s\n", fields_pattern);

    if (debug_file != -1 && debug_file_name != NULL)
    {
        ck_write(debug_file, header_pattern, strlen(header_pattern), debug_file_name);
        ck_write(debug_file, "\n", 1, debug_file_name);
        ck_write(debug_file, fields_pattern, strlen(fields_pattern), debug_file_name);
    }

    {
        pcre2_code *p = pcre2_compile(header_pattern, PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
        pcre2_jit_compile(p, PCRE2_JIT_COMPLETE);
        patterns[0] = p;
    }
    {
        pcre2_code *p = pcre2_compile(fields_pattern, PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);
        pcre2_jit_compile(p, PCRE2_JIT_COMPLETE);
        patterns[1] = p;
    }
    return message_type;
}

range_list starts_with(char *line, int length, pcre2_code *pattern)
{
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(pattern, NULL);

    int rc = pcre2_match(pattern, line, length, 0, 0, match_data, NULL); // find the first range

    // printf("starts_with rc is %d\n", rc);
    if (rc < 0)
    {
        switch (rc)
        {
        case PCRE2_ERROR_NOMATCH:
            // printf("No match!\n");
            break;
        default:
            // printf("Matching error %d\n", rc);
            break;
        }
        pcre2_match_data_free(match_data);
        range_list res;
        kv_init(res);
        return res;
    }

    range_list dyn_ranges;
    kv_init(dyn_ranges);
    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
    for (int i = 1; i < rc; i++)
    {
        if (ovector[2 * i] == -1)
            continue;
        // printf("Group %d %d %d\n",i, ovector[2 * i], ovector[2 * i + 1]);
        range v = {.start = ovector[2 * i], .len = ovector[2 * i + 1] - ovector[2 * i], .mutable = 1};
        kv_push(range, dyn_ranges, v);
        // kv_push(range, dyn_ranges, v);
        //  ranges[0][i - 1] = v;
    }
    range v = {.start = ovector[0], .len = ovector[1] - ovector[0], .mutable = 1};
    kv_push(range, dyn_ranges, v); // add the global range at the end

    pcre2_match_data_free(match_data);
    return dyn_ranges;
}

range_list get_mutable_ranges(char *line, int length, int offset, pcre2_code *pattern)
{
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(pattern, NULL);

    range_list dyn_ranges;
    kv_init(dyn_ranges);

    for (;;) // catch all the other ranges
    {
        int rc = pcre2_match(pattern, line, length, offset, 0, match_data, NULL);
        if (rc < 0)
        {
            switch (rc)
            {
            case PCRE2_ERROR_NOMATCH:
                // printf("No match!\n");
                break;
            default:
                // printf("Matching error %d\n", rc);
                break;
            }
            pcre2_match_data_free(match_data);
            match_data = NULL;
            break;
        }
        PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
        if (offset != ovector[0])
        {
            range v = {.start = offset, .len = ovector[0] - offset, .mutable = 1};
            kv_push(range, dyn_ranges, v);
        }

        // printf("Matched over %d %d\n", ovector[0], ovector[1]);
        for (int i = 1; i < rc; i++)
        {
            if (ovector[2 * i] == -1)
                continue;
            // printf("Group %d %d %d\n",i, ovector[2 * i], ovector[2 * i + 1]);
            range v = {.start = ovector[2 * i], .len = ovector[2 * i + 1] - ovector[2 * i], .mutable = 1};
            kv_push(range, dyn_ranges, v);
            // ranges[0][i - 1] = v;
        }
        if (offset == ovector[1])
        { // in the case the match is empty, we just move a step forward
            offset++;
        }
        else
        {
            offset = ovector[1];
        }
    }

    if (offset < length) // catch anything past the last matched pattern
    {
        range v = {.start = offset, .len = length - offset, .mutable = 1};
        kv_push(range, dyn_ranges, v);
    }

    if (match_data != NULL)
    {
        pcre2_match_data_free(match_data);
    }
    return dyn_ranges;
}

char *unescape_string(const char *input)
{
    size_t length = strlen(input);
    char *output = (char *)malloc((length + 1) * sizeof(char));

    if (output == NULL)
    {
        printf("Memory allocation failed.\n");
        return NULL;
    }

    size_t i, j = 0;
    for (i = 0; i < length; i++)
    {
        if (input[i] == '\\')
        {
            i++; // Skip the backslash
            switch (input[i])
            {
            case 'n':
                output[j++] = '\n';
                break;
            case 't':
                output[j++] = '\t';
                break;
            case 'r':
                output[j++] = '\r';
                break;
            case '\\':
                output[j++] = '\\';
                break;
            default:
                output[j++] = input[i];
                break;
            }
        }
        else
        {
            output[j++] = input[i];
        }
    }

    output[j] = '\0'; // Add null-terminator to the output string
    return output;
}

void write_new_seeds(char *enriched_file, char *contents)
{
    FILE *fp = fopen(enriched_file, "w");
    if (fp == NULL)
    {
        printf("Error in opening the file %s\n", enriched_file);
        exit(1);
    }

    // remove the newline and whiltespace in the beginning of the string if any
    while (contents[0] == '\n' || contents[0] == ' ' || contents[0] == '\t' || contents[0] == '\r')
    {
        contents++;
    }

    // Check if last 4 characters of the client_request_answer string are \r\n\r\n
    // If not, add them
    int len = strlen(contents);
    if (contents[len - 1] != '\n' || contents[len - 2] != '\r' || contents[len - 3] != '\n' || contents[len - 4] != '\r')
    {
        fprintf(fp, "%s\r\n\r\n", contents);
    }
    else
    {
        fprintf(fp, "%s", contents);
    }

    fclose(fp);
}

char *format_string(char *state_string)
{
    // remove the newline and whiltespace in the beginning of the string if any
    while (state_string[0] == '\n' || state_string[0] == ' ' || state_string[0] == '\t' || state_string[0] == '\r')
    {
        state_string++;
    }

    int len = strlen(state_string);
    while (state_string[len - 1] == '\n' || state_string[len - 1] == '\r' || state_string[len - 1] == ' ' || state_string[len - 1] == '.')
    {
        state_string[len - 1] = '\0';
        len--;
    }

    return state_string;
}

/***
 * Get the protocol states based on self-consistency check
 * pass the parameters: protocol_name, states_set, states_string
 ***/
void get_protocol_message_types(char *state_prompt, khash_t(strSet) * states_set)
{
    khash_t(strMap) *state_to_times = kh_init(strMap); // map from state to times

    for (int i = 0; i < CONFIDENT_TIMES; i++)
    {
        char *state_answer = chat_with_llm(state_prompt, LLM_DEFAULT_MODEL, MESSAGE_TYPE_RETRIES, 0.5);
        if (state_answer == NULL)
            continue;
        // printf("## Answer from LLM:\n %s\n", state_answer);

        state_answer = format_string(state_answer);

        char *state_tokens = strtok(state_answer, ",");
        while (state_tokens != NULL)
        {
            char *protocol_state = state_tokens;
            protocol_state = format_string(protocol_state);
            // save the state to the map
            int ret;
            khiter_t k = kh_put(strMap, state_to_times, protocol_state, &ret);
            if (ret == 0)
            {
                kh_value(state_to_times, k)++;
            }
            else
            {
                kh_value(state_to_times, k) = 1;
            }

            state_tokens = strtok(NULL, ",");
        }
    }

    // traverse the map and get the states whose times are larger than 0.5 * CONFIDENT_TIMES
    for (khiter_t k = kh_begin(state_to_times); k != kh_end(state_to_times); ++k)
    {
        if (kh_exist(state_to_times, k))
        {
            if (kh_value(state_to_times, k) >= 0.5 * CONFIDENT_TIMES)
            {
                const char *protocol_state = kh_key(state_to_times, k);
                // add the state to the set
                int ret;
                kh_put(strSet, states_set, protocol_state, &ret);
            }
        }
    }
}

khash_t(strSet) * duplicate_hash(khash_t(strSet) * set)
{
    khash_t(strSet) *new_set = kh_init(strSet);

    for (khiter_t k = kh_begin(set); k != kh_end(set); ++k)
    {
        if (kh_exist(set, k))
        {
            const char *val = kh_key(set, k);
            int ret;
            kh_put(strSet, new_set, val, &ret);
        }
    }

    return new_set;
}

// message_set_list generate_combinations(khash_t(strSet)* sequence, int size)
// {
//     if(size == 0)
//     {
//         message_set_list output;
//         kv_init(output);
//         kv_push(khash_t(strSet)*,output,kh_init(strSet));
//         return output;
//     }
//     else
//     {
//         message_set_list subcombinations = generate_combinations(sequence,size-1);
//         message_set_list newCombinations;
//         kv_init(newCombinations);
//         for(int i = 0; i < kv_size(subcombinations);i++)
//         {
//             khash_t(strSet)* target = kv_A(subcombinations,i);
//             khiter_t sequence_iter;
//             for (sequence_iter = kh_begin(sequence); sequence_iter != kh_end(sequence); sequence_iter++)
//             {
//                 if (!kh_exist(sequence, sequence_iter))
//                     continue;
//                 khiter_t k = kh_get(strSet, target, kh_val(sequence,sequence_iter));
//                 if (kh_exist(target, k))
//                     continue;
//                 khash_t(strSet)* newCombination = duplicate_hash(target);
//                 int absent;
//                 kh_put(strSet,newCombination,kh_val(sequence,sequence_iter))    
//             }
//         }
//         return newCombinations;
//     }
// }
void make_combination(khash_t(strSet)* sequence, const char** data , message_set_list* res,khiter_t st, khiter_t end, int index, int size);

message_set_list message_combinations(khash_t(strSet)* sequence, int size)
{
    message_set_list res;
    kv_init(res);
    const char* data[size];
    make_combination(sequence,data, &res, kh_begin(sequence), kh_end(sequence), 0, size);
    return res;
}

void make_combination(khash_t(strSet)* sequence, const char** data , message_set_list* res,khiter_t st, khiter_t end,
                     int index, int size)
{

    if (index == size)
    {
        khash_t(strSet)* combination = kh_init(strSet);
        int absent;
        for (int j=0; j<size; j++){
            kh_put(strSet,combination, data[j],&absent );
        }
        kv_push(khash_t(strSet)*,*res,combination);
        return;
    }
    for (khiter_t i=st; i != end && end-i+1 >= size-index; i++)
    {
        if(!kh_exist(sequence,i))
            continue;
        data[index] = kh_key(sequence,i);
        make_combination(sequence, data,res, i+1, end, index+1, size);
    }
}



int min(int a, int b) {
    return a < b ? a : b;
}

/* ============================================
 * Fix-10a: Lightweight LLM response cleaner.
 *
 * Problem discovered in R9: returning raw LLM output (Fix-9a) fixed RTSP
 * by preserving multi-region structure, but BROKE SMTP because:
 *   1. Markdown ``` fencing becomes a garbage SMTP region
 *   2. LLM inserts blank lines between commands -> empty \r\n regions
 *      (SMTP splits on \r\n, not \r\n\r\n like RTSP)
 *   3. LLM uses placeholders like <<USERNAME>> instead of real values
 *
 * Solution: protocol-aware cleaning that preserves structure for
 * header-based protocols (RTSP/SIP/HTTP) while cleaning up line-based
 * protocols (FTP/SMTP). This is NOT the old extract_protocol_commands_
 * from_response() which stripped URLs/headers/CSeq -- this only removes
 * the wrapper garbage while keeping actual protocol content intact.
 * ============================================ */
char *clean_llm_response(const char *response, const char *protocol_name)
{
    if (!response || !*response)
        return NULL;

    size_t resp_len = strlen(response);
    size_t cap = resp_len + 64;
    char *out = calloc(cap, 1);
    if (!out) return NULL;
    size_t out_pos = 0;

    /* Determine if this is a line-based protocol (region = \r\n)
     * vs a header-based protocol (region = \r\n\r\n).            */
    int line_based = 0;
    if (protocol_name) {
        if (strcasecmp(protocol_name, "FTP") == 0 ||
            strcasecmp(protocol_name, "SMTP") == 0) {
            line_based = 1;
        }
    }

    const char *end = response + resp_len;

    /* --- Phase 1: Skip LLM preamble text before the first code fence ---
     * Many LLM responses start with:
     *   "Certainly! Below is the modified sequence...\n```\n"
     * or just natural language.  We skip to inside the ``` block. */
    const char *content_start = NULL;

    /* Check for opening ``` fence */
    const char *fence = strstr(response, "```");
    if (fence) {
        /* Jump past ```[language]\n */
        content_start = fence + 3;
        while (content_start < end && *content_start != '\n' && *content_start != '\r')
            content_start++;  /* skip optional language tag */
        if (content_start < end && *content_start == '\r') content_start++;
        if (content_start < end && *content_start == '\n') content_start++;
    } else {
        /* No fence -- use entire response */
        content_start = response;
    }

    /* --- Phase 2: Find the end boundary (closing ``` or end of string) --- */
    const char *content_end = end;
    if (fence) {
        const char *close_fence = strstr(content_start, "```");
        if (close_fence)
            content_end = close_fence;
    }

    /* --- Phase 3: Copy content with protocol-aware blank-line handling --- */
    const char *src = content_start;

    while (src < content_end) {
        /* Find end of current line */
        const char *line_end = src;
        while (line_end < content_end && *line_end != '\n' && *line_end != '\r')
            line_end++;

        size_t line_len = line_end - src;

        /* Check if line is blank (empty or only whitespace) */
        int is_blank = 1;
        for (size_t i = 0; i < line_len; i++) {
            if (src[i] != ' ' && src[i] != '\t') {
                is_blank = 0;
                break;
            }
        }

        if (is_blank) {
            if (line_based) {
                /* For SMTP/FTP: skip blank lines entirely.
                 * This prevents empty \r\n regions from being created
                 * by extract_requests_smtp(). */
                /* (do nothing -- just advance past this line) */
            } else {
                /* For RTSP/SIP/HTTP: blank lines ARE the region delimiter
                 * (\r\n\r\n), so we MUST preserve them. */
                if (out_pos + 2 < cap) {
                    out[out_pos++] = '\r';
                    out[out_pos++] = '\n';
                }
            }
        } else {
            /* Non-blank line: copy it */

            /* Fix-12 defense: For line-based protocols, strip trailing
             * literal \r\n text (4 chars: backslash-r-backslash-n) that
             * the LLM may output despite being told not to.  Without this,
             * unescape_string() later converts the literal \r\n to real
             * \r\n, producing double-CRLF between commands. */
            size_t effective_len = line_len;
            if (line_based) {
                /* Strip one or more trailing literal \r\n sequences */
                while (effective_len >= 4 &&
                       src[effective_len - 4] == '\\' &&
                       src[effective_len - 3] == 'r'  &&
                       src[effective_len - 2] == '\\' &&
                       src[effective_len - 1] == 'n') {
                    effective_len -= 4;
                }
                /* Also strip trailing literal \r (2 chars) without \n */
                if (effective_len >= 2 &&
                    src[effective_len - 2] == '\\' &&
                    src[effective_len - 1] == 'r') {
                    effective_len -= 2;
                }
                /* If stripping leaves an empty line, skip it */
                if (effective_len == 0) {
                    src = line_end;
                    if (src < content_end && *src == '\r') src++;
                    if (src < content_end && *src == '\n') src++;
                    continue;
                }
            }

            /* Ensure capacity */
            if (out_pos + effective_len + 4 >= cap) {
                cap = (out_pos + effective_len + 64) * 2;
                out = realloc(out, cap);
                if (!out) return NULL;
            }

            memcpy(out + out_pos, src, effective_len);
            out_pos += effective_len;

            /* Add \r\n line terminator */
            out[out_pos++] = '\r';
            out[out_pos++] = '\n';
        }

        /* Advance past line ending */
        src = line_end;
        if (src < content_end && *src == '\r') src++;
        if (src < content_end && *src == '\n') src++;
    }

    /* Trim trailing whitespace/newlines */
    while (out_pos > 0 && (out[out_pos-1] == '\r' || out[out_pos-1] == '\n' ||
                           out[out_pos-1] == ' '  || out[out_pos-1] == '\t'))
        out_pos--;

    /* For header-based protocols, ensure we end with \r\n\r\n
     * so the last request is properly terminated */
    if (!line_based && out_pos > 0) {
        if (out_pos + 5 >= cap) {
            cap = out_pos + 8;
            out = realloc(out, cap);
        }
        out[out_pos++] = '\r';
        out[out_pos++] = '\n';
        out[out_pos++] = '\r';
        out[out_pos++] = '\n';
    }
    /* For line-based protocols, ensure we end with \r\n */
    if (line_based && out_pos > 0) {
        if (out_pos + 3 >= cap) {
            cap = out_pos + 4;
            out = realloc(out, cap);
        }
        out[out_pos++] = '\r';
        out[out_pos++] = '\n';
    }

    if (out_pos == 0) {
        free(out);
        return NULL;
    }

    out[out_pos] = '\0';
    fprintf(stderr, "[clean_llm_response] %s: %zu -> %zu bytes (line_based=%d)\n",
            protocol_name ? protocol_name : "?", resp_len, out_pos, line_based);
    return out;
}

/* Per-protocol hints for the enrichment prompt */
typedef struct {
    const char *name;
    const char *sequences;    /* typical command/message sequences to explore */
    const char *errors;       /* error/boundary cases specific to this protocol */
    const char *format_hint;  /* protocol-specific format instructions for LLM */
} EnrichHintEntry;

static const EnrichHintEntry ENRICH_HINT_TABLE[] = {
    /* Fix-12: Removed literal \\r\\n from line-based format hints.
     * Root cause of bftpd IPSM-edge regression (-37.3%):
     *  - The old hint told the LLM to terminate each command with \\r\\n,
     *    so the LLM output literal \\r\\n text at the end of each line.
     *  - clean_llm_response() ALSO added real \\r\\n after each line.
     *  - unescape_string() then converted the literal \\r\\n → real \\r\\n.
     *  - Result: \\r\\n\\r\\n (double CRLF) between every FTP command.
     *  - FTP is line-based: each command should be separated by a single \\r\\n.
     *  - The extra blank line between commands confused the FTP server and
     *    degraded IPSM state coverage (116 edges vs baseline's 185).
     * Fix: Tell the LLM to put one command per line WITHOUT literal \\r\\n.
     *      clean_llm_response() will add the correct \\r\\n terminator.
     *
     * Fix-22: Protocol-specific hint improvements for underperforming protocols.
     * Root cause analysis (exim/proftpd/kamailio/forked-daapd):
     *   - FTP (proftpd): Original hint only listed basic commands; advanced
     *     ProFTPD-specific cmds (SITE CHMOD/CHOWN, MLSD, MLST, CLNT, HOST,
     *     LANG, MOD_FACTS features) were never in the enrichment seeds.
     *   - SMTP (exim): Missing DATA body content, BDAT chunking, AUTH variants
     *     (GSSAPI/EXTERNAL), ESMTP SIZE/BODY/ENVID params, MIME multipart.
     *   - SIP (kamailio): No concrete header values → LLM generated <<VALUE>>
     *     placeholders → kamailio rejected 100% of enriched seeds (400 Bad Request).
     *   - DAAP (forked-daapd): No concrete session-id/revision-number → every
     *     enriched seed had placeholder values → forked-daapd rejected them all.
     */
    {"FTP",
     /* Fix-22a: ProFTPD advanced commands and edge-case coverage */
     "USER+PASS+CWD+LIST+RETR+STOR+DELE+MKD+RMD+RNFR+RNTO+QUIT, PASV+PORT transfers, "
     "FEAT+OPTS negotiation, SITE CHMOD/CHOWN/SYMLINK extended commands, "
     "MLSD+MLST machine-readable listing, CLNT client identification, "
     "HOST virtual hosting, LANG language negotiation, "
     "STAT+SYST+HELP+NOOP keepalive, TYPE A/I/E/L, MODE S/B/C, "
     "APPE append, REST restart, SIZE+MDTM file info, STOU unique-store, "
     "ALLO pre-allocate, REIN reinitialize session",
     "oversized filenames (256+ chars), path traversal (/../../../etc/passwd), "
     "invalid TYPE/MODE params, restart offsets beyond file size, MKD deeply nested paths, "
     "RNFR without RNTO, SITE commands with boundary values, non-ASCII LANG tags",
     "One command per line, NO blank lines between commands. "
     "Do NOT write \\r\\n — just use normal line breaks. "
     "Use CONCRETE values — never <<VALUE>> placeholders. "
     "Example:\nUSER anonymous\nPASS guest@\nSYST\nFEAT\nTYPE I\nPASV\nMLSD /\nSITE CHMOD 755 /pub\nSTAT\nQUIT"},
    {"SMTP",
     /* Fix-22b: exim advanced SMTP coverage with DATA body and BDAT */
     "EHLO+MAIL+RCPT+DATA body+QUIT, AUTH LOGIN/PLAIN/GSSAPI/EXTERNAL, "
     "VRFY/EXPN probing, RSET+MAIL chains, BDAT chunked transfer, "
     "MAIL FROM with SIZE/BODY/ENVID/RET ESMTP params, "
     "RCPT TO with NOTIFY/ORCPT params, STARTTLS negotiation, "
     "DATA with MIME multipart bodies, oversized DATA content, "
     "multi-recipient sessions, NOOP+HELP+RSET keepalive",
     "malformed addresses (missing @, bare LF, null bytes in headers), "
     "oversized headers (8KB+), repeated RSET without EHLO, bare CR/LF in DATA, "
     "MAIL without RCPT, nested MIME boundaries, AUTH with invalid base64, "
     "BDAT with wrong chunk size, RCPT to non-existent local user",
     "One command per line, NO blank lines between commands. "
     "Do NOT write \\r\\n — just use normal line breaks. "
     "Use CONCRETE values — never <<USERNAME>> or <<VALUE>> placeholders. "
     "For DATA body: write body lines directly, end with a line containing only a dot (.). "
     "Example:\nEHLO fuzzer.test\nMAIL FROM:<fuzz@test.com> SIZE=1024\n"
     "RCPT TO:<victim@localhost>\nDATA\nFrom: fuzz@test.com\nSubject: test\n\nHello body\n."},
    {"RTSP",
     "DESCRIBE+SETUP+PLAY+PAUSE+TEARDOWN, interleaved channel requests, OPTIONS probing",
     "invalid session IDs, malformed stream URIs, unsupported transport specs, bad CSeq",
     "Each request includes: command URL RTSP/1.0, headers (CSeq, Transport, Session), "
     "and is terminated by a blank line (\\r\\n\\r\\n). "
     "Use CONCRETE values. Example CSeq: 1, Session: 12345678"},
    /* Fix-23: HTTP entry extended to cover BOTH lighttpd (plain HTTP) AND
     * forked-daapd (DAAP-over-HTTP), since both are launched with -P HTTP.
     * The old HTTP entry only described plain HTTP GET/POST; the DAAP paths
     * (/login, /databases, /server-info, /update, /ctrl-int) were never
     * included in enrichment seeds, so forked-daapd stayed at shallow
     * coverage despite Fix-22d adding a dead "DAAP" key that was never matched.
     *
     * Fix: HTTP sequences now include DAAP subpaths with concrete session-id
     * and revision-number values so forked-daapd enriched seeds are accepted
     * by the server (session-id must be a real integer returned by /login).
     *
     * The existing {"DAAP", ...} entry below is kept for documentation but
     * will never be reached at runtime — protocol_name is always "HTTP".
     */
    {"HTTP",
     /* General HTTP */
     "GET/POST/PUT/DELETE/OPTIONS/HEAD sequences, pipelining, chunked transfer, keep-alive, "
     /* DAAP-over-HTTP paths for forked-daapd */
     "DAAP login (/login?pairing-guid=...), /server-info, /update?revision-number=N, "
     "/databases?session-id=S, /databases/1/items?session-id=S, "
     "/databases/1/containers?session-id=S, /databases/1/items/ID.mp3?session-id=S, "
     "/ctrl-int/1/playstatus?session-id=S, /ctrl-int/1/pause?session-id=S, "
     "/ctrl-int/1/nextitem?session-id=S, /logout?session-id=S, "
     "/content-codes, /databases/1/browse/artists?session-id=S",
     "path traversal (/../), oversized headers, invalid methods, malformed URIs, HTTP/0.9, "
     "invalid DAAP session-id (0 or negative), mismatched revision-number, "
     "missing Host header, malformed pairing-guid (wrong length), "
     "requests with stale/too-large revision-number",
     "Each request includes: METHOD path HTTP/1.1, headers (Host, Content-Type, etc.), "
     "terminated by blank line (\\r\\n\\r\\n). Use CONCRETE values — NEVER placeholders. "
     "For DAAP: session-id is a positive integer (e.g. 1831879645), revision-number starts at 1. "
     "Example sequence (lighttpd):\n"
     "GET /index.html HTTP/1.1\nHost: localhost:8080\n\n"
     "POST /upload HTTP/1.1\nHost: localhost:8080\nContent-Length: 5\n\nhello\n"
     "Example sequence (forked-daapd):\n"
     "GET /login?pairing-guid=0x0000000000000001 HTTP/1.1\nHost: localhost:3689\nClient-DAAP-Version: 3.12\nContent-Length: 0\n\n"
     "GET /server-info HTTP/1.1\nHost: localhost:3689\nClient-DAAP-Version: 3.12\n\n"
     "GET /databases?session-id=1831879645&revision-number=1 HTTP/1.1\nHost: localhost:3689\nClient-DAAP-Version: 3.12\n\n"
     "GET /databases/1/items?session-id=1831879645&meta=dmap.itemname,daap.songartist HTTP/1.1\nHost: localhost:3689\nClient-DAAP-Version: 3.12\n"},
    {"SIP",
     /* Fix-22c: kamailio — concrete SIP header values prevent <<VALUE>> placeholders */
     "REGISTER+INVITE+ACK+BYE stateful dialog, CANCEL mid-dialog, OPTIONS capability, "
     "re-REGISTER with Expires: 0 (de-register), REFER blind/attended transfer, "
     "SUBSCRIBE+NOTIFY event packages (presence/dialog/message-summary), "
     "MESSAGE instant messaging, PUBLISH event state, INFO mid-dialog, "
     "PRACK provisional ACK, UPDATE session refresh",
     "malformed SIP URIs (sip:@, sip::5060, empty user), missing mandatory headers "
     "(Via/From/To/CSeq/Call-ID/Max-Forwards), duplicate Via, invalid CSeq order, "
     "loop detection (Max-Forwards: 0), oversized headers, INVITE without SDP body",
     "Each request includes: METHOD sip:URI SIP/2.0, mandatory headers (Via, From, To, "
     "CSeq, Call-ID, Max-Forwards, Content-Length), terminated by blank line (\\r\\n\\r\\n). "
     "Use CONCRETE values — NEVER placeholders. "
     "Use a DIFFERENT Call-ID for each distinct dialog (e.g. call-1@127.0.0.1, call-2@127.0.0.1). "
     "Example REGISTER:\nREGISTER sip:127.0.0.1 SIP/2.0\n"
     "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK776\n"
     "From: <sip:alice@127.0.0.1>;tag=1928301774\nTo: <sip:alice@127.0.0.1>\n"
     "Call-ID: a84b4c76e66710@127.0.0.1\nCSeq: 1 REGISTER\nMax-Forwards: 70\n"
     "Contact: <sip:alice@127.0.0.1:5060>\nExpires: 3600\nContent-Length: 0\n"},
    /* NOTE (Fix-23): This {"DAAP",...} entry is NEVER reached at runtime.
     * forked-daapd is launched with -P HTTP, so protocol_name == "HTTP" always.
     * All DAAP-over-HTTP knowledge has been merged into the {"HTTP",...} entry above.
     * Kept here only as documentation / for any future -P DAAP experiment. */
    {"DAAP",
     /* Fix-22d: forked-daapd — concrete session-id and revision-number values */
     "login+server-info+update+databases+items+containers+playlists sequences, "
     "session management (login with pairing-guid, logout with session-id), "
     "content-codes enumeration (/content-codes), browse by artist/album/genre, "
     "database update polling with revision-number, playlist item listing, "
     "DACP remote control (ctrl-int, now-playing, playqueue-contents)",
     "invalid session-id (random large int or zero), mismatched revision-number, "
     "malformed pairing-guid (wrong length/format), unsupported meta tags, "
     "requests without session-id, requests with stale/too-large revision-number",
     "Each request is HTTP/1.1 GET with DAAP path and query params, "
     "terminated by blank line (\\r\\n\\r\\n). Use CONCRETE integer values — never placeholders. "
     "session-id is a positive integer (e.g. 1831879645), revision-number starts at 1. "
     "Example sequence:\nGET /login?pairing-guid=0x0000000000000001 HTTP/1.1\n"
     "Host: localhost:3689\nClient-DAAP-Version: 3.12\nAccept: */*\nContent-Length: 0\n\n"
     "GET /server-info HTTP/1.1\nHost: localhost:3689\nClient-DAAP-Version: 3.12\n\n"
     "GET /databases?session-id=1831879645&revision-number=1 HTTP/1.1\n"
     "Host: localhost:3689\nClient-DAAP-Version: 3.12\n"},
    {"MQTT",
     "CONNECT+SUBSCRIBE+PUBLISH+UNSUBSCRIBE+DISCONNECT, PINGREQ/PINGRESP, QoS 0/1/2",
     "oversized client IDs, invalid topic filters, will message variations, clean session",
     "Output each MQTT packet as one line in text form: TYPE Key=Value Key=Value. "
     "Example: CONNECT ClientId=test CleanSession=1 KeepAlive=60. "
     "Valid types: CONNECT, PUBLISH, SUBSCRIBE, UNSUBSCRIBE, PUBACK, PUBREC, PUBREL, PUBCOMP, PINGREQ, DISCONNECT. "
     "PUBLISH fields: Topic, QoS, Retain, Payload. SUBSCRIBE fields: PacketId, Topic, QoS"},
    {"DNS",
     "A/AAAA/MX/NS/PTR/TXT/SOA query sequences, recursive vs iterative",
     "malformed labels, oversized names, EDNS options, DNSSEC flag variations",
     "Output DNS queries in text-representable format with query type and domain"},
    {NULL, NULL, NULL, NULL}
};

char *enrich_sequence(char *sequence, khash_t(strSet) *missing_message_types, const char *protocol_name)
{
    /* Look up protocol-specific hints */
    const EnrichHintEntry *hint = NULL;
    if (protocol_name) {
        for (int i = 0; ENRICH_HINT_TABLE[i].name != NULL; i++) {
            if (strcasecmp(protocol_name, ENRICH_HINT_TABLE[i].name) == 0) {
                hint = &ENRICH_HINT_TABLE[i];
                break;
            }
        }
    }
    const char *proto   = (protocol_name && *protocol_name) ? protocol_name : "network";
    const char *seqs    = hint ? hint->sequences : "command sequences and state transitions";
    const char *errors  = hint ? hint->errors    : "invalid parameters, oversized values, boundary inputs";
    const char *fmt     = hint ? hint->format_hint : "Output each request in complete wire-ready format";

    /* Fix-9c: Rewritten prompt to produce COMPLETE protocol requests.
     * Uses protocol-specific format_hint from ENRICH_HINT_TABLE so that
     * header-based protocols (RTSP/SIP/HTTP) get \r\n\r\n instructions
     * while line-based protocols (FTP/SMTP) get \r\n instructions.
     * This avoids the baseline's problem of no format guidance AND
     * avoids the old prompt's problem of RTSP-centric hardcoding. */
    const char *prompt_template =
        "The following is one sequence of %s client requests:\n"
        "%.*s\n\n"
        "Please add %.*s client requests in the proper locations "
        "to maximize protocol state coverage.\n\n"
        "IMPORTANT: Output the COMPLETE modified request sequence in "
        "wire-ready format. Format: %s\n\n"
        "Tips for coverage: try %s and trigger %s.\n\n"
        "Output ONLY the complete modified request sequence:";

    int missing_fields_len = 0;
    int missing_fields_capacity = 100;
    char *missing_fields_seq = calloc(missing_fields_capacity, 1);

    khiter_t k;
    int i = 0;
    for (k = kh_begin(missing_message_types); 
    k != kh_end(missing_message_types) && i < min(MAX_ENRICHMENT_MESSAGE_TYPES, kh_size(missing_message_types)); 
    ++k)
    {
        if (!kh_exist(missing_message_types, k))
            continue;
        ++i; // Increment only after seeing a message type
        const char *message_type = kh_key(missing_message_types, k);
        int needed_len = strlen(message_type) + 2; // add for the ', '

        if (missing_fields_len + needed_len > missing_fields_capacity)
        {
            missing_fields_capacity += 2 * needed_len;
            missing_fields_seq = realloc(missing_fields_seq, missing_fields_capacity);
        }

        memcpy(missing_fields_seq + missing_fields_len, message_type, strlen(message_type));
        memcpy(missing_fields_seq + missing_fields_len + needed_len - 2, ", ", 2);

        missing_fields_len += needed_len;
    }
    missing_fields_len -= 2; // ignore the last ', '

    char *prompt = NULL;
    char *content = NULL;

    // FIXED: Use json-c library properly to handle ALL escaping automatically
    // json-c will correctly escape control characters as \uXXXX in the final JSON

    // Build the content string from protocol-aware template
    // Format specs: %s(proto), %.*s(sequence), %.*s(missing), %s(fmt), %s(seqs), %s(errors)
    asprintf(&content, prompt_template,
             proto,
             (int)strlen(sequence), sequence,
             missing_fields_len, missing_fields_seq,
             fmt,
             seqs,
             errors);
    
    // Create JSON array using json-c (this handles ALL escaping correctly)
    struct json_object *messages_array = json_object_new_array();
    
    // System message
    struct json_object *system_msg = json_object_new_object();
    json_object_object_add(system_msg, "role", json_object_new_string("system"));
    json_object_object_add(system_msg, "content", json_object_new_string("You are a helpful assistant."));
    json_object_array_add(messages_array, system_msg);
    
    // User message - json-c will automatically escape control characters
    struct json_object *user_msg = json_object_new_object();
    json_object_object_add(user_msg, "role", json_object_new_string("user"));
    json_object_object_add(user_msg, "content", json_object_new_string(content));
    json_object_array_add(messages_array, user_msg);
    
    // Get JSON string - json-c handles all escaping including \x01, \x04, \x1e etc.
    const char *json_str = json_object_to_json_string(messages_array);
    prompt = strdup(json_str);
    
    // Cleanup
    json_object_put(messages_array);  // This frees system_msg and user_msg too
    free(content);
    free(missing_fields_seq);

    char *response = chat_with_llm(prompt, LLM_DEFAULT_MODEL, ENRICHMENT_RETRIES, 0.5);

    free(prompt);

    /* Fix-10a: Protocol-aware response cleaning.
     *
     * History of this code path:
     *  - Original: used extract_protocol_commands_from_response() which stripped
     *    URLs, headers, CSeq -> only bare command names -> 1 region per seed
     *    -> IPSM edges: 72 (vs baseline 128)
     *  - Fix-9a: returned raw LLM output -> fixed RTSP (edges: 132) but broke
     *    SMTP because raw output contains markdown ```, blank lines between
     *    commands, and <<PLACEHOLDER>> tokens -> 59 SMTP regions (vs 7 original)
     *    -> coverage dropped from 7439 to 5845
     *  - Fix-10a: clean_llm_response() removes markdown fencing and LLM preamble,
     *    and for line-based protocols (SMTP/FTP) collapses blank lines while
     *    preserving blank lines for header-based protocols (RTSP/SIP/HTTP) where
     *    \r\n\r\n is the region delimiter.
     */
    if (!response) return NULL;

    char *cleaned = clean_llm_response(response, protocol_name);
    free(response);

    if (!cleaned) {
        fprintf(stderr, "[enrich] clean_llm_response returned NULL, skipping\n");
        return NULL;
    }

    return cleaned;
}

// // For debugging
// // gcc -g -o chat-llm chat-llm.c chat-llm.h -lcurl -ljson-c -lpcre2-8
// int main(int argc, char **argv)
// {
//     char *protocol_name = argv[1];
//     char *in_dir = argv[2];
//     khash_t(strSet) *states_set = kh_init(strSet);

//     char *state_prompt = construct_prompt_for_protocol_states(protocol_name);

//     // Get protocol states
//     get_protocol_message_types(state_prompt, states_set);

//     // traverse the states_set
//     khiter_t k;
//     for (k = kh_begin(states_set); k != kh_end(states_set); ++k)
//     {
//         if (kh_exist(states_set, k))
//         {
//             const char *protocol_state = kh_key(states_set, k);
//             printf("## State_traverse: %s\n", protocol_state);
//         }
//     }

//     // Get seeds to states and save them to the in_dir
//     get_seeds_to_states(in_dir, states_set, protocol_name);

//     // char *prompt = NULL;
//     // asprintf(&prompt, "user: The colors of flowers:\\nassistant: red and yellow.\\nuser: Other colors are:");
//     // printf("## Prompt to LLM:\n %s\n", prompt);
//     // char *answer = chat_with_llm(prompt, "codex-auto-review");
//     // printf("## Answer from LLM:\n %s\n", answer);

//     char *protocol_name = argv[1];
//     khash_t(consistency_table) *const_table = kh_init(consistency_table);
//     klist_t(rang) *protocol_patterns = kl_init(rang);

//     for (int iter = 0; iter < 5; iter++)
//     {

//         char *templates_prompt = construct_prompt_for_templates(protocol_name);
//         char *templates_answer = chat_with_llm(templates_prompt, "codex-auto-review");
//         // printf("## Answer from LLM:\n %s\n", templates_answer);
//         char *remaining_prompt = construct_prompt_for_remaining_templates(protocol_name, templates_prompt, templates_answer);
//         // printf("remaining prompt is:\n %s\n", remaining_prompt);
//         char *remaining_templates = chat_with_llm(remaining_prompt, "codex-auto-review");
//         // printf("## Remaining templates:\n %s\n", remaining_templates);

//         char *combined_templates = NULL;
//         asprintf(&combined_templates, "%s\n%s", templates_answer, remaining_templates);

//         printf("The final info is\n%s\n", combined_templates);
//         klist_t(gram) *grammar_list = kl_init(gram);
//         extract_message_grammars(combined_templates, grammar_list);

//         kliter_t(gram) * iter;
//         for (iter = kl_begin(grammar_list); iter != kl_end(grammar_list); iter = kl_next(iter))
//         {
//             json_object *jobj = kl_val(iter);

//             json_object *header = json_object_array_get_idx(jobj, 0);

//             int absent;

//             const char *header_str = json_object_get_string(header);

//             khiter_t k = kh_put(consistency_table, const_table, header_str, &absent);
//             if (absent)
//             {
//                 khash_t(field_table) *field_table = kh_init(field_table);
//                 kh_value(const_table, k) = field_table;
//             }

//             for (int i = 1; i < json_object_array_length(jobj); i++)
//             {
//                 const char *v = json_object_get_string(json_object_array_get_idx(jobj, i));
//                 khash_t(field_table) *field_table = kh_value(const_table, k);
//                 khiter_t field_k = kh_put(field_table, field_table, v, &absent);
//                 if (absent)
//                 {
//                     kh_value(field_table, field_k) = 0;
//                 }
//                 kh_value(field_table, field_k)++;
//             }
//         }
//         kl_destroy_gram(grammar_list);
//     }

//     for (khiter_t con_t_iter = kh_begin(const_table); con_t_iter != kh_end(const_table); ++con_t_iter)
//     {
//         if (kh_exist(const_table, con_t_iter))
//         {
//             pcre2_code **patterns = ck_alloc(2 * sizeof(pcre2_code *));

//             khash_t(field_table) *field_table = kh_value(const_table, con_t_iter);
//             const char* header_str = json_object_to_json_string(json_object_new_string(kh_key(const_table, con_t_iter)));

//             extract_message_pattern_k(header_str,field_table, patterns);
//             *kl_pushp(rang, protocol_patterns) = patterns;
//         }
//     }

//     char *demo_lines[] = {

//         "DESCRIBE 123\r\n"
//         "CSeq: 1212313\r\n"
//         "User-Agent: 1212313\r\n"
//         "Accept: 1212313\r\n"
//         "\r\n",

//         "DESCRIBE 123\r\n"
//         "DESCRIBE 123\r\n"
//         "User-Agent: 1212313\r\n"
//         "CSeq: 1212313\r\n"
//         "Accept: 1212313\r\n"
//         "\r\n",

//         "DESCRIBE 123\r\n"
//         "1231321321321"
//         "User-Agent: 1212313\r\n"
//         "CSeq: 1212313\r\n"
//         "Accept: 1212313\r\n"
//         "\r\n"
//         "1231321321321",

//         "DESCRIBE 123\r\n"
//         "1231321321321"
//         "User-Agent: 1212313\r\n"
//         "CSeq: 1212313\r1231321321321\n"
//         "Accept: 1212313\r\n"
//         "\r\n"
//         "1231321321321",

//         "PLAY 123\r\n"
//         "CSeq: 1212313\r\n"
//         "DESCRIBE 123\r\n"
//         "User-Agent: 1212313\r\n"
//         "Session: 1212313\r\n"
//         "Range: 1212313\r\n"
//         "\r\n",

//     };

// char* answers = "For the RTSP protocol, the DESCRIBE client request template is:"
//     "{\"DESCRIBE\":\"string\\r\\n\",\"CSeq:\":\"integer\\r\\n\",\"User-Agent:\":\"string\\r\\n\",\"Accept:\":\"string\\r\\n\\r\\n\"}."
//     "For the RTSP protocol, the DESCRIBE client request template is:{\"DESCRIBE\":\"string\\r\\n\",\"CSeq:\":\"integer\\r\\n\",\"User-Agent:\":\"string\\r\\n\",\"Accept:\":\"string\\r\\n\\r\\n\"}";

// for (int demo = 0; demo < sizeof(demo_lines) / sizeof(char *); demo++)
// {
//     printf("\nTrying to match \n%s\n\n", demo_lines[demo]);
//     int max_rc = -1;
//     kliter_t(rang) * iter_rang;
//     range_list max_ranges;
//     int i = 0;
//     for (iter_rang = kl_begin(protocol_patterns); iter_rang != kl_end(protocol_patterns); iter_rang = kl_next(iter_rang),i++)
//     {
//         // printf("Compare! \n");

//         pcre2_code **patterns = kl_val(iter_rang);
//         pcre2_code *header_pattern = patterns[0];
//         pcre2_code *fields_pattern = patterns[1];

//         range_list header_ranges = starts_with(demo_lines[demo], strlen(demo_lines[demo]), header_pattern);
//         kv_init(header_ranges);

//         if (kv_size(header_ranges) == 0)
//         {
//             printf("Demo %d Did not match pattern %d\n", demo, i);
//             continue;
//         }
//         else
//         {
//             printf("Demo %d Did matched pattern %d\n", demo, i);
//             range header_match = kv_pop(header_ranges);
//             char *offsetted_line = demo_lines[demo];
//             size_t offsetted_len = strlen(demo_lines[demo]);
//             range_list field_ranges = get_mutable_ranges(offsetted_line,offsetted_len, header_match.len,fields_pattern);

//             for(int i = 0; i < kv_size(field_ranges);i++){
//                 kv_push(range, header_ranges, kv_A(field_ranges,i));
//             }
//             kv_destroy(field_ranges);

//             max_ranges = header_ranges;

//             break;
//         }
//     }

//     if (max_rc != -1)
//     {
//         printf("Matched! \n");
//         for (int i = 0; i < max_rc; i++)
//         {
//             printf("start=%d len=%d mutable=%d\n", kv_A(max_ranges,i).start,kv_A(max_ranges,i).len, kv_A(max_ranges,i).mutable);
//             printf("content=%s\n", json_object_to_json_string(json_object_new_string_len(demo_lines[demo] + kv_A(max_ranges,i).start, kv_A(max_ranges,i).len)));
//         }
//     }
//     else
//     {
//         printf("No matches\n");
//     }
// }

// Traverse the list

//     return 0;
// }
