/* * 文件名: test.c
 * 描述: 通用型集成 LLM 的有状态灰盒 Fuzzer
 * 编译执行: clang -std=c11 -O2 -Wall -o test test.c -lcurl && ./test FTP -c ctx_ftp.txt 127.0.0.1 21
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdarg.h> 

#define DEFAULT_IP "127.0.0.1" 
#define DEBUG_MODE 1
#define MAX_PAYLOAD_LEN 4096
#define MAX_STATES 256 
#define CACHE_SIZE 64  
#define MAX_CONTEXT_LEN 8192 
#define SAFE_FREE(ptr) do { if(ptr) { free(ptr); ptr = NULL; } } while(0)

char TARGET_IP[64] = DEFAULT_IP;
char *g_context_data = NULL; 

// ==========================================
// Part 0.5: Logging System (Append Mode + Benchmark)
// ==========================================

FILE *g_log_fp = NULL;
FILE *g_benchmark_csv = NULL;
FILE *g_json_log = NULL;
bool g_benchmark_mode = false;
unsigned int g_random_seed = 0; 

void log_printf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    if (g_log_fp) {
        va_start(args, format);
        vfprintf(g_log_fp, format, args);
        va_end(args);
        fflush(g_log_fp); 
    }
}

#define printf log_printf

// JSON事件日志记录
void log_event_json(const char* event_type, const char* details) {
    if (!g_json_log) return;
    time_t now = time(NULL);
    fprintf(g_json_log, "{\"timestamp\":%ld,\"event\":\"%s\",\"details\":\"%s\"}\n", 
            now, event_type, details);
    fflush(g_json_log);
}

// Benchmark CSV行写入
void write_benchmark_csv_row() {
    if (!g_benchmark_csv) return;
    time_t now = time(NULL);
    time_t elapsed = now - stats.start_time;
    fprintf(g_benchmark_csv, "%ld,%lu,%d,%lu\n", 
            elapsed, stats.total_execs, stats.unique_edges, stats.crashes);
    fflush(g_benchmark_csv);
}

// ==========================================
// Part 0: 数据结构
// ==========================================

typedef enum { PROTO_TEXT, PROTO_BINARY } ProtoType;
typedef enum { SER_OBJECT, SER_LIST } SerializationMode; 

typedef struct {
    char name[32];
    int default_port;
    char payload_end[16];   
    ProtoType type;         
    char role_prompt[1024]; 
    char json_schema[2048]; 
    char init_template[2048]; 
    char mandatory_fields[3][32]; 
    SerializationMode ser_mode; 
    char list_key[32];          
    char template_str[1024];
    
    /* [OPTIMIZATION v8.24] 新增字段: 是否需要先接收服务端 Banner */
    bool recv_banner_first;    
} ProtocolSpec;

ProtocolSpec target_spec; 

typedef struct {
    int status_code;
    char body[1024];
    char state_hash[256]; 
} RealResponse;

typedef struct {
    unsigned long prompt_hash;
    char* response_content;
    bool occupied;
    time_t timestamp;  // [OPTIMIZATION] 缓存时间戳，用于CEGAR阶段过期控制
} SimpleCache;

SimpleCache llm_cache[CACHE_SIZE];

typedef struct {
    unsigned long total_execs;
    unsigned long valid_execs; 
    unsigned long crashes;     
    int unique_edges;          
    time_t start_time;
} FuzzStats;

FuzzStats stats = {0};

/* Scheduler: corpus storage and state visit counts for state-aware scheduling */
#define MAX_CORPUS 256
typedef struct { char json[MAX_PAYLOAD_LEN]; char edge[512]; char target_state[256]; bool occupied; } CorpusEntry;
static CorpusEntry corpus[MAX_CORPUS];

typedef struct { char state[256]; int count; } StateCount;
static StateCount state_counts[MAX_STATES];

/* Protocol-Specific State Extraction & Rejection Classification */
typedef enum {
    PROTO_STATE_INIT = 0,
    PROTO_STATE_AUTH,
    PROTO_STATE_READY,
    PROTO_STATE_TRANSFER,
    PROTO_STATE_ERROR,
    PROTO_STATE_UNKNOWN
} ProtoSemanticState;

typedef struct {
    const char* protocol_name;
    int rejection_code_min;  // 拒绝响应码最小值
    int rejection_code_max;  // 拒绝响应码最大值
    const char* error_keywords[8];  // 错误关键词列表
} RejectionClassifier;

static RejectionClassifier rejection_rules[] = {
    {"FTP", 500, 599, {"fail", "error", "not", "invalid", NULL}},
    {"HTTP", 400, 599, {"error", "forbidden", "unauthorized", "bad", NULL}},
    {"SMTP", 500, 599, {"fail", "reject", "error", NULL}},
    {"MQTT", 128, 255, {"refused", "error", "unauthorized", NULL}},  // MQTT CONNACK Return Codes
    {"Redis", -1, -1, {"-ERR", "-WRONGTYPE", "-NOAUTH", NULL}},
    {NULL, 0, 0, {NULL}}
};

// 判断响应是否为拒绝类（Rejection）
bool is_rejection_response(int status_code, const char* body, const char* proto_name) {
    if (!proto_name) return (status_code >= 400);
    
    for (int i = 0; rejection_rules[i].protocol_name != NULL; i++) {
        if (strcasecmp(rejection_rules[i].protocol_name, proto_name) == 0) {
            // 检查状态码范围
            if (rejection_rules[i].rejection_code_min > 0) {
                if (status_code >= rejection_rules[i].rejection_code_min && 
                    status_code <= rejection_rules[i].rejection_code_max) {
                    return true;
                }
            }
            // 检查错误关键词
            if (body) {
                for (int j = 0; j < 8 && rejection_rules[i].error_keywords[j] != NULL; j++) {
                    if (strcasestr_portable(body, rejection_rules[i].error_keywords[j])) {
                        return true;
                    }
                }
            }
            return false;
        }
    }
    // 默认规则
    return (status_code >= 400);
}

// 提取协议语义状态（Protocol Semantic State Extraction）
ProtoSemanticState extract_protocol_state(const char* proto_name, int status_code, const char* body) {
    if (!proto_name) return PROTO_STATE_UNKNOWN;
    
    if (strcasecmp(proto_name, "FTP") == 0) {
        if (status_code == 220) return PROTO_STATE_INIT;  // Welcome
        if (status_code == 331) return PROTO_STATE_AUTH;  // Need password
        if (status_code == 230) return PROTO_STATE_READY; // Logged in
        if (status_code == 150 || status_code == 125) return PROTO_STATE_TRANSFER;
        if (status_code >= 500) return PROTO_STATE_ERROR;
    } else if (strcasecmp(proto_name, "SMTP") == 0) {
        if (status_code == 220) return PROTO_STATE_INIT;
        if (status_code == 250) return PROTO_STATE_READY;
        if (status_code == 354) return PROTO_STATE_TRANSFER; // Start mail input
        if (status_code >= 500) return PROTO_STATE_ERROR;
    } else if (strcasecmp(proto_name, "HTTP") == 0) {
        if (status_code >= 200 && status_code < 300) return PROTO_STATE_READY;
        if (status_code >= 300 && status_code < 400) return PROTO_STATE_TRANSFER;
        if (status_code >= 400) return PROTO_STATE_ERROR;
    }
    
    return PROTO_STATE_UNKNOWN;
}

void increment_state_count(const char* state) {
    if (!state || !state[0]) return;
    for (int i = 0; i < MAX_STATES; i++) {
        if (state_counts[i].state[0] == '\0') break;
        if (strcmp(state_counts[i].state, state) == 0) { state_counts[i].count++; return; }
    }
    for (int i = 0; i < MAX_STATES; i++) {
        if (state_counts[i].state[0] == '\0') { strncpy(state_counts[i].state, state, sizeof(state_counts[i].state)-1); state_counts[i].state[sizeof(state_counts[i].state)-1] = '\0'; state_counts[i].count = 1; return; }
    }
}

int get_state_count(const char* state) {
    if (!state) return 0;
    for (int i = 0; i < MAX_STATES; i++) if (state_counts[i].state[0] && strcmp(state_counts[i].state, state) == 0) return state_counts[i].count;
    return 0;
}

// pick the least-visited state (returns 1 and writes into out, otherwise 0)
int pick_least_visited_state(char* out, size_t out_len) {
    int found = 0; int min = INT_MAX; int idx = -1;
    for (int i = 0; i < MAX_STATES; i++) {
        if (state_counts[i].state[0] == '\0') continue;
        if (state_counts[i].count < min) { min = state_counts[i].count; idx = i; found = 1; }
    }
    if (found && idx >= 0) { strncpy(out, state_counts[idx].state, out_len-1); out[out_len-1] = '\0'; return 1; }
    return 0;
}

// Save to in-memory corpus
void save_to_corpus(const char* json, const char* edge_info) {
    if (!json || !edge_info) return;
    for (int i = 0; i < MAX_CORPUS; i++) {
        if (!corpus[i].occupied) {
            strncpy(corpus[i].json, json, sizeof(corpus[i].json)-1); corpus[i].json[sizeof(corpus[i].json)-1] = '\0';
            strncpy(corpus[i].edge, edge_info, sizeof(corpus[i].edge)-1); corpus[i].edge[sizeof(corpus[i].edge)-1] = '\0';
            // extract target state after '-> '
            const char* arrow = strstr(edge_info, "->");
            if (arrow) {
                const char* s = arrow + 2; while (*s && isspace((unsigned char)*s)) s++;
                strncpy(corpus[i].target_state, s, sizeof(corpus[i].target_state)-1); corpus[i].target_state[sizeof(corpus[i].target_state)-1] = '\0';
            } else corpus[i].target_state[0] = '\0';
            corpus[i].occupied = true;
            if (DEBUG_MODE) printf("  -> [Corpus] Saved test case triggering: %s\n", edge_info);
            return;
        }
    }
    if (DEBUG_MODE) printf("  -> [Corpus] Full, skipping save.\n");
}

// Try to pick a corpus entry that targets a low-visited state. Returns 1+ copies json to out.
int pick_corpus_for_low_coverage(char* out, size_t out_len) {
    char target[256]; if (!pick_least_visited_state(target, sizeof(target))) return 0;
    for (int i = 0; i < MAX_CORPUS; i++) {
        if (!corpus[i].occupied) continue;
        if (corpus[i].target_state[0] && strcmp(corpus[i].target_state, target) == 0) {
            strncpy(out, corpus[i].json, out_len-1); out[out_len-1] = '\0'; return 1;
        }
    }
    return 0;
}

/* -----------------------------
 * Protocol mapping loader
 * Simple INI-like format: [PROTO]
 * template_str=... (raw, may include \r\n as escaped)
 * verbs=VERB1|VERB2|...
 * aliases=USER:user,command:cmd
 * ----------------------------- */
#define MAX_MAPPINGS 32
typedef struct { char name[32]; char template_str[1024]; char verbs[256]; char aliases[256]; char action_map[512]; int occupied; } ProtocolMapping;
static ProtocolMapping mappings[MAX_MAPPINGS];

static void trim_inplace(char* s) {
    if (!s) return;
    // trim right
    size_t len = strlen(s);
    while (len > 0 && (s[len-1]=='\n' || s[len-1]=='\r' || isspace((unsigned char)s[len-1]))) { s[--len]='\0'; }
    // trim left
    char* p = s; while (*p && isspace((unsigned char)*p)) p++;
    if (p != s) memmove(s, p, strlen(p)+1);
}

void load_protocol_mappings(const char* path) {
    if (!path) return;
    FILE* f = fopen(path, "r"); if (!f) { if (DEBUG_MODE) printf("[Mapping] No mapping file %s\n", path); return; }
    char line[2048]; char section[64] = "";
    while (fgets(line, sizeof(line), f)) {
        trim_inplace(line);
        if (line[0] == '\0' || line[0] == ';' || line[0] == '#') continue;
        if (line[0] == '[') {
            char* end = strchr(line, ']'); if (!end) { section[0]='\0'; continue; }
            size_t sl = end - line - 1; if (sl >= sizeof(section)) sl = sizeof(section)-1;
            strncpy(section, line+1, sl); section[sl] = '\0';
            trim_inplace(section);
            continue;
        }
        char* eq = strchr(line, '='); if (!eq || section[0]=='\0') continue;
        *eq = '\0'; char key[256]; char val[1536]; strncpy(key, line, sizeof(key)-1); key[sizeof(key)-1]='\0'; strncpy(val, eq+1, sizeof(val)-1); val[sizeof(val)-1]='\0'; trim_inplace(key); trim_inplace(val);
        // find or create mapping for section
        int idx = -1;
        for (int i = 0; i < MAX_MAPPINGS; i++) { if (mappings[i].occupied && strcasecmp(mappings[i].name, section)==0) { idx = i; break; } }
        if (idx == -1) { for (int i = 0; i < MAX_MAPPINGS; i++) { if (!mappings[i].occupied) { idx = i; mappings[i].occupied = 1; strncpy(mappings[i].name, section, sizeof(mappings[i].name)-1); mappings[i].name[sizeof(mappings[i].name)-1]='\0'; break; } } }
        if (idx == -1) continue;
        if (strcasecmp(key, "template_str") == 0) { strncpy(mappings[idx].template_str, val, sizeof(mappings[idx].template_str)-1); mappings[idx].template_str[sizeof(mappings[idx].template_str)-1]='\0'; }
        else if (strcasecmp(key, "verbs") == 0) { strncpy(mappings[idx].verbs, val, sizeof(mappings[idx].verbs)-1); mappings[idx].verbs[sizeof(mappings[idx].verbs)-1]='\0'; }
        else if (strcasecmp(key, "aliases") == 0) { strncpy(mappings[idx].aliases, val, sizeof(mappings[idx].aliases)-1); mappings[idx].aliases[sizeof(mappings[idx].aliases)-1]='\0'; }
        else if (strcasecmp(key, "action_map") == 0) { strncpy(mappings[idx].action_map, val, sizeof(mappings[idx].action_map)-1); mappings[idx].action_map[sizeof(mappings[idx].action_map)-1]='\0'; }
    }
    fclose(f);
    if (DEBUG_MODE) printf("[Mapping] Loaded protocol mappings from %s\n", path);
}

// Apply mapping to spec conservatively (only if spec template equals default or empty)
void apply_mapping_to_spec(ProtocolSpec* spec) {
    if (!spec) return;
    for (int i = 0; i < MAX_MAPPINGS; i++) {
        if (!mappings[i].occupied) continue;
        if (strcasecmp(mappings[i].name, spec->name) == 0) {
            // apply template if spec has default or empty
            if (spec->template_str[0] == '\0' || strstr(spec->template_str, "%command% %args%")) {
                if (mappings[i].template_str[0]) {
                    strncpy(spec->template_str, mappings[i].template_str, sizeof(spec->template_str)-1);
                    spec->template_str[sizeof(spec->template_str)-1] = '\0';
                    if (DEBUG_MODE) printf("[Mapping] Applied template_str for %s\n", spec->name);
                }
            }
            // set first mandatory field from aliases if missing
            if (spec->mandatory_fields[0][0] == '\0' && mappings[i].aliases[0]) {
                // aliases format: key1:keyalias1,key2:alias2
                char local[256]; strncpy(local, mappings[i].aliases, sizeof(local)-1); local[sizeof(local)-1]='\0';
                char* t = strtok(local, ","); if (t) {
                    char* c = strchr(t, ':'); if (c) { *c='\0'; trim_inplace(t); strncpy(spec->mandatory_fields[0], t, sizeof(spec->mandatory_fields[0])-1); }
                }
            }
            break;
        }
    }
}

// Forward prototypes needed here
const char* strcasestr_portable(const char* haystack, const char* needle);
void compact_json(const char* input, char* output);

// Preload corpus entries from a context string.
// It looks for [TEMPLATE]...[/TEMPLATE] segments first, then falls back to extracting top-level {...} JSONs.
void preload_corpus_from_context(const char* ctx) {
    if (!ctx) return;
    const char* p = ctx;
    int seed_count = 0;
    // First, extract [TEMPLATE] tags
    while (1) {
        const char* s = strcasestr_portable(p, "[TEMPLATE]");
        if (!s) break; s += strlen("[TEMPLATE]");
        const char* e = strcasestr_portable(s, "[/TEMPLATE]"); if (!e) break;
        size_t len = e - s; if (len >= MAX_PAYLOAD_LEN) len = MAX_PAYLOAD_LEN - 1;
        char buf[MAX_PAYLOAD_LEN]; strncpy(buf, s, len); buf[len] = '\0';
        // compact and save
        char compact[MAX_PAYLOAD_LEN]; compact_json(buf, compact);
        char edge_info[128]; snprintf(edge_info, sizeof(edge_info), "SEED_TEMPLATE_%d", ++seed_count);
        save_to_corpus(compact, edge_info);
        p = e + strlen("[/TEMPLATE]");
        if (seed_count >= MAX_CORPUS) return;
    }

    // Fallback: find JSON objects by matching braces (naive)
    p = ctx;
    while (*p && seed_count < MAX_CORPUS) {
        const char* b = strchr(p, '{'); if (!b) break;
        const char* q = b; int depth = 0; int in_str = 0; while (*q) {
            if (*q == '"' && (q==b || *(q-1) != '\\')) in_str = !in_str;
            if (!in_str) {
                if (*q == '{') depth++; else if (*q == '}') { depth--; if (depth == 0) { q++; break; } }
            }
            q++;
        }
        if (q > b) {
            size_t len = q - b; if (len >= MAX_PAYLOAD_LEN) len = MAX_PAYLOAD_LEN - 1;
            char buf[MAX_PAYLOAD_LEN]; strncpy(buf, b, len); buf[len] = '\0';
            char compact[MAX_PAYLOAD_LEN]; compact_json(buf, compact);
            char edge_info[128]; snprintf(edge_info, sizeof(edge_info), "SEED_JSON_%d", ++seed_count);
            save_to_corpus(compact, edge_info);
            p = q;
        } else break;
    }
}

// ==========================================
// Part 1: Utils & Caching & Minimization
// ==========================================

char* load_file_content(const char* filename) {
    if (!filename) return NULL;
    FILE *f = fopen(filename, "r");
    if (!f) {
        printf("[System] Warning: Could not open context file '%s'.\n", filename);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (length > MAX_CONTEXT_LEN) length = MAX_CONTEXT_LEN; 
    
    char *buffer = malloc(length + 1);
    if (buffer) {
        fread(buffer, 1, length, f);
        buffer[length] = '\0';
    }
    fclose(f);
    return buffer;
}

const char* get_api_key() {
    const char* key = getenv("KEY");
    return (key && strlen(key) > 0) ? key : NULL;
}

unsigned long hash_string(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) hash = ((hash << 5) + hash) + c; 
    return hash;
}

char* check_cache(const char* prompt, bool allow_expired) {
    unsigned long h = hash_string(prompt);
    int idx = h % CACHE_SIZE;
    if (llm_cache[idx].occupied && llm_cache[idx].prompt_hash == h) {
        // [OPTIMIZATION] CEGAR模式下检查缓存年龄（5分钟过期）
        if (!allow_expired) {
            time_t now = time(NULL);
            if (difftime(now, llm_cache[idx].timestamp) > 300) {
                if (DEBUG_MODE) printf("[Cache] Expired for hash %lu (age: %.0fs)\n", h, difftime(now, llm_cache[idx].timestamp));
                return NULL;
            }
        }
        if (DEBUG_MODE) printf("[Cache] Hit for hash %lu\n", h);
        return strdup(llm_cache[idx].response_content);
    }
    return NULL;
}

void add_cache(const char* prompt, const char* response) {
    if (!prompt || !response) return;
    unsigned long h = hash_string(prompt);
    int idx = h % CACHE_SIZE;
    if (llm_cache[idx].occupied) { free(llm_cache[idx].response_content); }
    llm_cache[idx].prompt_hash = h;
    llm_cache[idx].response_content = strdup(response);
    llm_cache[idx].occupied = true;
    llm_cache[idx].timestamp = time(NULL);
    if (DEBUG_MODE) printf("[Cache] Written for hash %lu\n", h);
}

void compact_json(const char* input, char* output) {
    const char* src = input;
    char* dst = output;
    bool in_string = false;
    while (*src) {
        if (*src == '"' && (src == input || *(src-1) != '\\')) {
            in_string = !in_string;
        }
        if (in_string) {
            *dst++ = *src++;
        } else {
            if (!isspace((unsigned char)*src)) *dst++ = *src;
            src++;
        }
    }
    *dst = '\0';
}

/* Forward declarations to avoid implicit declaration errors */
const char* strcasestr_portable(const char* haystack, const char* needle);
void compact_json(const char* input, char* output);
void preload_corpus_from_context(const char* ctx);
void realize_grammar_to_payload(const char* json_input, char* raw_output, size_t max_len, ProtocolSpec* spec);
RealResponse send_tcp_request(const char* raw_payload, ProtocolSpec* spec);

// Remove a top-level field "key" from a flat JSON object. Returns 1 if removed, 0 otherwise.
int remove_json_field(const char* json, const char* key, char* out, size_t max_len) {
    if (!json || !key || !out) return 0;
    const char* p = json;
    char keypat[128]; snprintf(keypat, sizeof(keypat), "\"%s\"", key);
    const char* kpos = strcasestr_portable(p, keypat);
    if (!kpos) return 0;
    // find start of pair (back to previous comma or '{')
    const char* pair_start = kpos;
    while (pair_start > p && *pair_start != '{' && *pair_start != ',') pair_start--;
    if (*pair_start == ',') pair_start++; // exclude comma
    // find end of pair (after value) - look for next comma or closing '}'
    const char* colon = strchr(kpos, ':'); if (!colon) return 0;
    const char* v = colon + 1;
    int in_str = 0; while (*v) {
        if (*v == '"' && (*(v-1) != '\\')) in_str = !in_str;
        if (!in_str && (*v == ',' || *v == '}')) break;
        v++;
    }
    const char* pair_end = v;
    // Build output: prefix + suffix, avoiding stray commas
    size_t pre_len = pair_start - p;
    size_t suf_len = strlen(pair_end);
    if (pre_len + suf_len + 1 >= max_len) return 0;
    // copy prefix trimming trailing comma/space
    while (pre_len > 0 && isspace((unsigned char)p[pre_len-1])) pre_len--;
    if (pre_len > 0 && p[pre_len-1] == ',') pre_len--; // remove trailing comma
    strncpy(out, p, pre_len); out[pre_len] = '\0';
    // append suffix but if suffix starts with comma, skip it
    const char* suffix = pair_end;
    while (*suffix && isspace((unsigned char)*suffix)) suffix++;
    if (*suffix == ',') suffix++;
    // trim leading spaces
    while (*suffix && isspace((unsigned char)*suffix)) suffix++;
    strncat(out, suffix, max_len - strlen(out) - 1);
    return 1;
}

// Apply a small JSON patch (flat object) onto original JSON. Patch is a JSON object with keys to replace/add.
// Returns 1 on success, 0 on error.
int apply_json_patch(const char* orig, const char* patch, char* out, size_t max_len) {
    if (!orig || !patch || !out) return 0;
    // naive: for each top-level key in patch, replace value in orig; if not found, insert before final '}'
    char work[MAX_PAYLOAD_LEN]; strncpy(work, orig, sizeof(work)-1); work[sizeof(work)-1]='\0';
    // parse patch keys
    const char* p = patch;
    // find first '{'
    const char* pb = strchr(p, '{'); if (!pb) return 0; pb++;
    while (*pb) {
        // find next '"'
        const char* q = strchr(pb, '"'); if (!q) break; const char* q2 = strchr(q+1, '"'); if (!q2) break;
        size_t klen = q2 - q - 1; char key[128]; if (klen >= sizeof(key)) klen = sizeof(key)-1; strncpy(key, q+1, klen); key[klen]='\0';
        const char* colon = strchr(q2+1, ':'); if (!colon) break; const char* val_start = colon+1;
        // value may be string or number or object; copy until ',' or '}' at same nesting
        int depth = 0; int in_str = 0; const char* vs = val_start; while (*vs) {
            if (*vs == '"' && (*(vs-1) != '\\')) in_str = !in_str;
            if (!in_str) {
                if (*vs == '{') depth++; else if (*vs == '}') { if (depth==0) break; depth--; }
                else if (*vs == ',' && depth==0) break;
            }
            vs++;
        }
        size_t vlen = vs - val_start; if (vlen >= MAX_PAYLOAD_LEN) vlen = MAX_PAYLOAD_LEN-1;
        char val[2048]; strncpy(val, val_start, vlen); val[vlen]='\0';
        // attempt to find key in work
        char keypat[256]; snprintf(keypat, sizeof(keypat), "\"%s\"", key);
        const char* kpos = strcasestr_portable(work, keypat);
        if (kpos) {
            // find ':' after kpos
            char* cpos = strchr(kpos, ':'); if (!cpos) { pb = vs; continue; }
            char* valp = cpos + 1; int in_s = 0; char* vend = valp; while (*vend) {
                if (*vend == '"' && (*(vend-1) != '\\')) in_s = !in_s;
                if (!in_s && (*vend == ',' || *vend == '}')) break;
                vend++;
            }
            // build new work: prefix + key + ':' + val + suffix
            char newwork[MAX_PAYLOAD_LEN];
            // copy up to colon
            char* colonp = strchr(kpos, ':'); size_t up_to = colonp - work + 1;
            strncpy(newwork, work, up_to); newwork[up_to] = '\0';
            // append val (trim spaces)
            const char* valptr = val; while (*valptr && isspace((unsigned char)*valptr)) valptr++;
            strncat(newwork, valptr, sizeof(newwork)-strlen(newwork)-1);
            // append rest after vend
            strncat(newwork, vend, sizeof(newwork)-strlen(newwork)-1);
            strncpy(work, newwork, sizeof(work)-1); work[sizeof(work)-1]='\0';
        } else {
            // insert before final '}'
            char* endb = strrchr(work, '}'); if (!endb) { pb = vs; continue; }
            // ensure comma separation if needed
            size_t prefix_len = endb - work;
            char newwork[MAX_PAYLOAD_LEN]; strncpy(newwork, work, prefix_len); newwork[prefix_len]='\0';
            // check if object empty
            const char* inner = strchr(work, '{'); if (inner && inner[1] != '}') strcat(newwork, ",");
            // append patch key:value
            size_t frag_len = vs - q; if (frag_len > 0) strncat(newwork, q, frag_len);
            strcat(newwork, " }");
            strncpy(work, newwork, sizeof(work)-1); work[sizeof(work)-1]='\0';
        }
        pb = vs; if (*pb == ',') pb++; // advance
    }
    // copy to out
    strncpy(out, work, max_len-1); out[max_len-1]='\0';
    return 1;
}

// Minimize counterexample by greedily removing top-level fields while preserving original server response code/body.
// Returns 1 and writes minimized JSON to out if success, otherwise copies original and returns 0.
int minimize_counterexample(const char* original_json, RealResponse* orig_res, ProtocolSpec* spec, char* out, size_t max_len) {
    if (!original_json || !orig_res || !spec || !out) return 0;
    char work[MAX_PAYLOAD_LEN]; strncpy(work, original_json, sizeof(work)-1); work[sizeof(work)-1]='\0';
    char keys[64][128]; int nk = 0;
    // parse top-level keys (naive)
    const char* p = work; const char* b = strchr(p, '{'); if (!b) { strncpy(out, original_json, max_len-1); out[max_len-1]='\0'; return 0; }
    p = b+1;
    while (*p) {
        const char* q = strchr(p, '"'); if (!q) break; const char* q2 = strchr(q+1, '"'); if (!q2) break;
        size_t klen = q2 - q - 1; if (klen >= 127) klen = 127;
        strncpy(keys[nk], q+1, klen); keys[nk][klen]='\0'; nk++;
        p = q2 + 1; const char* colon = strchr(p, ':'); if (!colon) break; p = colon + 1;
        // skip value
        int in_s = 0; int depth = 0; while (*p) {
            if (*p == '"' && (*(p-1) != '\\')) in_s = !in_s;
            if (!in_s) {
                if (*p == '{') depth++; else if (*p == '}') { if (depth==0) break; depth--; }
                else if (*p == ',' && depth==0) { p++; break; }
            }
            p++;
        }
    }
    // try removing each key greedily
    for (int i = 0; i < nk; i++) {
        char cand[MAX_PAYLOAD_LEN]; if (!remove_json_field(work, keys[i], cand, sizeof(cand))) continue;
        // realize payload and send
        char payload[MAX_PAYLOAD_LEN]; realize_grammar_to_payload(cand, payload, MAX_PAYLOAD_LEN, spec);
        RealResponse r = send_tcp_request(payload, spec);
        // preserve if status code and body prefix match
        if (r.status_code == orig_res->status_code && (orig_res->body[0] == '\0' || strstr(r.body, orig_res->body) || strstr(orig_res->body, r.body))) {
            // accept candidate
            strncpy(work, cand, sizeof(work)-1); work[sizeof(work)-1]='\0';
        }
    }
    strncpy(out, work, max_len-1); out[max_len-1]='\0';
    return 1;
}

const char* strcasestr_portable(const char* haystack, const char* needle) {
    if (!needle || !*needle) return haystack;
    const char* h = haystack;
    while (*h) {
        const char* h_adv = h;
        const char* n_adv = needle;
        while (*n_adv && *h_adv && tolower((unsigned char)*h_adv) == tolower((unsigned char)*n_adv)) {
            h_adv++; n_adv++;
        }
        if (!*n_adv) return h; 
        h++;
    }
    return NULL;
}

char* json_escape_string(const char* input) {
    if (!input) return strdup("");
    size_t len = strlen(input);
    char* output = calloc(len * 6 + 1, sizeof(char));
    if (!output) return NULL; 
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
    const char* key_pos = strcasestr_portable(json_str, "\"content\"");
    if (!key_pos) return NULL;
    const char* start_quote = strchr(key_pos, ':');
    if (!start_quote) return NULL;
    start_quote = strchr(start_quote, '"');
    if (!start_quote) return NULL;
    start_quote++; 
    const char* ptr = start_quote;
    const char* end_quote = NULL;
    while (*ptr) {
        if (*ptr == '\\') { ptr++; if (*ptr) ptr++; continue; }
        if (*ptr == '"') { end_quote = ptr; break; }
        ptr++;
    }
    if (!end_quote) return NULL;
    size_t len = end_quote - start_quote;
    char* raw = malloc(len + 1); if(!raw) return NULL;
    char* w = raw; const char* r = start_quote;
    while (r < end_quote) {
        if (*r == '\\') {
            r++; if(r>=end_quote) break;
            switch (*r) {
                case 'n': *w++ = '\n'; break; case 'r': *w++ = '\r'; break;
                case 't': *w++ = '\t'; break; case '"': *w++ = '"'; break;
                case '\\': *w++ = '\\'; break;
                case 'u': if (r+4<end_quote) { unsigned int u; sscanf(r+1,"%4x",&u); *w++=(u<128)?(char)u:'?'; r+=4; } break;
                default: *w++ = *r; 
            }
        } else *w++ = *r;
        r++;
    }
    *w = '\0';
    return raw;
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
    
    /* [OPTIMIZATION v8.25]
     * 智能缓存策略：允许在CEGAR修正阶段使用过期缓存刷新
     * temperature > 0.05 时允许旧缓存，否则强制获取新响应
     */
    bool allow_stale = (temperature > 0.05f);
    char* cached_resp = check_cache(prompt, allow_stale);
    if (cached_resp) return cached_resp;

    CURL* curl = curl_easy_init();
    if (!curl) return NULL;
    struct curl_slist* headers = curl_slist_append(NULL, "Content-Type: application/json");
    char auth[256]; snprintf(auth, sizeof(auth), "Authorization: Bearer %s", get_api_key());
    headers = curl_slist_append(headers, auth);
    
    char* esc_prompt = json_escape_string(prompt);
    size_t jsize = strlen(esc_prompt) + 4096; 
    char* data = malloc(jsize);
    snprintf(data, jsize, "{\"model\":\"%s\",\"messages\":[{\"role\":\"user\",\"content\":\"%s\"}],\"temperature\":%.2f}", model, esc_prompt, temperature);
    
    char* resp = NULL; char* content = NULL; long http_code = 0;
    curl_easy_setopt(curl, CURLOPT_URL, "https://free.v36.cm/v1/chat/completions");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 45L); 
    if (tries < 1) tries = 1;
    for (int i = 0; i < tries; i++) {
        if (resp) { free(resp); resp = NULL; }
        curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code == 200) { content = extract_content_from_json(resp); if(content) break; }
    }
    curl_easy_cleanup(curl); curl_slist_free_all(headers); free(esc_prompt); free(data); free(resp);
    return content;
}

char* extract_tag(const char* text, const char* tag) {
    if (!text) return NULL;
    char start[64], end[64];
    snprintf(start, 64, "[%s]", tag); snprintf(end, 64, "[/%s]", tag);
    const char* s = strcasestr_portable(text, start); 
    if (!s) return NULL; s += strlen(start);
    const char* e = strcasestr_portable(s, end); 
    if (!e) return NULL;
    size_t len = e - s; char* r = malloc(len + 1); strncpy(r, s, len); r[len] = '\0';
    return r;
}

size_t hex_to_bytes(const char* hex, unsigned char* out, size_t max_len) {
    size_t count = 0; const char* p = hex;
    while (*p && count < max_len) {
        while (*p && isspace((unsigned char)*p)) p++; if (!*p) break;
        unsigned int v; if (sscanf(p, "%2x", &v) == 1) { out[count++] = v; p += 2; } else p++;
    }
    return count;
}

// ==========================================
// Part 1.5: Generic Template Realizer
// ==========================================

void extract_json_value_generic(const char* json_snippet, const char* key, char* output, size_t max_len);

void handle_smart_fields(const char* json_snippet, const char* key, char* output, size_t max_len) {
    size_t key_len = strlen(key);
    char base_key[256] = {0};
    char temp_val[2048] = {0};

    if (key_len > 7 && strcmp(key + key_len - 7, "_length") == 0) {
        strncpy(base_key, key, key_len - 7);
        extract_json_value_generic(json_snippet, base_key, temp_val, 2048);
        if (strlen(temp_val) > 0) { snprintf(output, max_len, "%zu", strlen(temp_val)); return; }
    }
    if (key_len > 7 && strcmp(key + key_len - 7, "_hexlen") == 0) {
        strncpy(base_key, key, key_len - 7);
        extract_json_value_generic(json_snippet, base_key, temp_val, 2048);
        size_t v_len = strlen(temp_val);
        if (v_len > 0) { snprintf(output, max_len, "%02X", (unsigned int)v_len); return; }
    }
    if (strncmp(key, "num_", 4) == 0) {
        strcpy(base_key, key + 4); 
        char search_key[256];
        snprintf(search_key, 256, "\"%s\"", base_key);
        const char* arr_start = strcasestr_portable(json_snippet, search_key);
        if (arr_start) {
            arr_start = strchr(arr_start, '[');
            if (arr_start) {
                int count = 0; const char* p = arr_start + 1;
                while (*p && *p != ']') { if (*p == '{') count++; p++; }
                if (count == 0 && p > arr_start + 1) { count = 1; const char* c = arr_start; while ((c = strchr(c + 1, ',')) && c < p) count++; }
                snprintf(output, max_len, "%d", count); return;
            }
        }
    }
    strcpy(output, "");
}

void extract_json_value_generic(const char* json_snippet, const char* key, char* output, size_t max_len) {
    if (!json_snippet || !key || !output) return;
    strcpy(output, "");
    const char* aliases[12] = { NULL }; aliases[0] = key; 
    if (strcmp(key, "path") == 0) { aliases[1] = "url"; aliases[2] = "endpoint"; aliases[3] = "uri"; } 
    else if (strcmp(key, "body") == 0) { aliases[1] = "data"; aliases[2] = "content"; aliases[3] = "payload"; } 
    else if (strcmp(key, "headers") == 0) { aliases[1] = "header"; } 
    else if (strcmp(key, "method") == 0 || strcmp(key, "command") == 0) { aliases[1] = "verb"; aliases[2] = "cmd"; aliases[3] = "action"; aliases[4] = "method"; aliases[5] = "command"; } 
    else if (strcmp(key, "parameters") == 0 || strcmp(key, "args") == 0) { aliases[1] = "params"; aliases[2] = "arguments"; aliases[3] = "content"; aliases[4] = "value"; aliases[5] = "user"; aliases[6] = "password"; aliases[7] = "pass"; aliases[8] = "topic"; aliases[9] = "key"; }

    const char* v_start = NULL;
    for (int i = 0; i < 10 && aliases[i] != NULL; i++) {
        char search_key[256]; snprintf(search_key, 256, "\"%s\"", aliases[i]); 
        const char* k_pos = strcasestr_portable(json_snippet, search_key);
        if (!k_pos) { snprintf(search_key, 256, "%s:", aliases[i]); k_pos = strcasestr_portable(json_snippet, search_key); }
        if (k_pos) { const char* c_pos = strchr(k_pos, ':'); if (c_pos) { v_start = c_pos + 1; break; } }
    }
    if (!v_start) { handle_smart_fields(json_snippet, key, output, max_len); return; }
    while (*v_start && (isspace((unsigned char)*v_start) || *v_start == '"')) v_start++;
    const char* v_end = v_start; if (*(v_start - 1) == '[') { }
    while (*v_end && *v_end != '"' && *v_end != ',' && *v_end != '}' && *v_end != ']') v_end++;
    size_t len = v_end - v_start; if (len >= max_len) len = max_len - 1;
    strncpy(output, v_start, len); output[len] = '\0';
}

void apply_template(const char* tmpl, const char* json_context, char* output, size_t max_len) {
    const char* t_ptr = tmpl; char* o_ptr = output; size_t remaining = max_len - 1;
    while (*t_ptr && remaining > 0) {
        if (*t_ptr == '%') {
            const char* key_start = t_ptr + 1; const char* key_end = strchr(key_start, '%');
            if (key_end) {
                char key[64]; size_t key_len = key_end - key_start;
                if (key_len < 64) {
                    strncpy(key, key_start, key_len); key[key_len] = '\0';
                    char value[2048]; extract_json_value_generic(json_context, key, value, sizeof(value));
                    size_t v_len = strlen(value); if (v_len > remaining) v_len = remaining;
                    strncpy(o_ptr, value, v_len); o_ptr += v_len; remaining -= v_len;
                    t_ptr = key_end + 1; continue;
                }
            }
        }
        *o_ptr++ = *t_ptr++; remaining--;
    }
    *o_ptr = '\0';
}

const char* unwrap_json_root(const char* json_input, char* buffer, size_t buf_size) {
    const char* wrappers[] = {"\"test_case\"", "\"hypothesis\"", "\"request\"", "\"input\"", "\"data\"", NULL};
    for (int i = 0; wrappers[i] != NULL; i++) {
        const char* key_pos = strcasestr_portable(json_input, wrappers[i]); 
        if (key_pos) {
            const char* content_start = strchr(key_pos, ':');
            if (content_start) {
                content_start = strchr(content_start, '{'); 
                if (content_start) {
                    const char* content_end = strrchr(content_start, '}'); 
                    if (content_end && content_end > content_start) {
                        size_t len = content_end - content_start + 1;
                        if (len < buf_size) { strncpy(buffer, content_start, len); buffer[len] = '\0'; return buffer; }
                    }
                }
            }
        }
    }
    return json_input; 
}

void realize_grammar_to_payload(const char* json_input, char* raw_output, size_t max_len, ProtocolSpec* spec) {
    memset(raw_output, 0, max_len);
    char unwrapped_json[MAX_PAYLOAD_LEN];
    const char* effective_json = unwrap_json_root(json_input, unwrapped_json, MAX_PAYLOAD_LEN);

    // Heuristic: support top-level keys like "GET /login": { ... }
    // Convert them into a flat JSON with explicit "method" and "path" fields
    static char transformed[MAX_PAYLOAD_LEN]; transformed[0] = '\0';
    const char* first_q = strchr(effective_json, '"');
    if (first_q) {
        const char* second_q = strchr(first_q + 1, '"');
        if (second_q && second_q > first_q) {
            size_t key_len = second_q - first_q - 1;
            if (key_len > 0 && key_len < 256) {
                char keybuf[256]; strncpy(keybuf, first_q + 1, key_len); keybuf[key_len] = '\0';
                // only handle keys that contain a space (e.g., "GET /login")
                if (strchr(keybuf, ' ')) {
                    char method[64] = {0}; char path[256] = {0};
                    char* sp = strchr(keybuf, ' ');
                    if (sp) {
                        size_t mlen = sp - keybuf; if (mlen >= sizeof(method)) mlen = sizeof(method)-1;
                        strncpy(method, keybuf, mlen); method[mlen] = '\0';
                        strncpy(path, sp + 1, sizeof(path)-1); path[sizeof(path)-1] = '\0';
                    }
                    // find inner object for that key
                    const char* colon = strchr(second_q + 1, ':');
                    const char* brace = colon ? strchr(colon + 1, '{') : NULL;
                    if (brace) {
                        const char* q = brace; int depth = 0; const char* end = NULL; int in_str = 0;
                        while (*q) {
                            if (*q == '"' && (q == brace || *(q-1) != '\\')) in_str = !in_str;
                            if (!in_str) {
                                if (*q == '{') depth++; else if (*q == '}') { depth--; if (depth == 0) { end = q; break; } }
                            }
                            q++;
                        }
                        if (end && end > brace) {
                            const char* inner_start = brace + 1; const char* inner_end = end - 1;
                            size_t inner_len = inner_end >= inner_start ? (size_t)(inner_end - inner_start + 1) : 0;
                            if (inner_len + 256 < sizeof(transformed)) {
                                if (inner_len > 0) {
                                    snprintf(transformed, sizeof(transformed), "{\"method\":\"%s\",\"path\":\"%s\",%.*s}", method, path, (int)inner_len, inner_start);
                                } else {
                                    snprintf(transformed, sizeof(transformed), "{\"method\":\"%s\",\"path\":\"%s\"}", method, path);
                                }
                                effective_json = transformed;
                            }
                        }
                    }
                }
            }
        }
    }

    if (spec->ser_mode == SER_OBJECT) {
        // If template expects headers/host but JSON lacks them, inject Host header with TARGET_IP
        char temp_template[1024]; strncpy(temp_template, spec->template_str, sizeof(temp_template)-1); temp_template[sizeof(temp_template)-1] = '\0';
        bool injected = false;
        // handle %host% placeholder
        if (strcasestr_portable(temp_template, "%host%") && !strcasestr_portable(effective_json, "\"host\"") && !strcasestr_portable(effective_json, "\"headers\"")) {
            char newtmpl[1024]; newtmpl[0] = '\0';
            const char* p = temp_template; const char* found = strcasestr_portable(p, "%host%");
            if (found) {
                size_t pre = found - p; if (pre > sizeof(newtmpl)-1) pre = sizeof(newtmpl)-1;
                strncpy(newtmpl, p, pre); newtmpl[pre] = '\0';
                char hostrep[128]; snprintf(hostrep, sizeof(hostrep), "%s", TARGET_IP);
                strncat(newtmpl, hostrep, sizeof(newtmpl)-strlen(newtmpl)-1);
                strncat(newtmpl, found + strlen("%host%"), sizeof(newtmpl)-strlen(newtmpl)-1);
                apply_template(newtmpl, effective_json, raw_output, max_len);
                injected = true;
            }
        }
        // handle %headers% fallback
        if (!injected && strcasestr_portable(temp_template, "%headers%") && !strcasestr_portable(effective_json, "\"host\"") && !strcasestr_portable(effective_json, "\"headers\"")) {
            char replacement[128]; snprintf(replacement, sizeof(replacement), "Host: %s\\r\\n", TARGET_IP);
            char newtmpl[1024]; newtmpl[0] = '\0';
            const char* p = temp_template; const char* found = strcasestr_portable(p, "%headers%");
            if (found) {
                size_t pre = found - p; if (pre > sizeof(newtmpl)-1) pre = sizeof(newtmpl)-1;
                strncpy(newtmpl, p, pre); newtmpl[pre] = '\0';
                strncat(newtmpl, replacement, sizeof(newtmpl)-strlen(newtmpl)-1);
                strncat(newtmpl, found + strlen("%headers%"), sizeof(newtmpl)-strlen(newtmpl)-1);
                apply_template(newtmpl, effective_json, raw_output, max_len);
                injected = true;
            }
        }
        if (!injected) apply_template(spec->template_str, effective_json, raw_output, max_len);
    } 
    else if (spec->ser_mode == SER_LIST) {
        char root_key_search[64]; snprintf(root_key_search, 64, "\"%s\"", spec->list_key);
        const char* list_start = strcasestr_portable(effective_json, root_key_search); 
        if (!list_start) return;
        list_start = strchr(list_start, '['); if (!list_start) return;
        const char* ptr = list_start;
        while (*ptr) {
            const char* obj_start = strchr(ptr, '{'); if (!obj_start) break;
            const char* obj_end = strchr(obj_start, '}'); if (!obj_end) break;
            size_t item_len = obj_end - obj_start + 1;
            char item_json[1024];
            if (item_len < 1024) {
                strncpy(item_json, obj_start, item_len); item_json[item_len] = '\0';
                char item_payload[512]; apply_template(spec->template_str, item_json, item_payload, sizeof(item_payload));
                if (strlen(raw_output) + strlen(item_payload) < max_len) strcat(raw_output, item_payload);
            }
            ptr = obj_end + 1;
        }
    }
}

// Post-process payload for protocol-specific normalization (conservative heuristics)
void postprocess_payload_for_protocol(char* raw_output, ProtocolSpec* spec, const char* json_context) {
    if (!raw_output || !spec) return;
    // Only apply conservative heuristics to text protocols
    if (spec->type != PROTO_TEXT) return;

    // Ensure CRLF line ending for text protocols
    size_t len = strlen(raw_output);
    if (len >= 2) {
        if (!(raw_output[len-2] == '\r' && raw_output[len-1] == '\n') && !(raw_output[len-1] == '\n')) {
            if (len + 2 < MAX_PAYLOAD_LEN) { strcat(raw_output, "\r\n"); }
        }
    } else {
        if (len + 2 < MAX_PAYLOAD_LEN) strcat(raw_output, "\r\n");
    }

    // Protocol-specific normalization using protocol mappings, if available
    for (int i = 0; i < MAX_MAPPINGS; i++) {
        if (!mappings[i].occupied) continue;
        if (strcasecmp(mappings[i].name, spec->name) != 0) continue;
        // parse first token as command, rest as args
        char copy[MAX_PAYLOAD_LEN]; strncpy(copy, raw_output, sizeof(copy)-1); copy[sizeof(copy)-1] = '\0';
        char *cr = strstr(copy, "\r\n"); if (!cr) cr = strstr(copy, "\n"); if (cr) *cr = '\0';
        char *tok = strtok(copy, " "); if (!tok) break;
        char cmd[128]; strncpy(cmd, tok, sizeof(cmd)-1); cmd[sizeof(cmd)-1] = '\0';
        char args[1024] = ""; char *rest = strtok(NULL, ""); if (rest) { while (*rest && isspace((unsigned char)*rest)) rest++; strncpy(args, rest, sizeof(args)-1); }

    
    // HTTP-specific: ensure Host header is present and non-empty
    if (spec && strcasestr_portable(spec->name, "HTTP")) {
        const char* hdr_end = NULL;
        if (strstr(raw_output, "\r\n\r\n")) hdr_end = strstr(raw_output, "\r\n\r\n");
        else if (strstr(raw_output, "\n\n")) hdr_end = strstr(raw_output, "\n\n");

        char* host_pos = (char*)strcasestr_portable(raw_output, "Host:");
        if (host_pos) {
            // check if value empty between ':' and CRLF
            char* colon = strchr(host_pos, ':');
            if (colon) {
                char* v = colon + 1; while (*v && isspace((unsigned char)*v)) v++;
                char* line_end = strstr(v, "\r\n"); if (!line_end) line_end = strstr(v, "\n");
                size_t vlen = line_end ? (size_t)(line_end - v) : strlen(v);
                if (vlen == 0) {
                    // replace empty Host line with TARGET_IP
                    char newbuf[MAX_PAYLOAD_LEN]; newbuf[0] = '\0';
                    size_t prefix = host_pos - raw_output;
                    strncpy(newbuf, raw_output, prefix);
                    newbuf[prefix] = '\0';
                    char hostline[128]; snprintf(hostline, sizeof(hostline), "Host: %s\r\n", TARGET_IP);
                    strncat(newbuf, hostline, sizeof(newbuf)-strlen(newbuf)-1);
                    if (line_end) strncat(newbuf, line_end + (line_end[1] == '\n' && line_end[0] == '\r' ? 2 : 1), sizeof(newbuf)-strlen(newbuf)-1);
                    strncpy(raw_output, newbuf, MAX_PAYLOAD_LEN-1); raw_output[MAX_PAYLOAD_LEN-1] = '\0';
                }
            }
        } else if (hdr_end) {
            // insert Host header before header end
            char newbuf[MAX_PAYLOAD_LEN]; newbuf[0] = '\0';
            size_t prefix = hdr_end - raw_output;
            strncpy(newbuf, raw_output, prefix);
            newbuf[prefix] = '\0';
            char hostline[128]; snprintf(hostline, sizeof(hostline), "Host: %s\r\n", TARGET_IP);
            strncat(newbuf, hostline, sizeof(newbuf)-strlen(newbuf)-1);
            strncat(newbuf, hdr_end, sizeof(newbuf)-strlen(newbuf)-1);
            strncpy(raw_output, newbuf, MAX_PAYLOAD_LEN-1); raw_output[MAX_PAYLOAD_LEN-1] = '\0';
        }
    }
        if (mappings[i].action_map[0]) {
            char amap[512]; strncpy(amap, mappings[i].action_map, sizeof(amap)-1); amap[sizeof(amap)-1] = '\0';
            char* pair = strtok(amap, "|");
            while (pair) {
                char* c = strchr(pair, ':'); if (c) { *c = '\0'; char *akey = pair; char *av = c+1; trim_inplace(akey); trim_inplace(av);
                    if (strcasecmp(akey, cmd) == 0) {
                        // build payload using av as verb
                        char argval[512] = ""; extract_json_value_generic(json_context, "user", argval, sizeof(argval)); if (argval[0]=='\0') extract_json_value_generic(json_context, "USER", argval, sizeof(argval));
                        if (argval[0]=='\0' && args[0]) strncpy(argval, args, sizeof(argval)-1);
                        if (argval[0]=='\0') strncpy(argval, "", sizeof(argval)-1);
                        snprintf(raw_output, MAX_PAYLOAD_LEN, "%s %s\r\n", av, argval);
                        return;
                    }
                }
                pair = strtok(NULL, "|");
            }
        }

        // If command not in verbs, try aliases -> USER fallback
        if (mappings[i].verbs[0]) {
            int known = 0; char vcopy[256]; strncpy(vcopy, mappings[i].verbs, sizeof(vcopy)-1); vcopy[sizeof(vcopy)-1]='\0';
            char* v = strtok(vcopy, "|"); while (v) { if (strcasecmp(v, cmd) == 0) { known = 1; break; } v = strtok(NULL, "|"); }
            if (!known) {
                char userbuf[256] = ""; extract_json_value_generic(json_context, "user", userbuf, sizeof(userbuf)); if (userbuf[0] == '\0') extract_json_value_generic(json_context, "USER", userbuf, sizeof(userbuf));
                if (userbuf[0]) { snprintf(raw_output, MAX_PAYLOAD_LEN, "USER %s\r\n", userbuf); return; }
            }
        }
        break;
    }
}

// ==========================================
// Part 1.8: Spec Generator
// ==========================================

void parse_spec_from_json(const char* json, ProtocolSpec* spec) {
    char buf[2048];
    /* Ensure spec fields start in a known state */
    memset(spec->mandatory_fields, 0, sizeof(spec->mandatory_fields));
    spec->template_str[0] = '\0';

    extract_json_value_generic(json, "default_port", buf, 32); spec->default_port = atoi(buf);
    extract_json_value_generic(json, "type", buf, 32); spec->type = (strstr(buf, "BINARY")) ? PROTO_BINARY : PROTO_TEXT;
    extract_json_value_generic(json, "payload_end", buf, 32);
    if (strstr(buf, "\\r\\n\\r\\n")) strcpy(spec->payload_end, "\r\n\r\n");
    else if (strstr(buf, "\\r\\n")) strcpy(spec->payload_end, "\r\n");
    else strcpy(spec->payload_end, ""); 
    extract_json_value_generic(json, "role_prompt", spec->role_prompt, 1024);
    extract_json_value_generic(json, "json_schema", spec->json_schema, 2048);
    extract_json_value_generic(json, "init_template", spec->init_template, 2048);
    extract_json_value_generic(json, "ser_mode", buf, 32); spec->ser_mode = (strstr(buf, "LIST")) ? SER_LIST : SER_OBJECT;
    extract_json_value_generic(json, "list_key", spec->list_key, 32);
    extract_json_value_generic(json, "template_str", spec->template_str, 1024);
    
    // [OPTIMIZATION v8.24] 模板反转义
    char temp_tmpl[1024]; char* src = spec->template_str; char* dst = temp_tmpl;
    while (*src) {
        if (*src == '\\' && *(src+1) == 'r') { *dst++ = '\r'; src+=2; }
        else if (*src == '\\' && *(src+1) == 'n') { *dst++ = '\n'; src+=2; }
        else if (*src == '%' && *(src+1) == '%') { *dst++ = '%'; src+=2; } 
        else *dst++ = *src++;
    }
    *dst = '\0'; strcpy(spec->template_str, temp_tmpl);
    
    // [OPTIMIZATION v8.24] 解析 recv_banner_first
    char bool_buf[32] = {0};
    extract_json_value_generic(json, "recv_banner_first", bool_buf, 32);
    if (strcasestr_portable(bool_buf, "true") || strcmp(bool_buf, "1") == 0) {
        spec->recv_banner_first = true;
    } else {
        spec->recv_banner_first = false;
    }

    extract_json_value_generic(json, "mandatory_csv", buf, 256);
    char* token = strtok(buf, ","); int i = 0;
    while(token && i < 3) { while(isspace(*token)) token++; strcpy(spec->mandatory_fields[i++], token); token = strtok(NULL, ","); }

    /* Fallback defaults when LLM didn't provide mandatory fields or template */
    if (spec->mandatory_fields[0][0] == '\0') {
        strcpy(spec->mandatory_fields[0], "command");
        strcpy(spec->mandatory_fields[1], "args");
        spec->mandatory_fields[2][0] = '\0';
        if (DEBUG_MODE) printf("[Auto-Fix] mandatory_fields missing. Using defaults: command,args\n");
    }
    if (spec->template_str[0] == '\0') {
        strcpy(spec->template_str, "%command% %args%");
        if (DEBUG_MODE) printf("[Auto-Fix] template_str missing. Using default template: %s\n", spec->template_str);
    }
    // Ensure text templates include CRLF to work with line-based protocols (safe fallback)
    if (spec->type == PROTO_TEXT) {
        if (!strstr(spec->template_str, "\r") && !strstr(spec->template_str, "\n")) {
            size_t tlen = strlen(spec->template_str);
            if (tlen + 4 < sizeof(spec->template_str)) {
                strcat(spec->template_str, "\\r\\n"); // keep escaped form
                if (DEBUG_MODE) printf("[Auto-Fix] Appended CRLF to template_str for text protocol.\n");
            }
        }
    }
}

void heuristic_fix_spec(ProtocolSpec* spec) {
    if (spec->type == PROTO_TEXT && spec->default_port == 80) { 
        if (spec->template_str[0] == '{') {
            printf("[Auto-Fix] Detected Invalid JSON Template for HTTP. Resetting to Standard.\n");
            strcpy(spec->template_str, "%method% %path% HTTP/1.1\r\n%headers%\r\n\r\n%body%");
        }
    }
    if (strncmp(spec->template_str, "COMMAND ", 8) == 0) {
        printf("[Auto-Fix] Detected static 'COMMAND' in template. Replacing with dynamic placeholder.\n");
        char temp[1024];
        if (strncmp(spec->template_str + 8, "%command%", 9) == 0) {
             strcpy(temp, spec->template_str + 8);
        } else {
             snprintf(temp, 1024, "%%command%% %s", spec->template_str + 8);
        }
        strcpy(spec->template_str, temp);
    }
}

bool auto_generate_spec(const char* proto_name) {
    printf("[System] Auto-generating specification for protocol: %s...\n", proto_name);
    char prompt[16384]; 
    
    char context_snippet[MAX_CONTEXT_LEN + 100] = "";
    if (g_context_data) {
        snprintf(context_snippet, sizeof(context_snippet), 
            "\n<REFERENCE_CONTEXT>\n%s\n</REFERENCE_CONTEXT>\n"
            "INSTRUCTION: Use the above Context to define commands and schema strictly.\n", 
            g_context_data);
    } else {
        strcpy(context_snippet, "No external context provided. Rely on internal knowledge.\n");
    }

    snprintf(prompt, sizeof(prompt),
        "Role: Protocol Engineer.\n"
        "Task: Generate Spec for '%s'. Output JSON ONLY.\n"
        "%s"
        "Rules:\n"
        "1. 'template_str' must be RAW C-string (e.g. \"%%command%% %%args%%\"), NOT JSON.\n"
        "2. JSON Structure: Use 'command' for the action and 'args' for parameters.\n"
        "3. For FTP/SMTP/POP3: Template MUST use placeholders like \"%%command%%\", NOT literal \"COMMAND\".\n"
        "4. For MQTT/Binary: 'template_str' MUST be a Hex String pattern.\n"
        /* [OPTIMIZATION v8.24] 新增规则 5: 指导 LLM 设置 recv_banner_first */
        "5. Field 'recv_banner_first': Set to TRUE if server sends a banner immediately upon connection (e.g. FTP, SMTP, SSH). Set to FALSE for Client-first (e.g. HTTP, RTSP).\n"
        "Fields: default_port, type, recv_banner_first, payload_end, role_prompt, json_schema, init_template, ser_mode, list_key, template_str, mandatory_csv\n",
        proto_name, context_snippet
    );

    char* resp = chat_with_llm(prompt, "gpt-4o-mini", 3, 0.1f);
    if (!resp) { printf("[System] Error: Failed to generate spec from LLM.\n"); return false; }

    char* json_start = strchr(resp, '{');
    char* json_end = strrchr(resp, '}');
    if (json_start && json_end && json_end > json_start) {
        *(json_end + 1) = '\0';
        strcpy(target_spec.name, proto_name);
        parse_spec_from_json(json_start, &target_spec);
        heuristic_fix_spec(&target_spec);
        if (target_spec.init_template[0] != '{') {
             printf("[Auto-Fix] init_template is malformed. Resetting to empty JSON object.\n");
             strcpy(target_spec.init_template, "{}");
        }
        add_cache(prompt, resp);
        printf("[System] Spec Generated Successfully:\n");
        printf("  > Port: %d\n", target_spec.default_port);
        printf("  > Template: %s\n", target_spec.template_str);
        printf("  > Server-First Banner: %s\n", target_spec.recv_banner_first ? "TRUE" : "FALSE");
        SAFE_FREE(resp);
        return true;
    } else {
        printf("[System] Error: LLM output is not valid JSON.\n%s\n", resp); SAFE_FREE(resp); return false;
    }
}

// ==========================================
// Part 1.9: Verifier Reject Classification
// ==========================================

typedef enum {
    VFY_OK = 0,
    VFY_EMPTY_INPUT,
    VFY_TOO_LARGE,
    VFY_NO_JSON_OBJECT,
    VFY_MISSING_MANDATORY,
    VFY_CONSTRAINT_MISMATCH,
    VFY_EXCESSIVE_FIELDS,
    VFY_NESTING_TOO_DEEP
} VerifierRejectReason;

static VerifierRejectReason g_last_vfy_reason = VFY_OK;

const char* verifier_reason_str(VerifierRejectReason r) {
    switch (r) {
        case VFY_EMPTY_INPUT: return "EMPTY_INPUT";
        case VFY_TOO_LARGE: return "INPUT_TOO_LARGE";
        case VFY_NO_JSON_OBJECT: return "NO_JSON_OBJECT";
        case VFY_MISSING_MANDATORY: return "MISSING_MANDATORY_FIELD";
        case VFY_CONSTRAINT_MISMATCH: return "CONSTRAINT_MISMATCH";
        case VFY_EXCESSIVE_FIELDS: return "TOO_MANY_FIELDS";
        case VFY_NESTING_TOO_DEEP: return "NESTING_TOO_DEEP";
        default: return "OK";
    }
}


// ==========================================
// Part 2: 验证与网络
// ==========================================

// TCP发送与接收函数
RealResponse send_tcp_request(const char* raw_payload, ProtocolSpec* spec) {
    RealResponse res = {0};
    res.status_code = 0;
    res.body[0] = '\0';
    res.state_hash[0] = '\0';
    
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        if (DEBUG_MODE) printf("[Net] Socket creation failed\n");
        return res;
    }
    
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(spec->default_port);
    
    if (inet_pton(AF_INET, TARGET_IP, &server_addr.sin_addr) <= 0) {
        if (DEBUG_MODE) printf("[Net] Invalid address\n");
        close(sockfd);
        return res;
    }
    
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        if (DEBUG_MODE) printf("[Net] Connection failed\n");
        close(sockfd);
        return res;
    }
    
    // [OPTIMIZATION v8.24] 如果协议需要先接收banner
    if (spec->recv_banner_first) {
        char banner[1024] = {0};
        int n = recv(sockfd, banner, sizeof(banner) - 1, 0);
        if (n > 0) {
            banner[n] = '\0';
            if (DEBUG_MODE) printf("[Net] Received banner: %s\n", banner);
            // 从banner提取状态码
            if (isdigit((unsigned char)banner[0])) {
                res.status_code = atoi(banner);
            }
        }
    }
    
    // 发送payload
    ssize_t sent = send(sockfd, raw_payload, strlen(raw_payload), 0);
    if (sent < 0) {
        if (DEBUG_MODE) printf("[Net] Send failed\n");
        close(sockfd);
        return res;
    }
    
    // 接收响应
    char buffer[4096] = {0};
    ssize_t received = recv(sockfd, buffer, sizeof(buffer) - 1, 0);
    
    close(sockfd);
    
    if (received > 0) {
        buffer[received] = '\0';
        strncpy(res.body, buffer, sizeof(res.body) - 1);
        res.body[sizeof(res.body) - 1] = '\0';
        
        // 提取状态码（尝试从响应的第一行）
        if (isdigit((unsigned char)buffer[0])) {
            res.status_code = atoi(buffer);
        } else if (strstr(buffer, "HTTP/")) {
            const char* code_pos = strstr(buffer, " ");
            if (code_pos) res.status_code = atoi(code_pos + 1);
        } else {
            res.status_code = 200; // 默认假设成功
        }
        
        // 生成状态哈希
        sanitize_response_body(res.body);
        snprintf(res.state_hash, sizeof(res.state_hash), "S_%d_%.32s", res.status_code, res.body);
    } else {
        res.status_code = 0; // 无响应
        strcpy(res.state_hash, "S_NO_RESPONSE");
    }
    
    return res;
}

void sanitize_response_body(char *body) {
    if (!body) return;
    int len = strlen(body);
    for (int i = 0; i < len; i++) {
        if (isdigit((unsigned char)body[i])) {
            body[i] = 'N';
        }
    }
}

// ==========================================
// Deterministic & Explainable Verifier
// ==========================================

bool verify_json_grammar(const char* json_input, ProtocolSpec* spec) {
    g_last_vfy_reason = VFY_OK;

    if (!json_input || strlen(json_input) == 0) {
        g_last_vfy_reason = VFY_EMPTY_INPUT;
        return false;
    }

    if (strlen(json_input) > MAX_PAYLOAD_LEN) {
        g_last_vfy_reason = VFY_TOO_LARGE;
        return false;
    }

    char unwrapped_buf[MAX_PAYLOAD_LEN];
    const char* effective_json =
        unwrap_json_root(json_input, unwrapped_buf, MAX_PAYLOAD_LEN);

    if (!strchr(effective_json, '{') || !strchr(effective_json, '}')) {
        g_last_vfy_reason = VFY_NO_JSON_OBJECT;
        return false;
    }

    /* ---- Mandatory Field Check ---- */
    for (int i = 0; i < 3; i++) {
        const char* key = spec->mandatory_fields[i];
        if (key && strlen(key) > 0) {
            char search_key[64];
            snprintf(search_key, sizeof(search_key), "\"%s\"", key);
            if (!strcasestr_portable(effective_json, search_key)) {
                g_last_vfy_reason = VFY_MISSING_MANDATORY;
                return false;
            }
        }
    }

    /* ---- Field Count Limitation (Resource Exhaustion Guard) ---- */
    int field_count = 0;
    for (const char* p = effective_json; *p; p++) {
        if (*p == ':' && ++field_count > 32) {
            g_last_vfy_reason = VFY_EXCESSIVE_FIELDS;
            return false;
        }
    }

    /* ---- Nesting Depth Limitation ---- */
    int depth = 0;
    for (const char* p = effective_json; *p; p++) {
        if (*p == '{') depth++;
        else if (*p == '}') depth--;
        if (depth > 8) {
            g_last_vfy_reason = VFY_NESTING_TOO_DEEP;
            return false;
        }
    }

    /* ---- Schema / Constraint Validation (lightweight) ---- */
    if (spec && spec->json_schema[0]) {
        // If schema looks like JSON (starts with '{'), parse it as a lightweight JSON-Schema-like structure.
        if (spec->json_schema[0] == '{') {
            // Simple parser: look for "<key>":{...} blocks and support type,minLength,maxLength,enum,required
            char schema_copy[2048]; strncpy(schema_copy, spec->json_schema, sizeof(schema_copy)-1); schema_copy[sizeof(schema_copy)-1]='\0';
            const char* s = schema_copy;
            while (*s) {
                const char* kq = strchr(s, '"'); if (!kq) break; const char* kq2 = strchr(kq+1, '"'); if (!kq2) break;
                size_t klen = kq2 - kq - 1; if (klen == 0) { s = kq2 + 1; continue; }
                char key[128]; if (klen >= sizeof(key)) klen = sizeof(key)-1; strncpy(key, kq+1, klen); key[klen]='\0';
                const char* brace = strchr(kq2+1, '{'); if (!brace) { s = kq2 + 1; continue; }
                const char* q = brace + 1; int depth = 1; const char* end = NULL; int in_str = 0;
                while (*q) {
                    if (*q == '"' && (*(q-1) != '\\')) in_str = !in_str;
                    if (!in_str) { if (*q == '{') depth++; else if (*q == '}') { depth--; if (depth==0) { end = q; break; } } }
                    q++;
                }
                if (!end) { s = kq2 + 1; continue; }
                size_t block_len = end - brace - 1; char block[1024] = {0}; if (block_len > 0 && block_len < sizeof(block)) strncpy(block, brace+1, block_len);

                // extract properties from block
                // type
                char typeval[32] = {0}; const char* p = strcasestr_portable(block, "\"type\"");
                if (p) { const char* c = strchr(p, ':'); if (c) { const char* v = strchr(c, '"'); if (v) { const char* v2 = strchr(v+1, '"'); if (v2) { size_t tv = v2 - v - 1; if (tv < sizeof(typeval)) strncpy(typeval, v+1, tv); } } } }
                // minLength
                int minL = -1, maxL = -1; p = strcasestr_portable(block, "minLength"); if (p) { const char* c = strchr(p, ':'); if (c) minL = atoi(c+1); }
                p = strcasestr_portable(block, "maxLength"); if (p) { const char* c = strchr(p, ':'); if (c) maxL = atoi(c+1); }
                // enum
                char enumcopy[512] = {0}; int enum_count = 0; p = strcasestr_portable(block, "enum"); if (p) { const char* a = strchr(p, '['); const char* b = a ? strchr(a, ']') : NULL; if (a && b && b > a) { size_t el = b - a - 1; if (el < sizeof(enumcopy)) strncpy(enumcopy, a+1, el); // copy raw vals
                        // split by ',' of quoted strings
                        const char* r = enumcopy; while (*r) {
                            const char* q1 = strchr(r, '"'); if (!q1) break; const char* q2 = strchr(q1+1, '"'); if (!q2) break; size_t vlen = q2 - q1 - 1; char val[64]; if (vlen >= sizeof(val)) vlen = sizeof(val)-1; strncpy(val, q1+1, vlen); val[vlen]='\0'; // store temporarily by embedding back into enumcopy separated by '|'
                            if (enum_count==0) { memset(enumcopy,0,sizeof(enumcopy)); strncpy(enumcopy, val, sizeof(enumcopy)-1); } else { strncat(enumcopy, "|", sizeof(enumcopy)-strlen(enumcopy)-1); strncat(enumcopy, val, sizeof(enumcopy)-strlen(enumcopy)-1); }
                            enum_count++; r = q2 + 1; }
                    }
                }
                // required
                bool required = false; p = strcasestr_portable(block, "\"required\""); if (p) { const char* c = strchr(p, ':'); if (c) { if (strcasestr_portable(c, "true") || strchr(c,'1')) required = true; } }

                // Validate according to extracted constraints
                char valbuf[2048] = {0}; extract_json_value_generic(effective_json, key, valbuf, sizeof(valbuf));
                if (required && valbuf[0] == '\0') { g_last_vfy_reason = VFY_MISSING_MANDATORY; return false; }
                if (valbuf[0] != '\0') {
                    if (typeval[0]) {
                        if (strcasestr_portable(typeval, "number")) {
                            const char* t = valbuf; if (*t == '-') t++; bool ok = (*t != '\0'); while (*t) { if (!isdigit((unsigned char)*t)) { ok = false; break; } t++; } if (!ok) { g_last_vfy_reason = VFY_CONSTRAINT_MISMATCH; return false; }
                        }
                    }
                    if (minL >= 0 && (int)strlen(valbuf) < minL) { g_last_vfy_reason = VFY_CONSTRAINT_MISMATCH; return false; }
                    if (maxL >= 0 && (int)strlen(valbuf) > maxL) { g_last_vfy_reason = VFY_CONSTRAINT_MISMATCH; return false; }
                    if (enum_count > 0) {
                        bool matched = false; char enumcpy[512]; strncpy(enumcpy, enumcopy, sizeof(enumcpy)-1);
                        char* e = strtok(enumcpy, "|"); while (e) { if (strcasecmp(e, valbuf) == 0) { matched = true; break; } e = strtok(NULL, "|"); }
                        if (!matched) { g_last_vfy_reason = VFY_CONSTRAINT_MISMATCH; return false; }
                    }
                }

                s = end + 1;
            }
        } else {
            // fallback to legacy lightweight DSL (key:rule:params;...)
            char schema_copy[2048]; strncpy(schema_copy, spec->json_schema, sizeof(schema_copy)-1); schema_copy[sizeof(schema_copy)-1]='\0';
            char* tok = strtok(schema_copy, ";");
            while (tok) {
                char key[128] = {0}; char rule[128] = {0}; char params[1024] = {0};
                char* p1 = strchr(tok, ':');
                if (!p1) { tok = strtok(NULL, ";"); continue; }
                size_t klen = p1 - tok; if (klen >= sizeof(key)) klen = sizeof(key)-1; strncpy(key, tok, klen); key[klen]='\0';
                char* p2 = strchr(p1+1, ':');
                if (p2) { size_t rlen = p2 - (p1+1); if (rlen >= sizeof(rule)) rlen = sizeof(rule)-1; strncpy(rule, p1+1, rlen); rule[rlen]='\0'; strncpy(params, p2+1, sizeof(params)-1); params[sizeof(params)-1]='\0'; }
                else { strncpy(rule, p1+1, sizeof(rule)-1); rule[sizeof(rule)-1]='\0'; params[0] = '\0'; }
                if (strcmp(rule, "required") == 0) { char search_key[128]; snprintf(search_key, sizeof(search_key), "\"%s\"", key); if (!strcasestr_portable(effective_json, search_key)) { g_last_vfy_reason = VFY_MISSING_MANDATORY; return false; } tok = strtok(NULL, ";"); continue; }
                char val[2048] = {0}; extract_json_value_generic(effective_json, key, val, sizeof(val)); if (val[0] == '\0') { tok = strtok(NULL, ";"); continue; }
                if (strcmp(rule, "maxlen") == 0) { int m = atoi(params); if ((int)strlen(val) > m) { g_last_vfy_reason = VFY_CONSTRAINT_MISMATCH; return false; } }
                else if (strcmp(rule, "minlen") == 0) { int m = atoi(params); if ((int)strlen(val) < m) { g_last_vfy_reason = VFY_CONSTRAINT_MISMATCH; return false; } }
                else if (strcmp(rule, "enum") == 0) { bool matched = false; char copyp[1024]; strncpy(copyp, params, sizeof(copyp)-1); copyp[sizeof(copyp)-1]='\0'; char* e = strtok(copyp, "|"); while (e) { if (strcasecmp(e, val) == 0) { matched = true; break; } e = strtok(NULL, "|"); } if (!matched) { g_last_vfy_reason = VFY_CONSTRAINT_MISMATCH; return false; } }
                else if (strcmp(rule, "type") == 0) { if (strcmp(params, "number") == 0) { const char* s2 = val; if (*s2 == '-') s2++; bool ok = (*s2 != '\0'); while (*s2) { if (!isdigit((unsigned char)*s2)) { ok = false; break; } s2++; } if (!ok) { g_last_vfy_reason = VFY_CONSTRAINT_MISMATCH; return false; } } }
                tok = strtok(NULL, ";");
            }
        }
    }

    return true;
}


RealResponse send_tcp_request(const char* raw_payload, ProtocolSpec* spec) {
    RealResponse res; memset(&res, 0, sizeof(res)); res.status_code = 0;
    unsigned char send_buf[MAX_PAYLOAD_LEN]; size_t send_len = 0;
    if (spec->type == PROTO_BINARY) { send_len = hex_to_bytes(raw_payload, send_buf, MAX_PAYLOAD_LEN); } 
    else { strncpy((char*)send_buf, raw_payload, MAX_PAYLOAD_LEN); send_len = strlen((char*)send_buf); }

    int sock = socket(AF_INET, SOCK_STREAM, 0); if (sock < 0) return res;
    struct timeval timeout; timeout.tv_sec = 2; timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    struct sockaddr_in server_addr; server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(spec->default_port);
    inet_pton(AF_INET, TARGET_IP, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) { close(sock); return res; }
    
    /* [OPTIMIZATION v8.24] Configuration-Driven Banner Sync
     * 由 LLM 生成的 recv_banner_first 字段控制，而非硬编码协议名
     */
    if (spec->recv_banner_first || spec->ser_mode == SER_LIST) {
        char banner[1024]; 
        // 使用短超时防止阻塞
        struct timeval short_tv; short_tv.tv_sec = 1; short_tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &short_tv, sizeof(short_tv));
        
        int n = recv(sock, banner, 1023, 0);
        if (n > 0) { 
            banner[n] = 0; 
            if (DEBUG_MODE) printf("[Net] Consumed Banner: %.20s...\n", banner);
            // 如果尚未有响应体(如SER_LIST情况)，记录Banner作为上下文
            if (strlen(res.body) == 0) strncpy(res.body, banner, 512); 
        }
        
        // 恢复正常超时
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    }

    send(sock, send_buf, send_len, 0);
    char buffer[4096]; int r_len = recv(sock, buffer, 4095, 0); close(sock);

    if (r_len > 0) {
        buffer[r_len] = '\0';
        int code = 0;
        if (sscanf(buffer, "%*s %d", &code) == 1 && code > 0) res.status_code = code;
        else if (sscanf(buffer, "%d", &code) == 1 && code > 0) res.status_code = code;
        else res.status_code = 1;

        char* body_start = buffer; char* split = strstr(buffer, "\r\n\r\n");
        if (split) body_start = split + 4; else { split = strstr(buffer, "\n\n"); if (split) body_start = split + 2; }
        
        char clean_body[1024]; int max_len = 1000; int c_idx = 0;
        for(int i=0; body_start[i] && c_idx < max_len; i++) {
            if (isprint((unsigned char)body_start[i]) || body_start[i] == ' ' || body_start[i] == '\n') clean_body[c_idx++] = body_start[i];
            else clean_body[c_idx++] = '.'; 
        }
        clean_body[c_idx] = '\0'; 
        
        sanitize_response_body(clean_body);
        strncpy(res.body, clean_body, 1023);

        snprintf(res.state_hash, 256, "S_%d_%.60s", res.status_code, res.body);
        for(int i=0; res.state_hash[i]; i++) if(isspace((unsigned char)res.state_hash[i])) res.state_hash[i] = '.';
    }
    return res;
}

// save_to_corpus is implemented above (state-aware corpus).

void log_event_json(const char* event_type, const char* details) {
    if (!g_json_log) return;
    time_t now = time(NULL);
    fprintf(g_json_log, "{\"timestamp\":%ld,\"event\":\"%s\",\"details\":\"%s\"}\n", 
            now, event_type, details ? details : "");
    fflush(g_json_log);
}

void write_benchmark_csv_row() {
    if (!g_benchmark_csv) return;
    double duration = difftime(time(NULL), stats.start_time);
    fprintf(g_benchmark_csv, "%.1f,%lu,%d,%lu\n", 
            duration, stats.total_execs, stats.unique_edges, stats.crashes);
    fflush(g_benchmark_csv);
}

void print_stats() {
    printf("\n=== Fuzzing Statistics ===\n");
    printf("Total Execs: %lu\n", stats.total_execs);
    printf("Valid Execs: %lu\n", stats.valid_execs);
    printf("Unique Edges: %d\n", stats.unique_edges);
    printf("Crashes (5xx/Drop): %lu\n", stats.crashes);
    double duration = difftime(time(NULL), stats.start_time);
    printf("Duration: %.1fs\n", duration);
    printf("Avg Speed: %.1f execs/s\n", stats.total_execs / (duration > 0 ? duration : 1));
    printf("==========================\n");
    
    // JSON格式输出（便于自动化分析）
    if (g_json_log) {
        char details[512];
        snprintf(details, sizeof(details), 
                "execs:%lu,valid:%lu,edges:%d,crashes:%lu,duration:%.1f,speed:%.1f",
                stats.total_execs, stats.valid_execs, stats.unique_edges, 
                stats.crashes, duration, stats.total_execs / (duration > 0 ? duration : 1));
        log_event_json("final_stats", details);
    }
}

// ==========================================
// Part 3: 主逻辑
// ==========================================

void run_universal_fuzzer() {
    ProtocolSpec* spec = &target_spec; 
    stats.start_time = time(NULL);

    printf("========================================\n");
    printf("[System] Universal Fuzzer v8.24 (Config-Driven)\n");
    printf("[System] Protocol: %s\n", spec->name);
    printf("[System] Target: %s:%d\n", TARGET_IP, spec->default_port);
    if (g_context_data) printf("[System] Context Loaded: %lu bytes\n", strlen(g_context_data));
    srand(time(NULL));

    char current_json_hypothesis[MAX_PAYLOAD_LEN];
    strcpy(current_json_hypothesis, spec->init_template); 
    
    char visited_edges[MAX_STATES][512]; 
    char prev_state_hash[256] = "S_START";
    char last_server_feedback[1024] = "None (Initial)";
    // CEGAR: track repeated refinements on same edge and back off
    int consecutive_refine = 0;
    char last_refine_edge[512] = "";

    for (int step = 1; step <= 8; step++) {
        printf("\n--- Round %d ---\n", step);
        bool round_success = false;

        for (int i = 0; i < 2; i++) {
            stats.total_execs++;
            printf("[Hypothesis] JSON: %.100s...\n", current_json_hypothesis);
            
            if (!verify_json_grammar(current_json_hypothesis, spec)) {
                printf("[Verifier] REJECTED (%s)\n",verifier_reason_str(g_last_vfy_reason));
                continue;
            }
            stats.valid_execs++;

            char raw_payload[MAX_PAYLOAD_LEN];
            realize_grammar_to_payload(current_json_hypothesis, raw_payload, MAX_PAYLOAD_LEN, spec);
            // conservative post-processing to improve protocol conformance
            postprocess_payload_for_protocol(raw_payload, spec, current_json_hypothesis);
            
            char pl_preview[100]; strncpy(pl_preview, raw_payload, 90); pl_preview[90]='\0';
            for(int p=0; pl_preview[p]; p++) if(pl_preview[p]=='\r'||pl_preview[p]=='\n') pl_preview[p]='.';
            printf("[Realizer] Compiled: %s...\n", pl_preview);

            RealResponse res = send_tcp_request(raw_payload, spec);
            if (res.status_code == 0) { 
                printf("[Net] No response (Possible Crash).\n"); 
                stats.crashes++; 
                sleep(1); break; 
            }
            if (strlen(res.body) > 0) { strncpy(last_server_feedback, res.body, 1023); last_server_feedback[1023] = '\0'; }

            char current_edge[512];
            snprintf(current_edge, 512, "%s -> %s", prev_state_hash, res.state_hash);
            
            bool is_new_edge = true;
            for(int k=0; k<stats.unique_edges; k++) if(strcmp(visited_edges[k], current_edge) == 0) is_new_edge = false;
            
            if(is_new_edge && stats.unique_edges < MAX_STATES) {
                printf("  -> [Result] NEW EDGE: %s\n", current_edge);
                strcpy(visited_edges[stats.unique_edges++], current_edge); 
                save_to_corpus(current_json_hypothesis, current_edge); 
                increment_state_count(res.state_hash);
                round_success = true;
                // reset refine counter on progress
                consecutive_refine = 0; last_refine_edge[0] = '\0';
            } else {
                printf("  -> [Result] Code:%d (Seen Edge)\n", res.status_code);
                // still increment observed state frequency
                increment_state_count(res.state_hash);
            }
            
            strcpy(prev_state_hash, res.state_hash);
            
            // [OPTIMIZATION v8.25] 使用协议感知的拒绝分类
            bool is_rejection = is_rejection_response(res.status_code, res.body, spec->name);
            ProtoSemanticState semantic_state = extract_protocol_state(spec->name, res.status_code, res.body);
            if (DEBUG_MODE && semantic_state != PROTO_STATE_UNKNOWN) {
                const char* state_names[] = {"INIT", "AUTH", "READY", "TRANSFER", "ERROR", "UNKNOWN"};
                printf("  -> [Semantic] Protocol State: %s\n", state_names[semantic_state]);
            }

            if (is_rejection) {
                printf("  -> [CEGAR] Rejection detected. Triggering Refinement.\n");
                if (g_json_log) {
                    char log_buf[512];
                    snprintf(log_buf, sizeof(log_buf), "code:%d,body:%.100s", res.status_code, res.body);
                    log_event_json("rejection", log_buf);
                }
                // detect repeated refinement on same edge and back off after 3 attempts
                if (last_refine_edge[0] != '\0' && strcmp(current_edge, last_refine_edge) == 0) {
                    consecutive_refine++;
                } else {
                    consecutive_refine = 1;
                    strncpy(last_refine_edge, current_edge, sizeof(last_refine_edge)-1); last_refine_edge[sizeof(last_refine_edge)-1] = '\0';
                }
                if (consecutive_refine >= 3) {
                    printf("  -> [CEGAR] Repeated refinements on same edge; aborting refinement to request new hypothesis.\n");
                    break; // exit inner attempt loop to let scheduler request new case
                }

                char minimized_json[MAX_PAYLOAD_LEN];
                compact_json(current_json_hypothesis, minimized_json);

                char prompt[4096];
                snprintf(prompt, 4096,
                    "Role: %s\nTask: Fix the rejected Hypothesis (Refinement Mode).\n"
                    "Error Context: Code %d, Body \"%s\"\n"
                    "Input (Minimized): %s\n"
                    "Constraint: Modify ONLY the specific field causing the error. Do NOT rewrite the whole structure.\n"
                    "Schema: %s\n"
                    "Output: JSON ONLY, wrapped in [TEMPLATE]...[/TEMPLATE].\n",
                    spec->role_prompt, res.status_code, res.body, minimized_json, spec->json_schema
                );
                char* llm_resp = chat_with_llm(prompt, "gpt-4o-mini", 3, 0.1f);
                if (llm_resp) {
                    // New flow: minimize counterexample first, then ask LLM for a local PATCH
                    char minimized[MAX_PAYLOAD_LEN];
                    if (minimize_counterexample(current_json_hypothesis, &res, spec, minimized, sizeof(minimized))) {
                        printf("  -> [CEGAR] Minimized CE: %.200s...\n", minimized);
                    } else {
                        strncpy(minimized, current_json_hypothesis, sizeof(minimized)-1); minimized[sizeof(minimized)-1]='\0';
                    }
                    // Build strict patch prompt
                    char patch_prompt[8192];
                    snprintf(patch_prompt, sizeof(patch_prompt),
                        "Role: %s\nTask: Apply a LOCAL PATCH to the minimized rejected JSON.\n"
                        "Failure: Code %d, Body '%s'\n"
                        "Input (Minimized): %s\n"
                        "Constraint: DO NOT rewrite the whole JSON. Output ONLY a JSON object containing the specific fields to CHANGE or ADD.\n"
                        "Limit: At most 3 fields. Output must be wrapped in [PATCH]...[/PATCH].\n",
                        spec->role_prompt, res.status_code, res.body, minimized
                    );
                    char* patch_resp = chat_with_llm(patch_prompt, "gpt-4o-mini", 3, 0.0f);
                    if (patch_resp) {
                        char* patch = extract_tag(patch_resp, "PATCH");
                        if (patch) {
                            // basic validation: patch should be shorter than original and contain '{'
                            if (strlen(patch) < strlen(current_json_hypothesis) * 2 && strchr(patch, '{')) {
                                char new_json[MAX_PAYLOAD_LEN];
                                if (apply_json_patch(current_json_hypothesis, patch, new_json, sizeof(new_json))) {
                                    printf("  -> [CEGAR] Applied LOCAL PATCH: %.200s...\n", new_json);
                                    strncpy(current_json_hypothesis, new_json, sizeof(current_json_hypothesis)-1);
                                    current_json_hypothesis[sizeof(current_json_hypothesis)-1] = '\0';
                                    round_success = true;
                                    add_cache(patch_prompt, patch_resp);
                                } else {
                                    printf("  -> [CEGAR] Patch application failed. Ignoring.\n");
                                }
                            } else {
                                printf("  -> [CEGAR] Patch rejected (invalid or too large).\n");
                            }
                            SAFE_FREE(patch);
                        } else {
                            printf("  -> [CEGAR] No [PATCH] tag found in LLM response.\n");
                        }
                        SAFE_FREE(patch_resp);
                    }
                    SAFE_FREE(llm_resp);
                    break;
                }
            }
        }

        // [BENCHMARK] 定期写入CSV
        if (g_benchmark_mode && step % 2 == 0) {
            write_benchmark_csv_row();
        }
        
        if (!round_success && step < 8) {
            char corpus_candidate[MAX_PAYLOAD_LEN] = "";
            if (pick_corpus_for_low_coverage(corpus_candidate, sizeof(corpus_candidate))) {
                printf("[Scheduler] Plateau. Selecting corpus case targeting low-coverage state.\n");
                printf("  -> [Scheduler] New Hypothesis(from corpus): %.100s...\n", corpus_candidate);
                strncpy(current_json_hypothesis, corpus_candidate, sizeof(current_json_hypothesis)-1);
                current_json_hypothesis[sizeof(current_json_hypothesis)-1] = '\0';
                sleep(1);
                continue;
            }

            printf("[Scheduler] Plateau. Asking LLM for New Test Case...\n");
            char prompt[4096];
            char extra_instruction[512] = "";
            char target_state_hint[256] = "";
            if (pick_least_visited_state(target_state_hint, sizeof(target_state_hint))) {
                // include a hint to the LLM to try to reach a low-visited state
                snprintf(extra_instruction + strlen(extra_instruction), sizeof(extra_instruction) - strlen(extra_instruction), "TIP: Try to reach state '%s' which has low coverage.\n", target_state_hint);
            }
            if (strstr(spec->name, "MQTT")) {
                strcpy(extra_instruction, "4. For MQTT: Output keys 'client_id', 'topic', 'message'. DO NOT output status/error logs.\n");
            }
            if (strstr(spec->name, "Redis")) {
                 strcat(extra_instruction, "5. For Redis: JSON MUST be flat. Use {\"command\": \"SET\", \"key\": \"...\", \"value\": \"...\"}. DO NOT use {\"SET\": {...}}.\n");
            }

            snprintf(prompt, 4096,
                "Role: %s\n"
                "Task: Generate a NEW Test Case (JSON Data) to explore NEW STATES.\n"
                "Constraints:\n"
                "1. Output MUST strictly match Schema: %s\n"
                "2. MUST include keys: %s, %s, %s\n"
                "3. NEGATIVE CONSTRAINT: DO NOT include fields like 'Current State', 'Current JSON', 'History'.\n"
                "4. Structure: Keep JSON FLAT. Do NOT nest commands inside keys.\n"
                "%s"
                "<CONTEXT>\n"
                "Previous State Hash: \"%s\"\n"
                "Last Server Feedback: \"%s\"\n"
                "</CONTEXT>\n"
                "<INSTRUCTION>\n"
                "Generate a different command/parameter to trigger a state transition. Output JSON ONLY, wrapped in [TEMPLATE]...[/TEMPLATE].\n"
                "</INSTRUCTION>\n", 
                spec->role_prompt, 
                spec->json_schema, 
                spec->mandatory_fields[0], spec->mandatory_fields[1], spec->mandatory_fields[2], 
                extra_instruction, 
                prev_state_hash, last_server_feedback
            );
            char* llm_resp = chat_with_llm(prompt, "gpt-4o-mini", 3, 0.1f);
            if (llm_resp) {
                char* suggestion = extract_tag(llm_resp, "TEMPLATE");
                if (suggestion) {
                    printf("  -> [Scheduler] New Hypothesis: %.100s...\n", suggestion);
                    strcpy(current_json_hypothesis, suggestion); 
                    add_cache(prompt, llm_resp);
                    SAFE_FREE(suggestion);
                } else printf("  -> [Scheduler] Error: No [TEMPLATE] tag found.\n");
                SAFE_FREE(llm_resp);
            }
        }
        sleep(1);
    }
    print_stats();
    printf("\n[System] Fuzzing Finished.\n");
}

int main(int argc, char** argv) {
    g_log_fp = fopen("test.txt", "a");
    if (g_log_fp) {
        time_t now = time(NULL);
        fprintf(g_log_fp, "\n\n=== NEW SESSION START: %s", ctime(&now));
    } else {
        fprintf(stderr, "Warning: Could not open test.txt for logging.\n");
    }

    if (!get_api_key()) { printf("Error: Export KEY='your_api_key' first.\n"); if(g_log_fp) fclose(g_log_fp); return 1; }
    
    if (argc < 2) { 
        printf("Usage: ./fuzzer <PROTOCOL_NAME> [OPTIONS] [TARGET_IP] [PORT]\n");
        printf("Options:\n");
        printf("  -c <file>       Context file (RFC/examples)\n");
        printf("  --benchmark     Enable benchmark mode (CSV output)\n");
        printf("  --seed <n>      Set random seed for reproducibility\n");
        printf("  --json-log      Enable JSON event logging\n");
        if(g_log_fp) fclose(g_log_fp); 
        return 1; 
    }

    const char* proto_input = argv[1];
    
    int arg_idx = 2;
    // 解析所有选项
    while (arg_idx < argc && argv[arg_idx][0] == '-') {
        if (strcmp(argv[arg_idx], "-c") == 0 && arg_idx + 1 < argc) {
            g_context_data = load_file_content(argv[arg_idx + 1]);
            arg_idx += 2;
        } else if (strcmp(argv[arg_idx], "--benchmark") == 0) {
            g_benchmark_mode = true;
            printf("[System] Benchmark mode enabled.\n");
            arg_idx++;
        } else if (strcmp(argv[arg_idx], "--seed") == 0 && arg_idx + 1 < argc) {
            g_random_seed = (unsigned int)atoi(argv[arg_idx + 1]);
            srand(g_random_seed);
            printf("[System] Random seed set to: %u\n", g_random_seed);
            arg_idx += 2;
        } else if (strcmp(argv[arg_idx], "--json-log") == 0) {
            g_json_log = fopen("fuzzer_events.json", "w");
            if (g_json_log) printf("[System] JSON logging enabled.\n");
            arg_idx++;
        } else {
            printf("Unknown option: %s\n", argv[arg_idx]);
            arg_idx++;
        }
    }
    
    // 初始化benchmark CSV
    if (g_benchmark_mode) {
        char csv_filename[128];
        snprintf(csv_filename, sizeof(csv_filename), "benchmark_%s_%ld.csv", proto_input, time(NULL));
        g_benchmark_csv = fopen(csv_filename, "w");
        if (g_benchmark_csv) {
            fprintf(g_benchmark_csv, "time,total_execs,unique_edges,crashes\n");
            printf("[System] Benchmark output: %s\n", csv_filename);
        }
    }

    int override_port = 0;
    if (argc > arg_idx) { strncpy(TARGET_IP, argv[arg_idx], 63); TARGET_IP[63] = '\0'; }
    if (argc > arg_idx + 1) {
        override_port = atoi(argv[arg_idx + 1]);
        printf("[System] Override Port: %d\n", override_port);
    }
    
    if (!auto_generate_spec(proto_input)) {
        printf("Critical Error: Could not generate spec for %s. Exiting.\n", proto_input);
        if(g_context_data) free(g_context_data);
        if(g_log_fp) fclose(g_log_fp);
        return 1;
    }

    // Load protocol mappings (optional file in workspace root)
    load_protocol_mappings("protocol_mappings.cfg");
    apply_mapping_to_spec(&target_spec);

    // Preload corpus seeds from provided context to help cold-start coverage
    if (g_context_data) preload_corpus_from_context(g_context_data);

    // Re-apply command-line override after auto-generated spec to ensure user intent wins
    if (override_port > 0) { target_spec.default_port = override_port; printf("[System] Applied override port: %d\n", target_spec.default_port); }

    run_universal_fuzzer();
    
    // 清理资源
    if (g_context_data) free(g_context_data);
    if (g_log_fp) fclose(g_log_fp);
    if (g_benchmark_csv) {
        write_benchmark_csv_row();  // 最后一次写入
        fclose(g_benchmark_csv);
    }
    if (g_json_log) fclose(g_json_log);
    
    return 0;
}