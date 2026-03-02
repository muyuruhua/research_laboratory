#define _GNU_SOURCE // asprintf
#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>

#include "chat-llm.h"
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
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    mem->memory = realloc(mem->memory, mem->size + realsize + 1);
    if (mem->memory == NULL)
    {
        /* out of memory! */
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

/* forward declaration for validator used in llm_handle_plateau */
static int is_garbage_response(const char *response, size_t len);

/* --- curl global lifecycle (call once from main thread) --- */
void chat_llm_global_init(void)  { curl_global_init(CURL_GLOBAL_DEFAULT); }
void chat_llm_global_cleanup(void) { curl_global_cleanup(); }

char *chat_with_llm(char *prompt, char *model, int tries, float temperature)
{
    CURL *curl;
    CURLcode res = CURLE_OK;
    char *answer = NULL;
    char *url = NULL;
    if (strcmp(model, "gpt-4o") == 0)
    {
        url = "https://lingyunapi.com/v1/completions";
    }
    else
    {
        url = "https://lingyunapi.com/v1/chat/completions";
    }
    const char *api_key = getenv("KEY");
    if (!api_key) {
        fprintf(stderr, "KEY environment variable not set\n");
        return NULL;
    }
    char auth_header[256];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", api_key);
    char *content_header = "Content-Type: application/json";
    char *accept_header = "Accept: application/json";
    char *data = NULL;
    if (strcmp(model, "gpt-4o") == 0)
    {
        asprintf(&data, "{\"model\": \"gpt-4o\", \"prompt\": \"%s\", \"max_tokens\": %d, \"temperature\": %f}", prompt, MAX_TOKENS, temperature);
    }
    else
    {
        asprintf(&data, "{\"model\": \"gpt-4o-mini\",\"messages\": %s, \"max_tokens\": %d, \"temperature\": %f}", prompt, MAX_TOKENS, temperature);
    }
    
    // DEBUG: Print request data for hypothesis system debugging
    if (strstr(prompt, "protocol") != NULL && strstr(prompt, "templates") != NULL) {
        fprintf(stderr, "\n=== LLM REQUEST DEBUG ===\n");
        fprintf(stderr, "URL: %s\n", url);
        fprintf(stderr, "Data length: %zu bytes\n", strlen(data));
        fprintf(stderr, "First 500 chars of data:\n%.500s\n", data);
        fprintf(stderr, "========================\n\n");
    }
    do
    {
        struct MemoryStruct chunk;

        chunk.memory = malloc(1); /* will be grown as needed by the realloc above */
        chunk.size = 0;           /* no data at this point */

        curl = curl_easy_init();
        if (curl)
        {
            struct curl_slist *headers = NULL;
            headers = curl_slist_append(headers, auth_header);
            headers = curl_slist_append(headers, content_header);
            headers = curl_slist_append(headers, accept_header);

            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, chat_with_llm_helper);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
            
            // Set timeouts to prevent hanging
            curl_easy_setopt(curl, CURLOPT_TIMEOUT, 120L);  // Total request timeout: 120 seconds
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);  // Connection timeout: 30 seconds

            res = curl_easy_perform(curl);

            if (res == CURLE_OK)
            {
                json_object *jobj = json_tokener_parse(chunk.memory);

                // Check if the "choices" key exists
                if (json_object_object_get_ex(jobj, "choices", NULL))
                {
                    json_object *choices = json_object_object_get(jobj, "choices");
                    json_object *first_choice = json_object_array_get_idx(choices, 0);
                    const char *data;

                    // The answer begins with a newline character, so we remove it
                    if (strcmp(model, "gpt-4o") == 0)
                    {
                        json_object *jobj4 = json_object_object_get(first_choice, "text");
                        data = json_object_get_string(jobj4);
                    }
                    else
                    {
                        json_object *jobj4 = json_object_object_get(first_choice, "message");
                        json_object *jobj5 = json_object_object_get(jobj4, "content");
                        data = json_object_get_string(jobj5);
                    }
                    if (data[0] == '\n')
                        data++;
                    answer = strdup(data);
                }
                else
                {
                    printf("Error response is: %s\n", chunk.memory);
                    sleep(2); // Sleep for a small amount of time to ensure that the service can recover
                }
                json_object_put(jobj);
            }
            else
            {
                printf("Error: %s\n", curl_easy_strerror(res));
            }

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }

        free(chunk.memory);
    } while ((res != CURLE_OK || answer == NULL) && (--tries > 0));

    if (data != NULL)
    {
        free(data);
    }

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
 * llm_handle_plateau: state-aware plateau handler.
 * - Builds a rich prompt embedding state coverage stats (state_ctx)
 * - Asks LLM to return either suggested_request OR actions[]
 * - Passes response back as raw JSON for parent-side validation
 * state_ctx: JSON string like {"nodes":N,"edges":M,"growth_rate":X,...}, may be NULL
 */
char *llm_handle_plateau(const char *protocol_name, const char *examples,
                         const char *history, const char *state_ctx) {
    if (!protocol_name) return NULL;

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
        "  - seed_ids: exact seed indices reachable from this state (use in prioritize_seeds)\n\n"
        "**Communication History (most recent interactions):**\n\"\"\"%s\"\"\"\n\n"
        "**Example Request Formats:**\n%s\n\n"
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
        "- States with seeds_count=0: cannot be targeted, skip them\n"
        "- Use the EXACT state id and seed_ids numbers from the states[] data — do NOT invent IDs\n"
        "- Strategy A (suggested_request) is best when history shows unrecognized commands\n\n"
        "Respond with ONLY valid JSON. No markdown, no code blocks, no explanation outside JSON.",
        protocol_name,
        state_section ? state_section : "",
        history ? history : "",
        examples ? examples : "");
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

    char *resp = chat_with_llm(prompt, "gpt-4o-mini", STALL_RETRIES, 1.2);
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
    ck_free(formatted);
    return out;
}

/* Lookup table of per-protocol few-shot examples for grammar prompts.
 * Each entry shows ONE representative message of that protocol using the
 * exact <<VALUE>> template format so the LLM knows the expected output style.
 * Format convention (same as rest of code):
 *   \\n       -> literal \n seen by LLM
 *   \\\"      -> literal " seen by LLM
 *   \\\\r\\\\n -> literal \r\n seen by LLM
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
     "For the FTP protocol, the USER client request template is:\\n"
     "USER: [\\\"USER <<VALUE>>\\\\r\\\\n\\\"]"},
    {"SMTP", "EHLO",
     "For the SMTP protocol, the EHLO client request template is:\\n"
     "EHLO: [\\\"EHLO <<VALUE>>\\\\r\\\\n\\\"]"},
    {"RTSP", "DESCRIBE",
     "For the RTSP protocol, the DESCRIBE client request template is:\\n"
     "DESCRIBE: [\\\"DESCRIBE <<VALUE>>\\\\r\\\\n\\\","
     "\\\"CSeq: <<VALUE>>\\\\r\\\\n\\\","
     "\\\"User-Agent: <<VALUE>>\\\\r\\\\n\\\","
     "\\\"Accept: <<VALUE>>\\\\r\\\\n\\\","
     "\\\"\\\\r\\\\n\\\"]"},
    {"HTTP", "GET",
     "For the HTTP protocol, the GET client request template is:\\n"
     "GET: [\\\"GET <<VALUE>> HTTP/1.1\\\\r\\\\n\\\","
     "\\\"Host: <<VALUE>>\\\\r\\\\n\\\","
     "\\\"\\\\r\\\\n\\\"]"},
    {"SIP",  "REGISTER",
     "For the SIP protocol, the REGISTER client request template is:\\n"
     "REGISTER: [\\\"REGISTER sip:<<VALUE>> SIP/2.0\\\\r\\\\n\\\","
     "\\\"Via: SIP/2.0/UDP <<VALUE>>\\\\r\\\\n\\\","
     "\\\"From: <sip:<<VALUE>>>\\\\r\\\\n\\\","
     "\\\"To: <sip:<<VALUE>>>\\\\r\\\\n\\\","
     "\\\"CSeq: <<VALUE>> REGISTER\\\\r\\\\n\\\","
     "\\\"\\\\r\\\\n\\\"]"},
    {"DAAP", "login",
     "For the DAAP protocol, the login client request template is:\\n"
     "login: [\\\"GET /login?pairing-guid=<<VALUE>> HTTP/1.1\\\\r\\\\n\\\","
     "\\\"Host: <<VALUE>>\\\\r\\\\n\\\","
     "\\\"Client-DAAP-Version: <<VALUE>>\\\\r\\\\n\\\","
     "\\\"\\\\r\\\\n\\\"]"},
    {"MQTT", "CONNECT",
     "For the MQTT protocol, the CONNECT packet template is:\\n"
     "CONNECT: [\\\"\\\\x10<<VALUE>>\\\\x00\\\\x04MQTT\\\\x04<<VALUE>>\\\\x00\\\\x3c\\\\x00<<VALUE>>\\\"]"},
    {"DNS",  "QUERY",
     "For the DNS protocol, the QUERY request template is:\\n"
     "QUERY: [\\\"<<VALUE>>\\\\x01\\\\x00\\\\x00\\\\x01\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00\\\\x00<<VALUE>>\\\"]"},
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
             "%s\\n"
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
        char *state_answer = chat_with_llm(state_prompt, "gpt-4o-mini", MESSAGE_TYPE_RETRIES, 0.5);
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
            /* Ensure capacity */
            if (out_pos + line_len + 4 >= cap) {
                cap = (out_pos + line_len + 64) * 2;
                out = realloc(out, cap);
                if (!out) return NULL;
            }

            memcpy(out + out_pos, src, line_len);
            out_pos += line_len;

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
    {"FTP",
     "ALLO+STOR, REST+RETR, REIN, PASV/PORT switches, MLSD/MLST",
     "invalid paths (/../..), long filenames (256+ chars), permission denials, case variants (MKD vs mkd)",
     "Each command on its own line with arguments, terminated by \\r\\n. "
     "NO blank lines between commands. Use concrete values, NOT placeholders "
     "like <<VALUE>>. Example: USER anonymous\\r\\nPASS guest\\r\\n"},
    {"SMTP",
     "EHLO+MAIL+RCPT+DATA, AUTH LOGIN/PLAIN, VRFY/EXPN probing, RSET+MAIL chains",
     "malformed addresses, oversized headers, repeated RSET, missing EHLO, bare CR/LF",
     "Each command on its own line with arguments, terminated by \\r\\n. "
     "NO blank lines between commands. Use concrete values, NOT placeholders "
     "like <<USERNAME>>. Example: EHLO test.com\\r\\nMAIL FROM:<user@test.com>\\r\\n"},
    {"RTSP",
     "DESCRIBE+SETUP+PLAY+PAUSE+TEARDOWN, interleaved channel requests, OPTIONS probing",
     "invalid session IDs, malformed stream URIs, unsupported transport specs, bad CSeq",
     "Each request includes: command URL RTSP/1.0, headers (CSeq, Transport, Session), "
     "and is terminated by a blank line (\\r\\n\\r\\n)"},
    {"HTTP",
     "GET/POST/PUT/DELETE/OPTIONS/HEAD sequences, pipelining, chunked transfer, keep-alive",
     "path traversal (/../), oversized headers, invalid methods, malformed URIs, HTTP/0.9",
     "Each request includes: METHOD path HTTP/1.1, headers (Host, Content-Type, etc.), "
     "and is terminated by a blank line (\\r\\n\\r\\n)"},
    {"SIP",
     "REGISTER+INVITE+ACK+BYE, CANCEL, OPTIONS, re-registration, forked dialogs",
     "malformed SIP URIs, missing Via/From/To headers, invalid CSeq, loop detection",
     "Each request includes: METHOD sip:URI SIP/2.0, headers (Via, From, To, CSeq, Call-ID), "
     "and is terminated by a blank line (\\r\\n\\r\\n)"},
    {"DAAP",
     "login+server-info+update+databases+items+containers sequences, session management",
     "invalid session tokens, malformed content-codes, unexpected revision numbers",
     "Each request includes: GET path HTTP/1.1, headers (Host, Client-DAAP-Version), "
     "and is terminated by a blank line (\\r\\n\\r\\n)"},
    {"MQTT",
     "CONNECT+SUBSCRIBE+PUBLISH+UNSUBSCRIBE+DISCONNECT, PINGREQ/PINGRESP, QoS 0/1/2",
     "oversized client IDs, invalid topic filters, will message variations, clean session",
     "Output MQTT commands in text-representable format with all required fields"},
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

    char *response = chat_with_llm(prompt, "gpt-4o-mini", ENRICHMENT_RETRIES, 0.5);

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
//     // char *answer = chat_with_llm(prompt, "gpt-4o-mini");
//     // printf("## Answer from LLM:\n %s\n", answer);

//     char *protocol_name = argv[1];
//     khash_t(consistency_table) *const_table = kh_init(consistency_table);
//     klist_t(rang) *protocol_patterns = kl_init(rang);

//     for (int iter = 0; iter < 5; iter++)
//     {

//         char *templates_prompt = construct_prompt_for_templates(protocol_name);
//         char *templates_answer = chat_with_llm(templates_prompt, "gpt-4o-mini");
//         // printf("## Answer from LLM:\n %s\n", templates_answer);
//         char *remaining_prompt = construct_prompt_for_remaining_templates(protocol_name, templates_prompt, templates_answer);
//         // printf("remaining prompt is:\n %s\n", remaining_prompt);
//         char *remaining_templates = chat_with_llm(remaining_prompt, "gpt-4o-mini");
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
