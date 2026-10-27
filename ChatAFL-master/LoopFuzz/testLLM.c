#include <curl/curl.h>
#include <json-c/json.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI"
 * Optional: LLM_MODEL and CHATAFL_LLM_BASE (the complete chat endpoint URL).
 * gcc -o testLLM testLLM.c -lcurl -ljson-c -Wall -g && ./testLLM
 */
#define MAX_TOKENS 2048
#define DEFAULT_MODEL "codex-auto-review"
#define DEFAULT_URL "https://www.cctq.ai/v1/chat/completions"

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t receive_response(void *contents, size_t size, size_t nmemb,
                               void *userp)
{
    struct MemoryStruct *mem = userp;
    if (size && nmemb > SIZE_MAX / size)
        return 0;
    size_t length = size * nmemb;
    if (mem->size == SIZE_MAX || length > SIZE_MAX - mem->size - 1)
        return 0;
    char *grown = realloc(mem->memory, mem->size + length + 1);
    if (!grown)
        return 0;
    mem->memory = grown;
    memcpy(mem->memory + mem->size, contents, length);
    mem->size += length;
    mem->memory[mem->size] = '\0';
    return length;
}

static int retryable_transport(CURLcode result)
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

static long request_timeout_ms(void)
{
    const char *setting = getenv("CHATAFL_LLM_TIMEOUT_MS");
    if (setting && *setting) {
        char *end;
        long value = strtol(setting, &end, 10);
        if (!*end && value > 0 && value <= 900000)
            return value;
    }
    return 120000L;
}

char *chat_with_llm(const char *prompt, const char *model, int tries,
                    float temperature)
{
    const char *key = getenv("KEY");
    if (!key || !*key) {
        fprintf(stderr, "KEY is not set or is empty.\n");
        return NULL;
    }
    if (strpbrk(key, "\r\n")) {
        fprintf(stderr, "KEY contains an invalid newline.\n");
        return NULL;
    }
    const char *url = getenv("CHATAFL_LLM_BASE");
    if (!url || !*url)
        url = DEFAULT_URL;

    json_object *messages = json_tokener_parse(prompt);
    if (!messages || !json_object_is_type(messages, json_type_array) ||
        !json_object_array_length(messages)) {
        fprintf(stderr, "Prompt must be a nonempty JSON messages array.\n");
        if (messages)
            json_object_put(messages);
        return NULL;
    }
    json_object *request = json_object_new_object();
    if (!request) {
        json_object_put(messages);
        return NULL;
    }
    /* Serialize objects with json-c: messages is an array, not a quoted string. */
    json_object_object_add(request, "model", json_object_new_string(model));
    json_object_object_add(request, "messages", messages);
    json_object_object_add(request, "max_tokens", json_object_new_int(MAX_TOKENS));
    json_object_object_add(request, "temperature", json_object_new_double(temperature));
    const char *body = json_object_to_json_string_ext(request, JSON_C_TO_STRING_PLAIN);

    const char prefix[] = "Authorization: Bearer ";
    size_t auth_size = sizeof(prefix) + strlen(key);
    char *authorization = malloc(auth_size);
    if (!authorization) {
        json_object_put(request);
        return NULL;
    }
    snprintf(authorization, auth_size, "%s%s", prefix, key);
    struct curl_slist *headers = NULL;
    const char *header_values[] = {authorization, "Content-Type: application/json",
                                   "Accept: application/json"};
    for (size_t i = 0; i < sizeof(header_values) / sizeof(header_values[0]); ++i) {
        struct curl_slist *next = curl_slist_append(headers, header_values[i]);
        if (!next) {
            curl_slist_free_all(headers);
            free(authorization);
            json_object_put(request);
            return NULL;
        }
        headers = next;
    }
    free(authorization);

    char *answer = NULL;
    printf("[DEBUG] model: %s\n[DEBUG] url: %s\n[DEBUG] data: %s\n",
           model, url, body);
    fflush(stdout);
    for (int attempt = 1; attempt <= tries; ++attempt) {
        struct MemoryStruct chunk = {calloc(1, 1), 0};
        CURL *curl = curl_easy_init();
        if (!chunk.memory || !curl) {
            free(chunk.memory);
            if (curl)
                curl_easy_cleanup(curl);
            break;
        }
        char error[CURL_ERROR_SIZE] = {0};
        long status = 0;
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_response);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
        curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, 15000L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, request_timeout_ms());
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        /* Keep both certificate and hostname verification enabled. */
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

        CURLcode result = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        fprintf(stderr, "[DEBUG] attempt %d/%d: curl=%d (%s), HTTP=%ld\n",
                attempt, tries, result, curl_easy_strerror(result), status);
        int retry = 0;
        if (result != CURLE_OK) {
            fprintf(stderr, "Transport error: %s\n", *error ? error : curl_easy_strerror(result));
            retry = retryable_transport(result);
        } else if (status < 200 || status >= 300) {
            fprintf(stderr, "API error (HTTP %ld): %s\n", status, chunk.memory);
            retry = status == 408 || status == 429 || status == 500 ||
                    status == 502 || status == 503 || status == 504;
        } else {
            json_object *response = json_tokener_parse(chunk.memory);
            json_object *choices = NULL, *message = NULL, *content = NULL;
            if (response && json_object_object_get_ex(response, "choices", &choices) &&
                json_object_is_type(choices, json_type_array) &&
                json_object_array_length(choices) > 0) {
                json_object *first = json_object_array_get_idx(choices, 0);
                if (json_object_object_get_ex(first, "message", &message) &&
                    json_object_object_get_ex(message, "content", &content) &&
                    json_object_is_type(content, json_type_string)) {
                    const char *text = json_object_get_string(content);
                    if (*text == '\n')
                        ++text;
                    if (*text)
                        answer = strdup(text);
                }
            }
            if (!answer)
                fprintf(stderr, "Invalid chat response (expected choices[0].message.content): %s\n",
                        chunk.memory);
            if (response)
                json_object_put(response);
        }
        curl_easy_cleanup(curl);
        free(chunk.memory);
        if (answer || !retry || attempt == tries)
            break;
        fprintf(stderr, "Retrying in %d second(s).\n", attempt);
        sleep((unsigned int)attempt);
    }
    curl_slist_free_all(headers);
    json_object_put(request);
    return answer;
}

int main(void)
{
    const char *messages = "[{\"role\":\"user\",\"content\":\"You are an expert in networking protocols. For the RTSP protocol, the typical sequence is: DESCRIBE, SETUP, PLAY. Please explain where SET_PARAMETER and TEARDOWN should be placed in this sequence.\"}]";
    const char *model = getenv("LLM_MODEL");
    if (!model || !*model)
        model = DEFAULT_MODEL;
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "Failed to initialize libcurl.\n");
        return EXIT_FAILURE;
    }
    printf("Sending request to LLM API...\n");
    char *response = chat_with_llm(messages, model, 3, 0.7f);
    if (response)
        printf("\n=== LLM Response ===\n%s\n", response);
    else
        fprintf(stderr, "LLM request failed.\n");
    int result = response ? EXIT_SUCCESS : EXIT_FAILURE;
    free(response);
    curl_global_cleanup();
    return result;
}
