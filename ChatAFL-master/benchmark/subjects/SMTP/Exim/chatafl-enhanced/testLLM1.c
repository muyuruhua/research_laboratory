#define _GNU_SOURCE // asprintf
#include <stdio.h>
#include <curl/curl.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <json-c/json.h>

//#include "chat-llm.h"
#include "alloc-inl.h"
#include "hash.h"

// -lcurl -ljson-c -lpcre2-8
// apt install libcurl4-openssl-dev libjson-c-dev libpcre2-dev libpcre2-8-0

#define MAX_TOKENS 2048
#define CONFIDENT_TIMES 3

/*
大模型调用示例
导入大模型key：export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"
执行命令：gcc -I/opt/homebrew/include -L/opt/homebrew/lib -o testLLM1 testLLM1.c -lcurl -ljson-c -Wall -g && ./testLLM1
执行命令：gcc  -o testLLM1 testLLM1.c -lcurl -ljson-c -Wall -g && ./testLLM1

*/

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

char *chat_with_llm(const char *prompt, const char *model, int tries, float temperature)
{
    CURL *curl;
    CURLcode res = CURLE_OK;
    char *answer = NULL;
    char *url = NULL;
    printf("[DEBUG] model: %s\n", model);
    printf("[DEBUG] prompt: %s\n", prompt);
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
        fprintf(stderr, "KEY not set\n");
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
    printf("[DEBUG] url: %s\n", url);
    printf("[DEBUG] data: %s\n", data);
    curl_global_init(CURL_GLOBAL_DEFAULT);
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


            res = curl_easy_perform(curl);
            printf("[DEBUG] curl_easy_perform result: %d (%s)\n", res, curl_easy_strerror(res));

            if (chunk.memory && chunk.size > 0) {
                printf("[DEBUG] API raw response: %s\n", chunk.memory);
            } else {
                printf("[DEBUG] No response received from API.\n");
            }
            if (res == CURLE_OK)
            {
                json_object *jobj = json_tokener_parse(chunk.memory);
                if (!jobj) {
                    printf("[DEBUG] Failed to parse JSON response.\n");
                }
                // Check if the "choices" key exists
                if (jobj && json_object_object_get_ex(jobj, "choices", NULL))
                {
                    json_object *choices = json_object_object_get(jobj, "choices");
                    json_object *first_choice = json_object_array_get_idx(choices, 0);
                    const char *data;

                    // The answer begins with a newline character, so we remove it
                    if (strcmp(model, "instruct") == 0)
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
                    if (data && data[0] == '\n')
                        data++;
                    answer = strdup(data);
                    printf("[DEBUG] Parsed answer: %s\n", answer);
                }
                else
                {
                    printf("[DEBUG] Error response is: %s\n", chunk.memory);
                    sleep(2); // Sleep for a small amount of time to ensure that the service can recover
                }
                if (jobj) json_object_put(jobj);
            }
            else
            {
                printf("[DEBUG] Error: %s\n", curl_easy_strerror(res));
            }
            fflush(stdout);

            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
        }

        free(chunk.memory);
    } while ((res != CURLE_OK || answer == NULL) && (--tries > 0));

    if (data != NULL)
    {
        free(data);
    }

    curl_global_cleanup();
    return answer;
}


int main() {
    char* messages = "[{\"role\": \"user\", \"content\": \"You are an expert in networking protocols. For the RTSP protocol, the typical sequence is: DESCRIBE, SETUP, PLAY. Please explain where SET_PARAMETER and TEARDOWN should be placed in this sequence.\"}]";
    char* model ="gpt-4o-mini";
    printf("Sending request to LLM API...\n");
    char* response = chat_with_llm(messages, model, 3, 0.7);
    if (response) {
        printf("\n=== LLM Response ===\n");
        printf("%s\n", response);
        free(response);
    }
    return 0;
}