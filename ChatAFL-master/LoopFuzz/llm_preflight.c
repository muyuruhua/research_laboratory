#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "chat-llm.h"

/* Exercise the campaign's real client without printing credentials or answers. */
int main(void)
{
    const char *disabled = getenv("CHATAFL_NO_LLM");
    if (disabled && *disabled && strcmp(disabled, "0") != 0) {
        puts("[LLM preflight] SKIP (CHATAFL_NO_LLM)");
        return EXIT_SUCCESS;
    }

    chat_llm_global_init();
    const char *key = getenv("KEY");
    const char *endpoint = getenv("CHATAFL_LLM_BASE");
    if (!endpoint || !*endpoint)
        endpoint = "https://www.cctq.ai/v1/chat/completions";
    printf("[LLM preflight] endpoint=%s model=%s key_bytes=%zu max_tokens=%d top_p=%.6g\n",
           endpoint, llm_active_model(), key ? strlen(key) : 0,
           llm_active_max_tokens(), llm_active_top_p());
    fflush(stdout);

    char messages[] = "[{\"role\":\"user\",\"content\":\"Reply OK.\"}]";
    char *answer = chat_with_llm(messages, (char *)llm_active_model(), 1, 0.7f);
    int result = answer ? EXIT_SUCCESS : EXIT_FAILURE;
    puts(answer ? "[LLM preflight] PASS" : "[LLM preflight] FAIL");
    free(answer);
    chat_llm_global_cleanup();
    return result;
}
