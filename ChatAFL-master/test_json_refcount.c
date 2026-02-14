#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>

int main() {
    // 模拟generate_grammar_hypotheses的操作
    const char *json_str = "[{\"message_type\":\"TEST\",\"description\":\"test\",\"schema\":{\"type\":\"object\"},\"production_rules\":[\"rule1\"]}]";
    
    printf("1. Parsing JSON array...\n");
    json_object *response_json = json_tokener_parse(json_str);
    if (!response_json) {
        printf("Failed to parse\n");
        return 1;
    }
    printf("   response_json refcount: %d\n", json_object_get_refcount(response_json));
    
    printf("\n2. Getting array element...\n");
    json_object *hyp_json = json_object_array_get_idx(response_json, 0);
    printf("   hyp_json refcount: %d\n", json_object_get_refcount(hyp_json));
    printf("   response_json refcount: %d\n", json_object_get_refcount(response_json));
    
    printf("\n3. Serializing element to string...\n");
    const char *json_str_ptr = json_object_to_json_string(hyp_json);
    char *json_str_copy = strdup(json_str_ptr);
    printf("   hyp_json refcount: %d\n", json_object_get_refcount(hyp_json));
    printf("   response_json refcount: %d\n", json_object_get_refcount(response_json));
    
    printf("\n4. Re-parsing the string (simulating parse_llm_hypothesis_response)...\n");
    json_object *jobj = json_tokener_parse(json_str_copy);
    printf("   jobj refcount: %d (independent object)\n", json_object_get_refcount(jobj));
    printf("   hyp_json refcount: %d\n", json_object_get_refcount(hyp_json));
    printf("   response_json refcount: %d\n", json_object_get_refcount(response_json));
    
    printf("\n5. Freeing jobj (from parse_llm_hypothesis_response)...\n");
    json_object_put(jobj);
    printf("   hyp_json refcount: %d\n", json_object_get_refcount(hyp_json));
    printf("   response_json refcount: %d\n", json_object_get_refcount(response_json));
    
    printf("\n6. Freeing response_json (this should work)...\n");
    json_object_put(response_json);
    printf("   SUCCESS - no crash!\n");
    
    free(json_str_copy);
    return 0;
}
