/* llm-validator.c
 * Simple JSON schema validator for LLM outputs.
/* llm-validator.c
 * Simple JSON schema validator for LLM outputs.
 * Exports: validate_and_parse_llm_json()
 */

#include "chat-llm.h"
#include <string.h>
#include <stddef.h>
#include <stdlib.h>

/* Parse and validate LLM JSON. Allowed top-level variants:
 * - { "suggested_request": "..." }
 * - { "actions": [ {"type":"...", ...}, ... ] }
 * Returns a new json_object* (caller must json_object_put) or NULL on error.
 */
struct json_object *validate_and_parse_llm_json(const char *json_str) {
    if (!json_str) return NULL;
    struct json_object *jroot = json_tokener_parse(json_str);
    if (!jroot) return NULL;

    if (!json_object_is_type(jroot, json_type_object)) {
        json_object_put(jroot);
        return NULL;
    }

    /* Check if suggested_request exists */
    struct json_object *jreq = NULL;
    if (json_object_object_get_ex(jroot, "suggested_request", &jreq)) {
        if (!json_object_is_type(jreq, json_type_string)) { json_object_put(jroot); return NULL; }
        const char *req = json_object_get_string(jreq);
        if (!req) { json_object_put(jroot); return NULL; }
        size_t len = strlen(req);
        if (len == 0 || len >= 4096) { json_object_put(jroot); return NULL; }
        for (size_t i = 0; i < len; i++) {
            unsigned char c = (unsigned char)req[i];
            if (c < 9) { json_object_put(jroot); return NULL; }
            if (c > 13 && c < 32) { json_object_put(jroot); return NULL; }
        }
        /* Accept object as-is */
        return jroot;
    }

    /* Otherwise validate actions[] */
    struct json_object *jactions = NULL;
    if (json_object_object_get_ex(jroot, "actions", &jactions)) {
        if (!json_object_is_type(jactions, json_type_array)) { json_object_put(jroot); return NULL; }
        size_t na = json_object_array_length(jactions);
        if (na == 0) { json_object_put(jroot); return NULL; }
        for (size_t ai = 0; ai < na; ai++) {
            struct json_object *act = json_object_array_get_idx(jactions, ai);
            if (!json_object_is_type(act, json_type_object)) { json_object_put(jroot); return NULL; }
            struct json_object *jtype = NULL;
            if (!json_object_object_get_ex(act, "type", &jtype) || !json_object_is_type(jtype, json_type_string)) { json_object_put(jroot); return NULL; }
            const char *type = json_object_get_string(jtype);
            if (!type) { json_object_put(jroot); return NULL; }

            if (strcmp(type, "prioritize_seeds") == 0) {
                struct json_object *jsids = NULL;
                if (!json_object_object_get_ex(act, "seed_ids", &jsids) || !json_object_is_type(jsids, json_type_array)) { json_object_put(jroot); return NULL; }
                size_t nm = json_object_array_length(jsids);
                if (nm == 0 || nm > 100) { json_object_put(jroot); return NULL; }
                for (size_t k = 0; k < nm; k++) {
                    struct json_object *jid = json_object_array_get_idx(jsids, k);
                    if (!json_object_is_type(jid, json_type_int)) { json_object_put(jroot); return NULL; }
                    long v = json_object_get_int(jid);
                    if (v < 0) { json_object_put(jroot); return NULL; }
                }
            } else if (strcmp(type, "propose_mutations") == 0) {
                struct json_object *jseed = NULL;
                if (!json_object_object_get_ex(act, "seed_id", &jseed) || !json_object_is_type(jseed, json_type_int)) { json_object_put(jroot); return NULL; }
                long sid = json_object_get_int(jseed);
                if (sid < 0) { json_object_put(jroot); return NULL; }

                struct json_object *jops = NULL;
                if (!json_object_object_get_ex(act, "ops", &jops) || !json_object_is_type(jops, json_type_array)) { json_object_put(jroot); return NULL; }
                size_t nop = json_object_array_length(jops);
                if (nop == 0 || nop > 20) { json_object_put(jroot); return NULL; }
                for (size_t oi = 0; oi < nop; oi++) {
                    struct json_object *op = json_object_array_get_idx(jops, oi);
                    if (!json_object_is_type(op, json_type_object)) { json_object_put(jroot); return NULL; }
                    struct json_object *jop = NULL;
                    if (!json_object_object_get_ex(op, "op", &jop) || !json_object_is_type(jop, json_type_string)) { json_object_put(jroot); return NULL; }
                    const char *opname = json_object_get_string(jop);
                    if (!opname) { json_object_put(jroot); return NULL; }
                    if (strcmp(opname, "insert") == 0 || strcmp(opname, "replace") == 0) {
                        struct json_object *jpos = NULL, *jbytes = NULL;
                        if (!json_object_object_get_ex(op, "pos", &jpos) || !json_object_is_type(jpos, json_type_int)) { json_object_put(jroot); return NULL; }
                        if (!json_object_object_get_ex(op, "bytes_base64", &jbytes) || !json_object_is_type(jbytes, json_type_string)) { json_object_put(jroot); return NULL; }
                        const char *b64 = json_object_get_string(jbytes);
                        if (!b64 || strlen(b64) > 2048) { json_object_put(jroot); return NULL; }
                    } else if (strcmp(opname, "flip") == 0) {
                        struct json_object *jpos = NULL, *jlen = NULL;
                        if (!json_object_object_get_ex(op, "pos", &jpos) || !json_object_is_type(jpos, json_type_int)) { json_object_put(jroot); return NULL; }
                        if (!json_object_object_get_ex(op, "len", &jlen) || !json_object_is_type(jlen, json_type_int)) { json_object_put(jroot); return NULL; }
                        long l = json_object_get_int(jlen); if (l <= 0 || l > 4096) { json_object_put(jroot); return NULL; }
                    } else if (strcmp(opname, "grammar_expand") == 0) {
                        /* allow optional rule string */
                        struct json_object *jrule = NULL;
                        if (json_object_object_get_ex(op, "rule", &jrule) && !json_object_is_type(jrule, json_type_string)) { json_object_put(jroot); return NULL; }
                    } else {
                        json_object_put(jroot); return NULL;
                    }
                }
            } else if (strcmp(type, "set_target_state") == 0) {
                struct json_object *jsid = NULL;
                if (!json_object_object_get_ex(act, "state_id", &jsid) || !json_object_is_type(jsid, json_type_int)) { json_object_put(jroot); return NULL; }
                long sv = json_object_get_int(jsid);
                if (sv < 0) { json_object_put(jroot); return NULL; }
            } else if (strcmp(type, "suggest_strategy") == 0) {
                /* optional: allow with or without strategy field */
            } else {
                json_object_put(jroot); return NULL;
            }
        }
        return jroot;
    }

    /* Unknown top-level structure */
    json_object_put(jroot);
    return NULL;
}
