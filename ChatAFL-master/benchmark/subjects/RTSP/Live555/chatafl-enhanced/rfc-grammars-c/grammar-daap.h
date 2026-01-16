/* Auto-generated from RFC Grammar Converter */
/* Protocol: DAAP (DAAP Spec) */
#ifndef RFC_GRAMMAR_DAAP_H
#define RFC_GRAMMAR_DAAP_H

#define DAAP_GRAMMAR_JSON \
"{ \
  \"protocol\": \"DAAP\", \
  \"rfc\": \"DAAP Spec\", \
  \"format\": \"JSON-Template-with-Constraints\", \
  \"generated_method\": \"predefined\", \
  \"commands\": { \
    \"login\": { \
      \"template\": [ \
        \"login <<VALUE>>\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 512 \
        } \
      } \
    }, \
    \"update\": { \
      \"template\": [ \
        \"update <<VALUE>>\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 512 \
        } \
      } \
    }, \
    \"databases\": { \
      \"template\": [ \
        \"databases <<VALUE>>\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 512 \
        } \
      } \
    }, \
    \"containers\": { \
      \"template\": [ \
        \"containers <<VALUE>>\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 512 \
        } \
      } \
    }, \
    \"items\": { \
      \"template\": [ \
        \"items <<VALUE>>\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 512 \
        } \
      } \
    } \
  }, \
  \"responses\": [ \
    \"200\", \
    \"204\", \
    \"400\", \
    \"401\", \
    \"403\", \
    \"404\" \
  ], \
  \"state_machine\": { \
    \"INIT\": [ \
      \"login\" \
    ], \
    \"AUTHENTICATED\": [ \
      \"databases\", \
      \"update\" \
    ], \
    \"BROWSING\": [ \
      \"containers\", \
      \"items\" \
    ] \
  }, \
  \"constraints\": {} \
}"

#endif /* RFC_GRAMMAR_DAAP_H */
