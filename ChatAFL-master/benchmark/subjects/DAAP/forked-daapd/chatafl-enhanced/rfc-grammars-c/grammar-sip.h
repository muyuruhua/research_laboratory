/* Auto-generated from RFC Grammar Converter */
/* Protocol: SIP (RFC 3261) */
#ifndef RFC_GRAMMAR_SIP_H
#define RFC_GRAMMAR_SIP_H

#define SIP_GRAMMAR_JSON \
"{ \
  \"protocol\": \"SIP\", \
  \"rfc\": \"RFC 3261\", \
  \"format\": \"JSON-Template-with-Constraints\", \
  \"generated_method\": \"predefined\", \
  \"commands\": { \
    \"INVITE\": { \
      \"template\": [ \
        \"INVITE <<VALUE>>\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 512 \
        } \
      } \
    }, \
    \"ACK\": { \
      \"template\": [ \
        \"ACK <<VALUE>>\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 512 \
        } \
      } \
    }, \
    \"BYE\": { \
      \"template\": [ \
        \"BYE <<VALUE>>\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 512 \
        } \
      } \
    }, \
    \"CANCEL\": { \
      \"template\": [ \
        \"CANCEL <<VALUE>>\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 512 \
        } \
      } \
    }, \
    \"REGISTER\": { \
      \"template\": [ \
        \"REGISTER <<VALUE>>\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 512 \
        } \
      } \
    }, \
    \"OPTIONS\": { \
      \"template\": [ \
        \"OPTIONS <<VALUE>>\" \
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
    \"100\", \
    \"180\", \
    \"200\", \
    \"400\", \
    \"404\", \
    \"487\" \
  ], \
  \"state_machine\": { \
    \"INIT\": [ \
      \"REGISTER\", \
      \"INVITE\", \
      \"OPTIONS\" \
    ], \
    \"REGISTERED\": [ \
      \"INVITE\" \
    ], \
    \"CALLING\": [ \
      \"CANCEL\", \
      \"ACK\" \
    ], \
    \"ESTABLISHED\": [ \
      \"BYE\" \
    ] \
  }, \
  \"constraints\": {} \
}"

#endif /* RFC_GRAMMAR_SIP_H */
