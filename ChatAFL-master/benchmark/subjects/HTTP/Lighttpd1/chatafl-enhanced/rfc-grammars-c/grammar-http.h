/* Auto-generated from RFC Grammar Converter */
/* Protocol: HTTP (RFC 2616) */
#ifndef RFC_GRAMMAR_HTTP_H
#define RFC_GRAMMAR_HTTP_H

#define HTTP_GRAMMAR_JSON \
"{ \
  \"protocol\": \"HTTP\", \
  \"rfc\": \"RFC 2616\", \
  \"format\": \"JSON-Template-with-Constraints\", \
  \"generated_method\": \"predefined\", \
  \"commands\": { \
    \"GET\": { \
      \"template\": [ \
        \"GET <<URI>> HTTP/1.1\\r\\nHost: <<HOST>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URI\": { \
          \"type\": \"uri_path\", \
          \"max_length\": 2048 \
        }, \
        \"HOST\": { \
          \"type\": \"hostname\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"POST\": { \
      \"template\": [ \
        \"POST <<URI>> HTTP/1.1\\r\\nHost: <<HOST>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URI\": { \
          \"type\": \"uri_path\", \
          \"max_length\": 2048 \
        }, \
        \"HOST\": { \
          \"type\": \"hostname\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"PUT\": { \
      \"template\": [ \
        \"PUT <<URI>> HTTP/1.1\\r\\nHost: <<HOST>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URI\": { \
          \"type\": \"uri_path\", \
          \"max_length\": 2048 \
        }, \
        \"HOST\": { \
          \"type\": \"hostname\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"DELETE\": { \
      \"template\": [ \
        \"DELETE <<URI>> HTTP/1.1\\r\\nHost: <<HOST>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URI\": { \
          \"type\": \"uri_path\", \
          \"max_length\": 2048 \
        }, \
        \"HOST\": { \
          \"type\": \"hostname\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"HEAD\": { \
      \"template\": [ \
        \"HEAD <<URI>> HTTP/1.1\\r\\nHost: <<HOST>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URI\": { \
          \"type\": \"uri_path\", \
          \"max_length\": 2048 \
        }, \
        \"HOST\": { \
          \"type\": \"hostname\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"OPTIONS\": { \
      \"template\": [ \
        \"OPTIONS <<URI>> HTTP/1.1\\r\\nHost: <<HOST>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URI\": { \
          \"type\": \"uri_path\", \
          \"max_length\": 2048 \
        }, \
        \"HOST\": { \
          \"type\": \"hostname\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"TRACE\": { \
      \"template\": [ \
        \"TRACE <<URI>> HTTP/1.1\\r\\nHost: <<HOST>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URI\": { \
          \"type\": \"uri_path\", \
          \"max_length\": 2048 \
        }, \
        \"HOST\": { \
          \"type\": \"hostname\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"CONNECT\": { \
      \"template\": [ \
        \"CONNECT <<URI>> HTTP/1.1\\r\\nHost: <<HOST>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URI\": { \
          \"type\": \"uri_path\", \
          \"max_length\": 2048 \
        }, \
        \"HOST\": { \
          \"type\": \"hostname\", \
          \"max_length\": 256 \
        } \
      } \
    } \
  }, \
  \"responses\": [ \
    \"200\", \
    \"201\", \
    \"204\", \
    \"301\", \
    \"302\", \
    \"400\", \
    \"401\", \
    \"403\", \
    \"404\", \
    \"500\" \
  ], \
  \"state_machine\": { \
    \"INIT\": [ \
      \"GET\", \
      \"POST\", \
      \"PUT\", \
      \"DELETE\", \
      \"HEAD\", \
      \"OPTIONS\" \
    ], \
    \"REQUEST_SENT\": [ \
      \"response\" \
    ], \
    \"RESPONSE_RECEIVED\": [ \
      \"GET\", \
      \"POST\" \
    ] \
  }, \
  \"constraints\": {} \
}"

#endif /* RFC_GRAMMAR_HTTP_H */
