/* Auto-generated from RFC Grammar Converter */
/* Protocol: FTP (RFC 959) */
#ifndef RFC_GRAMMAR_FTP_H
#define RFC_GRAMMAR_FTP_H

#define FTP_GRAMMAR_JSON \
"{ \
  \"protocol\": \"FTP\", \
  \"rfc\": \"RFC 959\", \
  \"format\": \"JSON-Template-with-Constraints\", \
  \"generated_method\": \"predefined\", \
  \"commands\": { \
    \"USER\": { \
      \"template\": [ \
        \"USER <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"PASS\": { \
      \"template\": [ \
        \"PASS <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"CWD\": { \
      \"template\": [ \
        \"CWD <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"QUIT\": { \
      \"template\": [ \
        \"QUIT <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"PORT\": { \
      \"template\": [ \
        \"PORT <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"PASV\": { \
      \"template\": [ \
        \"PASV <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"LIST\": { \
      \"template\": [ \
        \"LIST <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"RETR\": { \
      \"template\": [ \
        \"RETR <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"STOR\": { \
      \"template\": [ \
        \"STOR <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"DELE\": { \
      \"template\": [ \
        \"DELE <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"string\", \
          \"max_length\": 256 \
        } \
      } \
    } \
  }, \
  \"responses\": [ \
    \"220\", \
    \"331\", \
    \"230\", \
    \"221\", \
    \"200\", \
    \"227\", \
    \"150\", \
    \"226\", \
    \"550\" \
  ], \
  \"state_machine\": { \
    \"INIT\": [ \
      \"USER\" \
    ], \
    \"USER_OK\": [ \
      \"PASS\" \
    ], \
    \"LOGGED_IN\": [ \
      \"CWD\", \
      \"PORT\", \
      \"PASV\", \
      \"LIST\", \
      \"RETR\", \
      \"STOR\", \
      \"DELE\", \
      \"QUIT\" \
    ], \
    \"DATA_CONN\": [ \
      \"LIST\", \
      \"RETR\", \
      \"STOR\" \
    ] \
  }, \
  \"constraints\": {} \
}"

#endif /* RFC_GRAMMAR_FTP_H */
