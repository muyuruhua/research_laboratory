/* Auto-generated from RFC Grammar Converter */
/* Protocol: SMTP (RFC 5321) */
#ifndef RFC_GRAMMAR_SMTP_H
#define RFC_GRAMMAR_SMTP_H

#define SMTP_GRAMMAR_JSON \
"{ \
  \"protocol\": \"SMTP\", \
  \"rfc\": \"RFC 5321\", \
  \"format\": \"JSON-Template-with-Constraints\", \
  \"generated_method\": \"predefined\", \
  \"commands\": { \
    \"EHLO\": { \
      \"template\": [ \
        \"EHLO <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"email_or_domain\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"HELO\": { \
      \"template\": [ \
        \"HELO <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"email_or_domain\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"MAIL\": { \
      \"template\": [ \
        \"MAIL <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"email_or_domain\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"RCPT\": { \
      \"template\": [ \
        \"RCPT <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"email_or_domain\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"DATA\": { \
      \"template\": [ \
        \"DATA <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"email_or_domain\", \
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
          \"type\": \"email_or_domain\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"RSET\": { \
      \"template\": [ \
        \"RSET <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"email_or_domain\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"VRFY\": { \
      \"template\": [ \
        \"VRFY <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"email_or_domain\", \
          \"max_length\": 256 \
        } \
      } \
    }, \
    \"EXPN\": { \
      \"template\": [ \
        \"EXPN <<VALUE>>\\r\\n\" \
      ], \
      \"constraints\": { \
        \"VALUE\": { \
          \"type\": \"email_or_domain\", \
          \"max_length\": 256 \
        } \
      } \
    } \
  }, \
  \"responses\": [ \
    \"220\", \
    \"250\", \
    \"354\", \
    \"221\", \
    \"550\", \
    \"551\", \
    \"552\", \
    \"553\", \
    \"554\" \
  ], \
  \"state_machine\": { \
    \"INIT\": [ \
      \"EHLO\", \
      \"HELO\" \
    ], \
    \"GREETED\": [ \
      \"MAIL\", \
      \"QUIT\", \
      \"RSET\" \
    ], \
    \"MAIL_OK\": [ \
      \"RCPT\" \
    ], \
    \"RCPT_OK\": [ \
      \"DATA\", \
      \"RCPT\" \
    ], \
    \"DATA_MODE\": [ \
      \".\", \
      \"QUIT\" \
    ] \
  }, \
  \"constraints\": {} \
}"

#endif /* RFC_GRAMMAR_SMTP_H */
