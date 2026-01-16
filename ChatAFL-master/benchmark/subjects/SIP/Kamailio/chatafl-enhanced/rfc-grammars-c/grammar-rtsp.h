/* Auto-generated from RFC Grammar Converter */
/* Protocol: RTSP (RFC 2326) */
#ifndef RFC_GRAMMAR_RTSP_H
#define RFC_GRAMMAR_RTSP_H

#define RTSP_GRAMMAR_JSON \
"{ \
  \"protocol\": \"RTSP\", \
  \"rfc\": \"RFC 2326\", \
  \"format\": \"JSON-Template-with-Constraints\", \
  \"generated_method\": \"predefined\", \
  \"commands\": { \
    \"DESCRIBE\": { \
      \"template\": [ \
        \"DESCRIBE <<URL>> RTSP/1.0\\r\\nCSeq: <<CSEQ>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URL\": { \
          \"type\": \"rtsp_url\", \
          \"max_length\": 512 \
        }, \
        \"CSEQ\": { \
          \"type\": \"integer\", \
          \"min\": 1, \
          \"max\": 999999 \
        } \
      } \
    }, \
    \"SETUP\": { \
      \"template\": [ \
        \"SETUP <<URL>> RTSP/1.0\\r\\nCSeq: <<CSEQ>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URL\": { \
          \"type\": \"rtsp_url\", \
          \"max_length\": 512 \
        }, \
        \"CSEQ\": { \
          \"type\": \"integer\", \
          \"min\": 1, \
          \"max\": 999999 \
        } \
      } \
    }, \
    \"PLAY\": { \
      \"template\": [ \
        \"PLAY <<URL>> RTSP/1.0\\r\\nCSeq: <<CSEQ>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URL\": { \
          \"type\": \"rtsp_url\", \
          \"max_length\": 512 \
        }, \
        \"CSEQ\": { \
          \"type\": \"integer\", \
          \"min\": 1, \
          \"max\": 999999 \
        } \
      } \
    }, \
    \"PAUSE\": { \
      \"template\": [ \
        \"PAUSE <<URL>> RTSP/1.0\\r\\nCSeq: <<CSEQ>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URL\": { \
          \"type\": \"rtsp_url\", \
          \"max_length\": 512 \
        }, \
        \"CSEQ\": { \
          \"type\": \"integer\", \
          \"min\": 1, \
          \"max\": 999999 \
        } \
      } \
    }, \
    \"TEARDOWN\": { \
      \"template\": [ \
        \"TEARDOWN <<URL>> RTSP/1.0\\r\\nCSeq: <<CSEQ>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URL\": { \
          \"type\": \"rtsp_url\", \
          \"max_length\": 512 \
        }, \
        \"CSEQ\": { \
          \"type\": \"integer\", \
          \"min\": 1, \
          \"max\": 999999 \
        } \
      } \
    }, \
    \"OPTIONS\": { \
      \"template\": [ \
        \"OPTIONS <<URL>> RTSP/1.0\\r\\nCSeq: <<CSEQ>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URL\": { \
          \"type\": \"rtsp_url\", \
          \"max_length\": 512 \
        }, \
        \"CSEQ\": { \
          \"type\": \"integer\", \
          \"min\": 1, \
          \"max\": 999999 \
        } \
      } \
    }, \
    \"ANNOUNCE\": { \
      \"template\": [ \
        \"ANNOUNCE <<URL>> RTSP/1.0\\r\\nCSeq: <<CSEQ>>\\r\\n\\r\\n\" \
      ], \
      \"constraints\": { \
        \"URL\": { \
          \"type\": \"rtsp_url\", \
          \"max_length\": 512 \
        }, \
        \"CSEQ\": { \
          \"type\": \"integer\", \
          \"min\": 1, \
          \"max\": 999999 \
        } \
      } \
    } \
  }, \
  \"responses\": [ \
    \"200\", \
    \"404\", \
    \"454\", \
    \"455\", \
    \"456\", \
    \"457\", \
    \"458\", \
    \"459\" \
  ], \
  \"state_machine\": { \
    \"INIT\": [ \
      \"DESCRIBE\", \
      \"OPTIONS\" \
    ], \
    \"DESCRIBED\": [ \
      \"SETUP\" \
    ], \
    \"READY\": [ \
      \"PLAY\", \
      \"SETUP\", \
      \"TEARDOWN\" \
    ], \
    \"PLAYING\": [ \
      \"PAUSE\", \
      \"TEARDOWN\" \
    ], \
    \"PAUSED\": [ \
      \"PLAY\", \
      \"TEARDOWN\" \
    ] \
  }, \
  \"constraints\": {} \
}"

#endif /* RFC_GRAMMAR_RTSP_H */
