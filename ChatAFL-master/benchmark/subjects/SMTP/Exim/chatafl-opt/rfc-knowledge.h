/*
 * ChatAFL-Opt: RFC Knowledge Configuration
 * ========================================
 * 
 * Protocol RFC mappings and structured knowledge extraction.
 * Follows Open-Closed Principle: Extend protocol support via configuration,
 * not by modifying core fuzzing logic.
 * 
 * Usage:
 *   1. get_rfc_url_for_protocol("FTP") → "https://www.rfc-editor.org/rfc/rfc959.txt"
 *   2. fetch_rfc_text("https://...") → full RFC text content
 *   3. extract_rfc_keywords(text, "FTP") → ["USER", "PASS", "STOR", ...]
 */

#ifndef __RFC_KNOWLEDGE_H
#define __RFC_KNOWLEDGE_H

#include <stddef.h>

/* ============================================
 * RFC Configuration Structure
 * ============================================ */

typedef struct rfc_info {
    const char *protocol_name;    // e.g., "FTP", "SMTP", "HTTP"
    const char *rfc_number;       // e.g., "RFC 959", "RFC 5321"
    const char *rfc_url;          // Full URL to RFC text
    const char *description;      // Brief description
    int has_ietf_spec;            // 1 if IETF standard, 0 otherwise
} rfc_info_t;

/* ============================================
 * RFC Database (Compile-time Configuration)
 * ============================================ */

// Global RFC mapping table
static const rfc_info_t RFC_DATABASE[] = {
    {
        .protocol_name = "FTP",
        .rfc_number = "RFC 959",
        .rfc_url = "https://www.rfc-editor.org/rfc/rfc959.txt",
        .description = "File Transfer Protocol",
        .has_ietf_spec = 1
    },
    {
        .protocol_name = "SMTP",
        .rfc_number = "RFC 5321",
        .rfc_url = "https://www.rfc-editor.org/rfc/rfc5321.txt",
        .description = "Simple Mail Transfer Protocol",
        .has_ietf_spec = 1
    },
    {
        .protocol_name = "RTSP",
        .rfc_number = "RFC 7826",
        .rfc_url = "https://www.rfc-editor.org/rfc/rfc7826.txt",
        .description = "Real-Time Streaming Protocol 2.0",
        .has_ietf_spec = 1
    },
    {
        .protocol_name = "SIP",
        .rfc_number = "RFC 3261",
        .rfc_url = "https://www.rfc-editor.org/rfc/rfc3261.txt",
        .description = "Session Initiation Protocol",
        .has_ietf_spec = 1
    },
    {
        .protocol_name = "DAAP",
        .rfc_number = "N/A",
        .rfc_url = "https://en.wikipedia.org/wiki/Digital_Audio_Access_Protocol",
        .description = "Digital Audio Access Protocol (Proprietary)",
        .has_ietf_spec = 0
    },
    {
        .protocol_name = "HTTP",
        .rfc_number = "RFC 9112",
        .rfc_url = "https://www.rfc-editor.org/rfc/rfc9112.txt",
        .description = "HTTP/1.1 Message Syntax and Routing",
        .has_ietf_spec = 1
    },
    {
        .protocol_name = "MQTT",
        .rfc_number = "OASIS mqtt-v3.1.1",
        .rfc_url = "https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html",
        .description = "MQTT Version 3.1.1 (OASIS Standard, not IETF RFC)",
        .has_ietf_spec = 0
    },
    {
        .protocol_name = "DNS",
        .rfc_number = "RFC 1035",
        .rfc_url = "https://www.rfc-editor.org/rfc/rfc1035.txt",
        .description = "Domain Name System - Implementation and Specification",
        .has_ietf_spec = 1
    },
    {
        .protocol_name = "DTLS12",
        .rfc_number = "RFC 6347",
        .rfc_url = "https://www.rfc-editor.org/rfc/rfc6347.txt",
        .description = "Datagram Transport Layer Security Version 1.2",
        .has_ietf_spec = 1
    },
    {
        .protocol_name = "TLS",
        .rfc_number = "RFC 8446",
        .rfc_url = "https://www.rfc-editor.org/rfc/rfc8446.txt",
        .description = "The Transport Layer Security (TLS) Protocol Version 1.3",
        .has_ietf_spec = 1
    },
    {
        .protocol_name = "SSH",
        .rfc_number = "RFC 4253",
        .rfc_url = "https://www.rfc-editor.org/rfc/rfc4253.txt",
        .description = "The Secure Shell (SSH) Transport Layer Protocol",
        .has_ietf_spec = 1
    },
    {
        .protocol_name = "DICOM",
        .rfc_number = "N/A",
        .rfc_url = "https://www.dicomstandard.org/current",
        .description = "Digital Imaging and Communications in Medicine",
        .has_ietf_spec = 0
    },
    // Terminator
    { .protocol_name = NULL }
};

#define RFC_DATABASE_SIZE (sizeof(RFC_DATABASE) / sizeof(rfc_info_t) - 1)

/* ============================================
 * RFC Caching Configuration
 * ============================================ */

// Cache RFC texts to avoid repeated downloads
#define RFC_CACHE_DIR "/tmp/chatafl-rfc-cache"
#define RFC_CACHE_ENABLED 1
#define RFC_FETCH_TIMEOUT 60      // seconds
#define RFC_MAX_SIZE (5 * 1024 * 1024)  // 5MB max

/* ============================================
 * RFC Knowledge Extraction Parameters
 * ============================================ */

// Protocol command/state extraction patterns
#define RFC_COMMAND_PATTERN_FTP   "^[A-Z]{3,4}\\b"  // USER, PASS, STOR, etc.
#define RFC_COMMAND_PATTERN_SMTP  "^[A-Z]{4}\\b"    // HELO, MAIL, RCPT, etc.
#define RFC_COMMAND_PATTERN_RTSP  "^[A-Z_]+:"       // DESCRIBE:, SETUP:, etc.
#define RFC_COMMAND_PATTERN_SIP   "^[A-Z]+\\s+sip:" // INVITE sip:, etc.
#define RFC_COMMAND_PATTERN_HTTP  "^[A-Z]+\\s+/"    // GET /, POST /, etc.
/* MQTT spec is OASIS HTML; after HTML->text stripping we extract canonical
 * control packet names globally (not line-anchored). */
#define RFC_COMMAND_PATTERN_MQTT  "\\b(CONNECT|CONNACK|PUBLISH|PUBACK|PUBREC|PUBREL|PUBCOMP|SUBSCRIBE|SUBACK|UNSUBSCRIBE|UNSUBACK|PINGREQ|PINGRESP|DISCONNECT|AUTH)\\b"

// Response code extraction patterns
#define RFC_RESPONSE_PATTERN_FTP  "\\b[1-5][0-9]{2}\\b"  // 220, 331, 530, etc.
#define RFC_RESPONSE_PATTERN_SMTP "\\b[2-5][0-9]{2}\\b"  // 220, 354, 550, etc.
#define RFC_RESPONSE_PATTERN_RTSP "\\b[1-5][0-9]{2}\\b"  // 200, 404, 461, etc.
#define RFC_RESPONSE_PATTERN_SIP  "\\b[1-6][0-9]{2}\\b"  // 100, 200, 407, etc.
#define RFC_RESPONSE_PATTERN_HTTP "\\b[1-5][0-9]{2}\\b"  // 200, 404, 500, etc.

/* ============================================
 * Public API Functions
 * ============================================ */

// Get RFC info for a protocol
const rfc_info_t* get_rfc_info_for_protocol(const char *protocol_name);

// Get RFC URL (convenience wrapper)
const char* get_rfc_url_for_protocol(const char *protocol_name);

// Fetch RFC text from URL (with caching)
char* fetch_rfc_text(const char *protocol_name);

// Extract structured knowledge from RFC text
char** extract_rfc_commands(const char *rfc_text, const char *protocol_name, size_t *count);
char** extract_rfc_response_codes(const char *rfc_text, const char *protocol_name, size_t *count);
char* extract_rfc_state_machine(const char *rfc_text, const char *protocol_name);

// Enhanced prompt construction with RFC knowledge
char* construct_prompt_with_rfc(
    const char *protocol_name,
    const char *prompt_template,
    int include_commands,
    int include_responses,
    int include_state_machine
);

// Cleanup
void cleanup_rfc_cache(void);

#endif // __RFC_KNOWLEDGE_H

// (Header end)

