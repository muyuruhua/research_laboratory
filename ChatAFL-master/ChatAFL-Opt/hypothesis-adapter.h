/* hypothesis-adapter.h
 * Adapter to integrate grammar hypotheses into AFL pattern structures
 */
#ifndef __HYPOTHESIS_ADAPTER_H
#define __HYPOTHESIS_ADAPTER_H

#include "grammar-hypothesis.h"
#include "klist.h"

// Integrate hypotheses into protocol_patterns and message_types_set.
// For MQTT (binary protocol), creates binary header-byte patterns.
// For text protocols (SIP, FTP, etc.), creates text regex patterns.
// Returns number of hypotheses integrated.
int integrate_hypotheses_into_protocol_patterns(hypothesis_context_t *ctx,
                                                klist_t(rang) *protocol_patterns,
                                                khash_t(strSet) *message_types_set,
                                                const char *out_dir,
                                                const char *protocol_name);

// Map MQTT type nibble (upper 4 bits of first byte) to message type name.
// Returns NULL if the nibble is not a known MQTT type.
const char *mqtt_type_nibble_to_name(unsigned char nibble);

// Returns 1 if the given protocol is binary-framed (e.g. MQTT, DNS).
int is_binary_protocol(const char *protocol_name);

#endif
