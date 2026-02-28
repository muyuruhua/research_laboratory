/* hypothesis-adapter.h
 * Adapter to integrate grammar hypotheses into AFL pattern structures
 */
#ifndef __HYPOTHESIS_ADAPTER_H
#define __HYPOTHESIS_ADAPTER_H

#include "grammar-hypothesis.h"
#include "klist.h"

// Integrate hypotheses into protocol_patterns and message_types_set.
// Returns number of hypotheses integrated.
int integrate_hypotheses_into_protocol_patterns(hypothesis_context_t *ctx,
                                                klist_t(rang) *protocol_patterns,
                                                khash_t(strSet) *message_types_set,
                                                const char *out_dir);

#endif
