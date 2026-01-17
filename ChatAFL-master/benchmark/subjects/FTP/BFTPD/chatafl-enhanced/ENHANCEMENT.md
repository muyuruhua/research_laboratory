# ChatAFL-Enhanced: Verified Loop Architecture

## Overview

ChatAFL-Enhanced upgrades the original ChatAFL by introducing a **verification & refinement loop** that addresses three critical limitations:

1. **Hallucination**: LLM produces invalid or inconsistent message grammars
2. **Unreproducibility**: No mechanism to validate or refine generated messages
3. **Uncontrollability**: No feedback mechanism when LLM's hypothesis fails

## Architecture

### Three Core Innovations

```
┌─────────────────────────────────────────────────────────────┐
│                     ChatAFL-Enhanced Loop                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Phase 1: HYPOTHESIS (LLM Generation)                        │
│  ──────────────────────────────────────────────────────────  │
│  Input: RFC snippets / captured packets / error responses    │
│  Output: {                                                    │
│    grammar: JSON Schema / ABNF / CFG,                       │
│    constraints: {length, enum, dependencies, state_deps},   │
│    templates: [message_template_1, ...]                     │
│  }                                                            │
│                                                               │
│  Phase 2: VERIFICATION (Verifier v0)                         │
│  ──────────────────────────────────────────────────────────  │
│  Check 1: Parseability                                       │
│    → Generated message ✓ parseable by local grammar parser   │
│    → Fallback: string-based validator                       │
│                                                               │
│  Check 2: Acceptability                                      │
│    → Send message to SUT (Server Under Test)                │
│    → If response ∈ {200, 201, ...} (non-rejection)          │
│      → ACCEPT & increment coverage counter                  │
│    → If response ∈ {400, 500, ...} (rejection/error)        │
│      → COLLECT as counterexample → Phase 3                  │
│                                                               │
│  Check 3: State Reachability                                 │
│    → Does message sequence reach new state node? (STT)      │
│    → State ~ hash(response_code + key_headers + coverage)   │
│    → If NEW state discovered → coverage gain                │
│                                                               │
│  Check 4: Coverage Gain                                      │
│    → Collect all three metrics above                         │
│    → If (parseability ∧ acceptability ∧ new_state):          │
│        → ADD to corpus grammar library (verifiedGrammars)   │
│    → Else → Phase 3 (Counterexample Refinement)             │
│                                                               │
│  Phase 3: COUNTEREXAMPLE-GUIDED REFINEMENT (CEGAR)           │
│  ──────────────────────────────────────────────────────────  │
│  Input: {                                                     │
│    failed_request,    # minimal failed message               │
│    server_response,   # error code / response                │
│    field_diff,        # which field caused failure           │
│    coverage_delta,    # did coverage improve?                │
│  }                                                            │
│                                                               │
│  Prompt Design: "Only patch field X or production rule Y"   │
│    → Limit LLM's freedom (avoid hallucination)              │
│    → Example: "change Content-Length only" / "fix separator" │
│                                                               │
│  Verify again → if success: reinsert loop                    │
│              → if failure: delta-debug or discard             │
│                                                               │
│  Phase 4: STATE-AWARE SCHEDULING (STT Feedback)              │
│  ──────────────────────────────────────────────────────────  │
│  Track: State Transition Tree (STT)                          │
│    state_node = hash(response_sequence)                      │
│    transition = (state_A, message_type) → state_B            │
│    coverage(state_B)                                          │
│                                                               │
│  Scheduling Policy:                                          │
│    → Prioritize messages reaching low-coverage states        │
│    → When plateau: ask LLM "how to reach state X?"          │
│    → Focus on rare transitions (state_B with few inbound)   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow & Integration Points

```
ChatAFL original flow:
  RFC → LLM grammar extraction → Mutate corpus → Fuzz SUT → Plateau → LLM plateau breaking

ChatAFL-Enhanced flow:
  RFC → LLM hypothesis (grammar)
    ↓
  [Verifier v0] → {parseable? acceptible? state_new? coverage_gain?}
    ├─ YES (all checks pass) → Add to verifiedGrammar library
    │                          → [State-aware Scheduler]
    │                               → Prioritize by state rarity
    │                               → Continue fuzzing
    │
    └─ NO (≥1 check fails) → Minimal counterexample
                              ↓
                        [CEGAR Refinement]
                        ↓ LLM: "only fix field X"
                        ↓
                        [Re-verify] → loop back
```

## Module Responsibilities

### 1. verifier.c / verifier.h

**Responsibility**: Validate LLM-generated grammars and messages

**Functions**:
```c
// Check if generated message matches grammar
int verify_parseability(
    const unsigned char *message, 
    size_t msg_len,
    const grammar_t *grammar,
    parsed_fields_t **fields_out
);

// Send message to SUT and classify response
int verify_acceptability(
    const char *host, int port,
    const unsigned char *request,
    size_t req_len,
    response_t *response_out  // stores {code, headers, body}
);

// Check if message sequence reaches new state
int verify_state_reachability(
    const unsigned int *state_sequence,
    int state_count,
    state_transition_tree_t *stt,
    int *is_new_state_out
);

// Calculate coverage gain from message
int calculate_coverage_gain(
    const state_transition_tree_t *stt,
    const response_t *response,
    float *coverage_gain_out
);

// Minimal counterexample via delta-debugging
unsigned char *minimize_counterexample(
    const unsigned char *message,
    size_t msg_len,
    const grammar_t *grammar
);
```

### 2. cegar-refinement.c / cegar-refinement.h

**Responsibility**: Refine failed grammars via counterexample feedback

**Functions**:
```c
// Build CEGAR prompt: only patch specific field
char *construct_cegar_prompt(
    const char *protocol_name,
    const failed_message_t *counterexample,
    const parsed_fields_t *fields,
    const int field_to_fix,  // constrain LLM's freedom
    char *prev_grammar
);

// Parse LLM's patch response
int parse_cegar_patch(
    const char *llm_response,
    json_object **patched_grammar_out
);

// Verify patch → if success, reinsert; if fail, try next field
int apply_and_verify_patch(
    const patched_grammar_t *patch,
    const unsigned char *original_message,
    verifier_context_t *vctx
);

// Cache CEGAR patches to avoid re-generation (reproducibility)
int cache_cegar_result(
    const char *cache_key,  // hash(counterexample)
    const patched_grammar_t *patch
);
```

### 3. state-scheduler.c / state-scheduler.h

**Responsibility**: Schedule fuzzing based on state transition graph (Stateful Greybox Fuzzing ideas)

**Functions**:
```c
// Build/update State Transition Tree
void update_state_transition_tree(
    state_transition_tree_t *stt,
    const unsigned int *state_sequence,
    int state_count,
    const struct queue_entry *seed
);

// Compute state rarity (inverse of visitation count)
float compute_state_rarity(
    const state_transition_tree_t *stt,
    unsigned int state_id
);

// Schedule next seed: prioritize rare states & transitions
struct queue_entry *schedule_next_seed_stt(
    state_transition_tree_t *stt,
    struct queue_entry *head,
    float rarity_weight  // balance with coverage
);

// When plateau detected: ask LLM for path to state X
char *construct_state_path_prompt(
    const char *protocol_name,
    unsigned int target_state_id,
    const verified_grammars_t *verified,
    const state_transition_tree_t *stt
);
```

## Expected Improvements Over ChatAFL

| Metric | ChatAFL | ChatAFL-Enhanced | Notes |
|--------|---------|------------------|-------|
| **Reliability** | ~60% messages fail parsing | >95% parseability | Verifier guards grammar quality |
| **Reproducibility** | No mechanism | Full trace logged | CEGAR + cache enables replay |
| **State Coverage** | Coverage-only feedback | Coverage + STT | State rarity guides search |
| **Plateau Breaking** | Random LLM calls | Targeted hypothesis | STT-aware LLM prompts |
| **Hallucination Control** | Unbounded LLM freedom | Constrained patches | Field-level CEGAR |

## Implementation Phases

### Phase 2.1: Verifier v0 (Week 1-2)
- [ ] Implement parseability check (CFG/regex-based)
- [ ] Implement acceptability check (HTTP status codes, error patterns)
- [ ] State tracking via response codes + key headers
- [ ] Coverage gain calculation (simple: new state = new response code)

### Phase 2.2: CEGAR Loop (Week 2-3)
- [ ] Delta-debugging for counterexample minimization
- [ ] Prompt engineering for field-level patches
- [ ] LLM response parsing + verification
- [ ] Patch caching for reproducibility

### Phase 2.3: State-aware Scheduling (Week 3-4)
- [ ] STT (State Transition Tree) data structure
- [ ] State rarity computation
- [ ] Integrate with afl-fuzz scheduler
- [ ] Test on FTP / MQTT targets

### Phase 2.4: Experimental Validation (Week 4-6)
- [ ] Reproduce ChatAFL baseline on 2 protocols
- [ ] Compare against AFLNet, ChatAFL, ChatAFL-Enhanced
- [ ] Measure: crash-time, coverage, state count, reproducibility

---

## Key Design Decisions

### 1. State Representation (Simple vs. Rich)

**Chosen: Hash-based approximation**
```c
state_id = hash(
    response_codes_sequence[0..k] +  // last k response codes
    coverage_bitmap[0..N] % 256      // coverage hash
)
```
Rationale: Avoid formal state inference (expensive), use pragmatic signal

### 2. Verifier Checkpoints (Where to verify?)

**Chosen: Three-stage filtering**
1. Grammar → message: parseability (pre-send)
2. Send to SUT: acceptability (on-network)
3. State machine: reachability (post-response)

Rationale: Fail-fast at each stage; minimal replay overhead

### 3. CEGAR Scope (How much freedom for LLM?)

**Chosen: Field-level patches only**
- Instead of "regenerate whole message" → "fix Content-Length field only"
- Limits hallucination; improves convergence

### 4. Scheduling Integration

**Chosen: Soft prioritization (not hard replacement)**
- STT rarity influences seed selection weight
- Coverage still matters (balance: 70% rarity + 30% coverage)
- Avoids getting stuck in low-coverage rare states

---

## Evaluation Metrics (USENIX'22 Stateful Greybox Fuzzing)

### Coverage & Effectiveness
- **Code Coverage** (traditional): LCOV or AFL coverage bitmap
- **State Coverage**: Number of distinct state nodes reached
- **Transition Coverage**: Number of distinct (state, message_type) → state' transitions
- **Crash Metrics**: Time-to-first-crash, crash count, unique crashes

### Reproducibility & Reliability
- **Parseability Rate**: % of LLM-generated messages that parse successfully
- **Acceptability Rate**: % of valid messages accepted by SUT (non-error responses)
- **State Reachability**: % of claimed state transitions that actually occur
- **CEGAR Convergence**: # of iterations to fix a grammar error

### Efficiency & Scalability
- **Overhead**: CEGAR time / total fuzzing time
- **Cost Control**: Cache hit rate (avoid re-generating same patches)
- **State Explosion**: Max # of states tracked in STT

---

## References

1. **ChatAFL**: [Large Language Model guided Protocol Fuzzing](...)
2. **Stateful Greybox Fuzzing**: USENIX'22 (state rarity, STT, transitions)
3. **AFLNet**: ICST'20 (response code-based state abstraction)
4. **CEGAR**: Classical software model-checking pattern (counterexample-guided abstraction refinement)
5. **Delta-Debugging**: Simplifying failure-inducing input (Zeller et al.)
