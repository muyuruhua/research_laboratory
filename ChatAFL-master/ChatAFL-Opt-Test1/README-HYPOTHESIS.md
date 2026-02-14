# ChatAFL-Opt: Hypothesis-Driven Grammar Learning for Protocol Fuzzing

## Overview

ChatAFL-Opt extends ChatAFL with a **hypothesis-validation-refinement closed loop** to address the key limitations of LLM-guided fuzzing:

1. **Hallucination** - LLMs generate plausible but incorrect grammars
2. **Non-reproducibility** - No systematic tracking of what works
3. **Lack of measurability** - No quantitative fitness metrics

## Architecture

### Core Components

#### 1. Grammar Hypothesis Generation (`grammar-hypothesis.h/c`)

**Data Structures:**
- `grammar_hypothesis_t`: Structured representation of message grammar
  - JSON Schema for field definitions
  - Constraint types: length, enum, regex, dependency, numeric
  - Validation metrics: parse success/failure, fitness score
  - Counterexample storage for refinement

**Key Features:**
- **Structured Output**: LLM generates JSON Schema + ABNF-like rules
- **Multiple Hypothesis**: Maintains multiple competing hypotheses per message type
- **Fitness Tracking**: `fitness = 0.7 * parse_rate + 0.3 * constraint_confidence`

#### 2. Runtime Validation Loop

**Integrated into `afl-fuzz.c`:**

```c
// In common_fuzz_stuff():
validate_and_refine_hypotheses(out_buf, len)
  ├─> Validate message against all hypotheses
  ├─> Update parse_success/parse_failure counters
  ├─> Update constraint violation rates
  ├─> Add counterexamples for failed validations
  └─> Periodically refine low-fitness hypotheses
```

**Validation Metrics:**
- Parse success rate
- Per-field constraint violation rates
- Confidence scores (1 - violation_rate)
- Overall hypothesis fitness

#### 3. Counterexample-Driven Refinement

**Refinement Trigger:**
- Fitness < 0.7 (threshold)
- ≥3 counterexamples accumulated
- Periodic check every 100 validations

**Refinement Process:**
```
Counterexamples → LLM Refinement Prompt → Updated Grammar → Clear Counterexamples
```

**Prompt Structure:**
```json
{
  "current_hypothesis": {
    "message_type": "USER",
    "schema": {...},
    "constraints": [...]
  },
  "counterexamples": [
    "USER \x00invalid [Reason: Length constraint violated]",
    "USER <script>tag</script> [Reason: Enum mismatch]"
  ],
  "task": "Revise grammar to accommodate these counterexamples"
}
```

### Design Principles

#### Open-Closed Principle Compliance

**Extension without Modification:**
- New module `grammar-hypothesis.c` (800+ lines)
- Minimal changes to `afl-fuzz.c`:
  - 1 include statement
  - 4 global variables
  - 2 function calls in main loop
  - Environment variable toggle (`CHATAFL_HYPOTHESIS`)

**Backward Compatibility:**
- Disabled by default
- No impact on existing ChatAFL functionality
- Can run standard ChatAFL with `CHATAFL_HYPOTHESIS=0`

## Usage

### 1. Build

```bash
cd ChatAFL-Opt
make clean && make
```

### 2. Enable Hypothesis Mode

```bash
export CHATAFL_HYPOTHESIS=1
export KEY="your-openai-api-key"
```

### 3. Run Fuzzing

```bash
./afl-fuzz -d -i seeds/ -o output/ -N tcp://127.0.0.1/21 \
  -P FTP -D 10000 -q 3 -s 3 -E -K -R \
  ./target @@
```

### 4. Monitor Hypotheses

```bash
# Hypothesis files are saved in:
output/grammar-hypotheses/
├── hypothesis-1234567890-USER.json
├── hypothesis-1234567891-PASS.json
└── hypothesis-1234567890-USER-refined-1234567900.json
```

### 5. Validation in Benchmark

```bash
cd ..
sudo -E ./run.sh 1 15 lightftp chatafl-opt
```

## Hypothesis JSON Schema Format

### Example: FTP USER Command

```json
{
  "hypothesis_id": 1702345678000,
  "message_type": "USER",
  "description": "FTP USER command for authentication",
  "schema": {
    "type": "object",
    "properties": {
      "command": {
        "type": "string",
        "enum": ["USER"],
        "description": "Command identifier"
      },
      "username": {
        "type": "string",
        "minLength": 1,
        "maxLength": 64,
        "pattern": "^[a-zA-Z0-9_-]+$",
        "description": "Username for authentication"
      },
      "terminator": {
        "type": "string",
        "enum": ["\\r\\n"],
        "description": "Line terminator"
      }
    },
    "required": ["command", "username", "terminator"]
  },
  "constraints": [
    {
      "field": "username",
      "type": "length",
      "min": 1,
      "max": 64
    },
    {
      "field": "username",
      "type": "regex",
      "pattern": "^[a-zA-Z0-9_-]+$"
    },
    {
      "field": "command",
      "type": "enum",
      "values": ["USER"]
    }
  ],
  "production_rules": [
    "USER <SP> <username> <CRLF>",
    "<username> ::= 1*64(<alphanum> | '_' | '-')"
  ],
  "fitness": 0.85,
  "parse_success": 127,
  "parse_failure": 23,
  "created_at": 1702345678,
  "last_updated": 1702345890
}
```

## Key Improvements Over ChatAFL

### 1. **Reproducibility**
- All hypotheses saved to disk with timestamps
- Refinement history tracked
- Can replay/analyze hypothesis evolution

### 2. **Measurability**
- Quantitative fitness scores
- Per-constraint violation rates
- Validation success rates
- Refinement iteration counts

### 3. **Falsifiability**
- Counterexamples explicitly stored
- Failed validations trigger refinement
- LLM can be proven wrong and corrected

### 4. **Transparency**
- JSON Schema is human-readable
- Constraint definitions are explicit
- Validation logic is deterministic

### 5. **Debugging Support**
```bash
# View hypothesis fitness over time
grep "fitness" output/grammar-hypotheses/*.json

# Count refinement iterations
ls output/grammar-hypotheses/*-refined-*.json | wc -l

# Analyze counterexamples
jq '.counterexamples' output/grammar-hypotheses/hypothesis-*.json
```

## Evaluation Metrics

### Hypothesis Quality
- **Fitness Score**: Parse success rate × constraint confidence
- **Refinement Count**: Number of LLM refinement iterations
- **Convergence Rate**: Time to reach fitness > 0.7

### Fuzzing Effectiveness
- **Code Coverage**: Standard AFL bitmap coverage
- **State Coverage**: Number of unique server states reached
- **Bug Detection**: Crashes/hangs found

### Comparison with ChatAFL
- **Reproducibility**: Hypothesis files enable exact reproduction
- **Cost Efficiency**: Fewer LLM calls due to validation filtering
- **Debugging**: Explicit counterexamples vs. opaque LLM outputs

## Future Work (Not in Phase 1)

1. **Hypothesis-Guided Mutation**: Use high-fitness hypotheses to guide mutation operators
2. **Multi-LLM Ensemble**: Compare hypotheses from different models
3. **Active Learning**: Strategically query LLM based on validation gaps
4. **Symbolic Execution Integration**: Use SMT solvers to validate constraints

## Technical Details

### Constraint Validation

```c
int check_constraint(field_constraint_t *c, const char *value, size_t len) {
    switch (c->type) {
        case CONSTRAINT_LENGTH:
            return len >= c->data.length.min && len <= c->data.length.max;
        
        case CONSTRAINT_ENUM:
            for (size_t i = 0; i < c->data.enumeration.count; i++)
                if (strncmp(value, c->data.enumeration.values[i], len) == 0)
                    return 1;
            return 0;
        
        case CONSTRAINT_REGEX:
            return pcre2_match(c->data.regex.compiled, value, len, ...) >= 0;
        
        case CONSTRAINT_NUMERIC:
            long long num = strtoll(value, NULL, 10);
            return num >= c->data.numeric.min && num <= c->data.numeric.max;
    }
}
```

### Fitness Calculation

```c
double calculate_hypothesis_fitness(grammar_hypothesis_t *hyp) {
    double parse_rate = (double)hyp->parse_success / 
                       (hyp->parse_success + hyp->parse_failure);
    
    double avg_confidence = 0.0;
    for (size_t i = 0; i < hyp->constraint_count; i++) {
        avg_confidence += hyp->constraints[i]->confidence;
    }
    avg_confidence /= hyp->constraint_count;
    
    return 0.7 * parse_rate + 0.3 * avg_confidence;
}
```

## Implementation Notes

### Environment Variables
- `CHATAFL_HYPOTHESIS=1`: Enable hypothesis mode
- `KEY`: OpenAI API key
- `HYPOTHESIS_REFINEMENT_INTERVAL`: Check interval (default: 100)

### File Structure
```
output/
├── queue/                     # Standard AFL queue
├── crashes/                   # Crashes
├── grammar-hypotheses/        # NEW: Hypothesis storage
│   ├── hypothesis-*.json      # Initial hypotheses
│   └── hypothesis-*-refined-*.json  # Refined versions
└── protocol-grammars/         # ChatAFL grammar patterns
```

### Performance Considerations
- **LLM Calls**: ~5 initial + ~1 per 100 validations (refinement)
- **Memory**: ~1KB per hypothesis, negligible overhead
- **CPU**: Validation adds ~5% overhead (mostly JSON parsing)

## Citation

If you use ChatAFL-Opt in research, please cite:

```bibtex
@inproceedings{chatafl-opt2026,
  title={ChatAFL-Opt: Hypothesis-Driven Grammar Learning for Protocol Fuzzing},
  author={Research Laboratory},
  booktitle={To be submitted},
  year={2026}
}
```

## License

Same as ChatAFL (Apache 2.0)
