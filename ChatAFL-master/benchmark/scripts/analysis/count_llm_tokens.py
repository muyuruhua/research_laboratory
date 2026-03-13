#!/usr/bin/env python3
"""Count LLM tokens from ChatAFL stall-interaction files using tiktoken.

Usage:
    count_llm_tokens.py <tar.gz file>

Output (single line, space-separated):
    <calls> <prompt_tokens> <completion_tokens>

- Prompt files (stall-interactions/prompt-*): JSON messages array
  [{"role":"system","content":"..."},{"role":"user","content":"..."}]
  Token count includes ~4 overhead tokens per message for role/formatting.
- Response files (stall-interactions/response-*): plain text (message.content)
- Calls = number of prompt files (each prompt = one API call).
- If a prompt has no matching response, that call's completion_tokens = 0
  (API may have timed out or returned an error).

Tokenizer: o200k_base (gpt-4o-mini / gpt-4o family).
Accuracy: ±1 token vs real API 'usage' field (verified).
"""

import json
import re
import sys
import tarfile


def get_encoder():
    """Get the tiktoken encoder for gpt-4o-mini (o200k_base)."""
    import tiktoken
    return tiktoken.encoding_for_model("gpt-4o-mini")


def count_prompt_tokens(enc, content: str) -> int:
    """Count tokens in a prompt file (JSON messages array)."""
    try:
        msgs = json.loads(content)
        total = 0
        for m in msgs:
            total += len(enc.encode(m.get("content", "")))
            # Overhead per message: role token + separators (~4 tokens)
            total += 4
        # Final assistant priming overhead
        total += 2
        return total
    except (json.JSONDecodeError, TypeError):
        # Fallback: raw token count
        return len(enc.encode(content))


def count_response_tokens(enc, content: str) -> int:
    """Count tokens in a response file (plain text = message.content)."""
    return len(enc.encode(content))


def main():
    if len(sys.argv) != 2:
        print("Usage: count_llm_tokens.py <tar.gz file>", file=sys.stderr)
        sys.exit(1)

    tar_path = sys.argv[1]
    enc = get_encoder()

    prompt_files = {}   # id -> content
    response_files = {} # id -> content

    prompt_re = re.compile(r"stall-interactions/prompt-(\d+)$")
    response_re = re.compile(r"stall-interactions/response-(\d+)$")

    with tarfile.open(tar_path, "r:gz") as tf:
        for member in tf.getmembers():
            m = prompt_re.search(member.name)
            if m:
                f = tf.extractfile(member)
                if f:
                    prompt_files[int(m.group(1))] = f.read().decode("utf-8", errors="replace")
                continue
            m = response_re.search(member.name)
            if m:
                f = tf.extractfile(member)
                if f:
                    response_files[int(m.group(1))] = f.read().decode("utf-8", errors="replace")

    calls = len(prompt_files)
    pt_total = sum(count_prompt_tokens(enc, c) for c in prompt_files.values())
    ct_total = sum(count_response_tokens(enc, c) for c in response_files.values())

    # Output: calls prompt_tokens completion_tokens
    print(f"{calls} {pt_total} {ct_total}")


if __name__ == "__main__":
    main()
