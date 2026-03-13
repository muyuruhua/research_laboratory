#!/bin/bash
# Analyze enrichment costs from experiment tar files
# Focus on benchmark/ directory (canonical location)

BASE="/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/benchmark"

echo "====================================================================="
echo "ENRICHMENT COST ANALYSIS - ALL EXPERIMENT TAR FILES"
echo "====================================================================="
echo ""

# Header
printf "%-60s | %6s | %6s | %6s | %10s | %10s | %10s\n" \
  "FILE" "ENRICH" "GRAMM" "STALL" "LLM_CALLS" "PROMPT_TK" "COMPL_TK"
printf "%-60s-+-%6s-+-%6s-+-%6s-+-%10s-+-%10s-+-%10s\n" \
  "------------------------------------------------------------" "------" "------" "------" "----------" "----------" "----------"

# Process all chatafl and chatafl_opt tar files  
find "$BASE" -name "out-*-chatafl*.tar.gz" -type f | sort | while read tarfile; do
    # Get relative path for display
    relpath="${tarfile#$BASE/}"
    
    # Get the tar prefix (e.g., out-exim-chatafl_opt)
    prefix=$(tar -tzf "$tarfile" 2>/dev/null | head -1 | sed 's|/$||')
    
    if [ -z "$prefix" ]; then
        echo "ERROR: Cannot read $relpath"
        continue
    fi
    
    # Count enriched files in queue/
    enriched=$(tar -tzf "$tarfile" 2>/dev/null | grep -c "queue/.*enriched")
    
    # Count llm-grammar-output files
    grammar=$(tar -tzf "$tarfile" 2>/dev/null | grep -c "protocol-grammars/llm-grammar-output")
    
    # Count stall prompt files (each prompt = 1 LLM call)
    stall=$(tar -tzf "$tarfile" 2>/dev/null | grep -c "stall-interactions/prompt-")
    
    # For _opt files, extract fuzzer_stats LLM metrics
    llm_calls="-"
    prompt_tk="-"
    compl_tk="-"
    
    if echo "$relpath" | grep -q "chatafl_opt\|chatafl_cl"; then
        stats=$(tar -xzf "$tarfile" --to-stdout "${prefix}/fuzzer_stats" 2>/dev/null)
        if [ -n "$stats" ]; then
            llm_calls=$(echo "$stats" | grep "llm_total_calls" | awk -F: '{gsub(/ /,"",$2); print $2}')
            prompt_tk=$(echo "$stats" | grep "llm_prompt_tokens" | awk -F: '{gsub(/ /,"",$2); print $2}')
            compl_tk=$(echo "$stats" | grep "llm_completion_tok" | awk -F: '{gsub(/ /,"",$2); print $2}')
            [ -z "$llm_calls" ] && llm_calls="-"
            [ -z "$prompt_tk" ] && prompt_tk="-"
            [ -z "$compl_tk" ] && compl_tk="-"
        fi
    fi
    
    printf "%-60s | %6s | %6s | %6s | %10s | %10s | %10s\n" \
      "$relpath" "$enriched" "$grammar" "$stall" "$llm_calls" "$prompt_tk" "$compl_tk"
done

echo ""
echo "====================================================================="
echo "LEGEND:"
echo "  ENRICH = enriched files in queue/ (enrichment LLM calls that succeeded)"
echo "  GRAMM  = llm-grammar-output-* files (grammar extraction calls)"
echo "  STALL  = prompt-* files in stall-interactions/ (stall LLM calls)"
echo "  LLM_CALLS/PROMPT_TK/COMPL_TK = from fuzzer_stats (Opt/CL only)"
echo "====================================================================="
