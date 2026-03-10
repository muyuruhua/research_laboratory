#!/bin/bash

# Generate the state and coverage graphs

FILTER=$1
TIME=${2:-1440}
EXPLICIT_DIR=${3:-""}   # Optional: explicit results directory name

reset="\e[0m"
green="\e[0;92m"
yellow="\e[0;33m"
function warn  { echo -e "${yellow}[!] $1$reset"; }
function info  { echo -e "${green}[+]$reset $1"; }

if [ -z "$FILTER" ]; then
    echo "Usage: analyze.sh <subject names> <time in minutes> [results-dir]"
    echo "  results-dir: optional, e.g. results-exim_Mar-06_22-09-54"
    exit 1
fi

PFBENCH="$PWD/benchmark"

# OCP Extension: Pre-flight permission check
if [ ! -w "$PFBENCH" ]; then
    warn "No write permission in $PFBENCH directory"
    warn "Please run with sudo or fix directory permissions:"
    warn "  sudo chown -R \$USER:$USER $PFBENCH"
    warn "  Or run: sudo ./analyze.sh $FILTER $TIME"
    exit 1
fi

cd $PFBENCH

for SUBJECT in $(echo $FILTER | tr "," "\n");
do
    echo "Analyzing $SUBJECT"
    
    # OCP: Find timestamped results directory matching pattern results-${SUBJECT}_*
    # This supports both old format (results-lightftp) and new format (results-lightftp_Feb-02_12-34-56)
    # Also supports explicit directory via 3rd argument
    if [ -n "$EXPLICIT_DIR" ]; then
        RESULTS_DIR="$EXPLICIT_DIR"
        info "Using explicitly specified directory: $RESULTS_DIR"
    else
        RESULTS_DIR=$(find . -maxdepth 1 -type d -name "results-${SUBJECT}_*" | sort -r | head -n 1)
    fi
    
    # Fallback to old naming convention if no timestamped directory found
    if [ -z "$RESULTS_DIR" ]; then
        RESULTS_DIR="results-${SUBJECT}"
    fi
    
    # Remove leading './' from find output
    RESULTS_DIR=${RESULTS_DIR#./}
    
    # Check if results exists
    if [ ! -d "$RESULTS_DIR" ] || [ -z "$(ls -A $RESULTS_DIR)" ]; then
        warn "No results for subject $SUBJECT (checked $RESULTS_DIR)."
        warn "Please check whether the fuzzing has completed via the following command:"
        warn "  docker ps -a | grep $SUBJECT"
        docker ps -a | grep $SUBJECT
        warn ""
        warn "If the containers' status is 'Up ..', please wait for the fuzzing to complete."
        warn "Once the fuzzing complete, the containers' status will change to 'Exited ..'"
        continue
    fi
    
    # OCP Extension: Check write permission in results directory before analysis
    if [ ! -w "$RESULTS_DIR" ]; then
        warn "No write permission in $RESULTS_DIR"
        warn "Attempting to fix permissions..."
        sudo chown -R $USER:$(id -gn) "$RESULTS_DIR" 2>/dev/null || {
            warn "Failed to fix permissions. Please run:"
            warn "  sudo chown -R \$USER:\$USER $RESULTS_DIR"
            continue
        }
        info "Permissions fixed successfully"
    fi
    
    # OCP Extension: Validate results directory contains actual fuzzing data
    TAR_COUNT=$(find "$RESULTS_DIR" -maxdepth 1 -name "*.tar.gz" 2>/dev/null | wc -l)
    if [ "$TAR_COUNT" -eq 0 ]; then
        warn "No .tar.gz files found in $RESULTS_DIR (empty or incomplete results)"
        warn "Skipping analysis for this directory"
        continue
    fi
    
    info "Found results directory: $RESULTS_DIR (contains $TAR_COUNT result archives)"
    
    # OCP Extension: Extract original subject name from timestamped directory
    # results-lightftp_Feb-13_02-04-17 → lightftp
    ORIGINAL_SUBJECT=$(echo "$RESULTS_DIR" | sed 's/results-\([^_]*\).*/\1/')
    
    # OCP Extension: Call analysis directly on this specific directory to avoid
    # profuzzbench_generate_all.sh processing all matching directories
    cd "$PFBENCH/$RESULTS_DIR"
    
    info "Extracting fuzzer names and replication count..."
    FUZZERS=$(ls *.tar.gz 2>/dev/null | perl -n -l -e 'print $1 if /^out-.+-(\w+)_\d+\.tar\.gz/;'|sort|uniq)
    REPS=$(ls *.tar.gz 2>/dev/null | perl -n -l -e 'print $1 if /^out-.+-\w+_(\d+)\.tar\.gz/;'|sort -r|head -1)
    
    if [ -z "$FUZZERS" ] || [ -z "$REPS" ]; then
        warn "Cannot extract fuzzer names or replication count from $RESULTS_DIR"
        cd "$PFBENCH"
        continue
    fi
    #echo $FUZZERS
    info "Subject: $ORIGINAL_SUBJECT, Fuzzers: $FUZZERS, Replications: $REPS"
    
    # OCP Extension: Clean up previous analysis (suppress expected "file not found" warnings)
    rm -f results.csv states.csv 2>/dev/null
    ls | grep out- | grep -v "tar.gz" | xargs rm -rf 2>/dev/null
    
    APPEND=0
    for FUZZER in $FUZZERS; do
        info "Analyzing fuzzer: $FUZZER"
        PATH=$PATH:$PFBENCH/scripts/execution:$PFBENCH/scripts/analysis \
            profuzzbench_generate_csv.sh $ORIGINAL_SUBJECT $REPS $FUZZER results.csv $APPEND states.csv
        APPEND=1
        ls | grep out- | grep -v "tar.gz" | xargs rm -rf 2>/dev/null
        printf "\n\n"
    done
    
    # ─── LLM Token Cost Extraction ──────────────────────────────────
    local llm_csv="llm_cost.csv"
    echo "fuzzer,run,runtime_min,llm_calls,prompt_tokens,completion_tokens,dedup_hits,cost_usd,prompt_per_24h,compl_per_24h,cost_per_24h" > "$llm_csv"
    local _llm_has_data=0
    for _LF in $FUZZERS; do
        for _LR in $(seq 1 $REPS); do
            local _ltarf="out-${ORIGINAL_SUBJECT}-${_LF}_${_LR}.tar.gz"
            [[ ! -f "$_ltarf" ]] && continue
            local _lstats
            _lstats=$(tar -xzOf "$_ltarf" --wildcards "*/fuzzer_stats" 2>/dev/null || true)
            [[ -z "$_lstats" ]] && continue
            local _lst _llu _lcalls _lptok _lctok _ldedup
            _lst=$(echo "$_lstats"   | grep -m1 '^start_time'        | sed 's/.*: *//' | tr -d '[:space:]')
            _llu=$(echo "$_lstats"   | grep -m1 '^last_update'       | sed 's/.*: *//' | tr -d '[:space:]')
            _lcalls=$(echo "$_lstats" | grep -m1 '^llm_total_calls'  | sed 's/.*: *//' | tr -d '[:space:]')
            _lptok=$(echo "$_lstats"  | grep -m1 '^llm_prompt_tokens'  | sed 's/.*: *//' | tr -d '[:space:]')
            _lctok=$(echo "$_lstats"  | grep -m1 '^llm_completion_tok' | sed 's/.*: *//' | tr -d '[:space:]')
            _ldedup=$(echo "$_lstats" | grep -m1 '^llm_dedup_hits'   | sed 's/.*: *//' | tr -d '[:space:]')
            [[ -z "$_lcalls" ]] && continue
            _lptok="${_lptok:-0}"; _lctok="${_lctok:-0}"
            local _lrmin=0
            [[ -n "$_lst" && -n "$_llu" ]] && _lrmin=$(( (_llu - _lst) / 60 ))
            # gpt-4o-mini: $0.15/1M prompt, $0.60/1M completion
            local _lcost _lptok24 _lctok24 _lcost24
            _lcost=$(awk   "BEGIN{printf \"%.6f\", (${_lptok}*0.15+${_lctok}*0.60)/1000000}")
            _lptok24=$(awk "BEGIN{ r=${_lrmin}; if(r>0) printf \"%.0f\", ${_lptok}/r*1440; else print 0}")
            _lctok24=$(awk "BEGIN{ r=${_lrmin}; if(r>0) printf \"%.0f\", ${_lctok}/r*1440; else print 0}")
            _lcost24=$(awk "BEGIN{ r=${_lrmin}; if(r>0) printf \"%.6f\", (${_lptok}*0.15+${_lctok}*0.60)/1000000/r*1440; else print 0}")
            echo "${_LF},${_LR},${_lrmin},${_lcalls:-0},${_lptok},${_lctok},${_ldedup:-0},${_lcost},${_lptok24},${_lctok24},${_lcost24}" >> "$llm_csv"
            _llm_has_data=1
        done
    done
    if [[ $_llm_has_data -eq 1 ]]; then
        info "LLM cost data → ${RESULTS_DIR}/llm_cost.csv"
    else
        rm -f "$llm_csv"
    fi

    # Generate plots
    info "Generating plots..."
    PATH=$PATH:$PFBENCH/scripts/execution:$PFBENCH/scripts/analysis \
        profuzzbench_plot.py -i results.csv -p ${ORIGINAL_SUBJECT} -r $REPS -c $TIME -s 60 \
        -o ${ORIGINAL_SUBJECT}_coverage -f $FUZZERS
    
    PATH=$PATH:$PFBENCH/scripts/execution:$PFBENCH/scripts/analysis \
        profuzzbench_state.py -i states.csv -p ${ORIGINAL_SUBJECT} -r $REPS -c $TIME -s 60 \
        -o ${ORIGINAL_SUBJECT}_states -f $FUZZERS
    
    # OCP Extension: Add timestamp to generated plots for better traceability
    # Extract timestamp from results directory (results-lightftp_Feb-13_02-04-17 → Feb-13_02-04-17)
    TIMESTAMP=$(echo "$RESULTS_DIR" | sed 's/results-[^_]*_\(.*\)/\1/')
    
    if [ ! -z "$TIMESTAMP" ] && [ "$TIMESTAMP" != "$RESULTS_DIR" ]; then
        # Rename plots to include timestamp
        if [ -f "${ORIGINAL_SUBJECT}_coverage.png" ]; then
            mv "${ORIGINAL_SUBJECT}_coverage.png" "cov_over_time_${ORIGINAL_SUBJECT}_${TIMESTAMP}.png"
            info "Generated coverage plot: cov_over_time_${ORIGINAL_SUBJECT}_${TIMESTAMP}.png"
        fi
        
        if [ -f "${ORIGINAL_SUBJECT}_states.png" ]; then
            mv "${ORIGINAL_SUBJECT}_states.png" "state_over_time_${ORIGINAL_SUBJECT}_${TIMESTAMP}.png"
            info "Generated state plot: state_over_time_${ORIGINAL_SUBJECT}_${TIMESTAMP}.png"
        fi
    fi
    
    cd "$PFBENCH"
    
    RES_FOLDER=$(date "+res_${SUBJECT}_%b-%d_%H-%M-%S")
    
    info "Results from analysis for ${SUBJECT} are stored in $RES_FOLDER"
    mkdir ../$RES_FOLDER
    cp -r *_${SUBJECT}.png ../$RES_FOLDER 2>/dev/null || true
    cp -r "$RESULTS_DIR" ../$RES_FOLDER
done
