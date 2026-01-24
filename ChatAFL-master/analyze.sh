#!/bin/bash

# Generate the state and coverage graphs

FILTER=$1
TIME=${2:-1440}
TIMESTAMP=$3  # Optional: specific timestamp

reset="\e[0m"
green="\e[0;92m"
yellow="\e[0;33m"
function warn  { echo -e "${yellow}[!] $1$reset"; }
function info  { echo -e "${green}[+]$reset $1"; }

if [ -z "$FILTER" ]; then
    echo "Usage: analyze.sh <subject names> <time in minutes> [timestamp]"
    echo ""
    echo "Examples:"
    echo "  ./analyze.sh kamailio 1                    # Auto-detect latest results"
    echo "  ./analyze.sh kamailio,exim 1               # Multiple subjects"
    echo "  ./analyze.sh kamailio 1 20260124_075908    # Specific timestamp"
    exit 1
fi

PFBENCH="$PWD/benchmark"
cd $PFBENCH

for SUBJECT in $(echo $FILTER | tr "," "\n");
do
    echo "Analyzing $SUBJECT"
    
    # Extended: Support timestamped directories while maintaining backward compatibility
    RESULTS_DIR=""
    
    # If specific timestamp provided, use it directly
    if [ -n "$TIMESTAMP" ]; then
        RESULTS_DIR="results-${SUBJECT}-${TIMESTAMP}"
        if [ ! -d "$RESULTS_DIR" ]; then
            warn "Specified results directory not found: $RESULTS_DIR"
            warn "Available directories for $SUBJECT:"
            ls -d results-${SUBJECT}* 2>/dev/null | sed 's/^/  /' || echo "  None found"
            continue
        fi
        info "Using specified results: $RESULTS_DIR"
    else
        # Auto-detect: try exact match first (backward compatibility)
        RESULTS_DIR="results-$SUBJECT"
        
        # If exact directory doesn't exist, try to find timestamped version
        if [ ! -d "$RESULTS_DIR" ]; then
            TIMESTAMPED_DIR=$(ls -dt results-${SUBJECT}-* 2>/dev/null | head -1)
            if [ -n "$TIMESTAMPED_DIR" ]; then
                RESULTS_DIR="$TIMESTAMPED_DIR"
                info "Using latest timestamped results: $RESULTS_DIR"
            fi
        fi
    fi
    
    # Check if results exists
    if [ ! -d "$RESULTS_DIR" ] || [ -z "$(ls -A $RESULTS_DIR 2>/dev/null)" ]; then
        warn "No results for subject $SUBJECT."
        warn "Please check whether the fuzzing has completed via the following command:"
        warn "  docker ps -a | grep $SUBJECT"
        docker ps -a | grep $SUBJECT
        warn ""
        warn "If the containers' status is 'Up ..', please wait for the fuzzing to complete."
        warn "Once the fuzzing complete, the containers' status will change to 'Exited ..'"
        continue
    fi
    
    PATH=$PATH:$PFBENCH/scripts/execution:$PFBENCH/scripts/analysis scripts/analysis/profuzzbench_generate_all.sh $SUBJECT $TIME
    
    RES_FOLDER=$(date "+res_${SUBJECT}_%b-%d_%H-%M-%S")
    
    info "Results from analysis for ${SUBJECT} are stored in $RES_FOLDER"
    mkdir ../$RES_FOLDER
    cp -r *_${SUBJECT}.png ../$RES_FOLDER 2>/dev/null
    cp -r ${RESULTS_DIR} ../$RES_FOLDER
done
