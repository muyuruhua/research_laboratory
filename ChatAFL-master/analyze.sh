#!/bin/bash

# Generate the state and coverage graphs

FILTER=$1
TIME=${2:-1440}

reset="\e[0m"
green="\e[0;92m"
yellow="\e[0;33m"
function warn  { echo -e "${yellow}[!] $1$reset"; }
function info  { echo -e "${green}[+]$reset $1"; }

if [ -z "$FILTER" ]; then
    echo "Usage: analyze.sh <subject names> <time in minutes>"
    exit 1
fi

PFBENCH="$PWD/benchmark"
cd $PFBENCH

for SUBJECT in $(echo $FILTER | tr "," "\n");
do
    echo "Analyzing $SUBJECT"
    
    # OCP: Find timestamped results directory matching pattern results-${SUBJECT}_*
    # This supports both old format (results-lightftp) and new format (results-lightftp_Feb-02_12-34-56)
    RESULTS_DIR=$(find . -maxdepth 1 -type d -name "results-${SUBJECT}_*" | sort -r | head -n 1)
    
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
    
    info "Found results directory: $RESULTS_DIR"
    
    # Pass the actual results directory to the analysis script
    PATH=$PATH:$PFBENCH/scripts/execution:$PFBENCH/scripts/analysis RESULTS_DIR=$RESULTS_DIR scripts/analysis/profuzzbench_generate_all.sh $SUBJECT $TIME
    
    RES_FOLDER=$(date "+res_${SUBJECT}_%b-%d_%H-%M-%S")
    
    info "Results from analysis for ${SUBJECT} are stored in $RES_FOLDER"
    mkdir ../$RES_FOLDER
    cp -r *_${SUBJECT}.png ../$RES_FOLDER 2>/dev/null || true
    cp -r "$RESULTS_DIR" ../$RES_FOLDER
done
