#!/bin/bash

# Enable error handling and debugging (OCP: configurable via DEBUG)
set -e  # Exit on error
set -o pipefail  # Catch errors in pipelines
[ "${DEBUG:-0}" = "1" ] && set -x  # Enable debug mode if DEBUG=1

if [ -z "$KEY" ]; then
    echo "ERROR: NO OPENAI API KEY PROVIDED! Please set the KEY environment variable"
    echo "Usage: export KEY=\"your-api-key\" && sudo -E ./setup.sh"
    exit 1  # Fixed: should exit with error code
fi

echo "[INFO] Using API key: ${KEY:0:10}...${KEY: -10}"

# Update the openAI key in all fuzzer variants
echo "[INFO] Updating OpenAI API key in source files..."
for x in ChatAFL ChatAFL-CL1 ChatAFL-CL2 ChatAFL-Enhanced;
do
  if [ -f "$x/chat-llm.h" ]; then
    sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$KEY\"/" $x/chat-llm.h
    echo "[OK] Updated $x/chat-llm.h"
  else
    echo "[WARNING] $x/chat-llm.h not found, skipping..."
  fi
done

# Copy the different versions of ChatAFL to the benchmark directories
echo "[INFO] Copying ChatAFL variants to benchmark directories..."
copied_count=0
for subject in ./benchmark/subjects/*/*; do
  if [ ! -d "$subject" ]; then
    continue
  fi
  
  rm -rf $subject/aflnet 2>&1 >/dev/null
  cp -r aflnet $subject/aflnet

  rm -rf $subject/chatafl 2>&1 >/dev/null
  cp -r ChatAFL $subject/chatafl
  
  rm -rf $subject/chatafl-cl1 2>&1 >/dev/null
  cp -r ChatAFL-CL1 $subject/chatafl-cl1
  
  rm -rf $subject/chatafl-cl2 2>&1 >/dev/null
  cp -r ChatAFL-CL2 $subject/chatafl-cl2
  
  rm -rf $subject/chatafl-enhanced 2>&1 >/dev/null
  cp -r ChatAFL-Enhanced $subject/chatafl-enhanced
  
  copied_count=$((copied_count + 1))
done
echo "[OK] Copied fuzzer variants to $copied_count target directories"

# Build the docker images
echo "[INFO] Starting Docker image builds..."
echo "[INFO] This may take 30-60 minutes depending on your system..."

PFBENCH="$PWD/benchmark"
cd $PFBENCH
PFBENCH=$PFBENCH scripts/execution/profuzzbench_build_all.sh

echo "[SUCCESS] Setup completed successfully!"
echo "[INFO] Docker images are ready for fuzzing experiments"

echo "[SUCCESS] Setup completed successfully!"