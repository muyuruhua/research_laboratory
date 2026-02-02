#!/bin/bash

# Check execution parameters
NUM_CONTAINERS=$1
TIMEOUT_MINUTES=$2
TARGET_LIST=$3
FUZZER_LIST=$4

if [[ "x$NUM_CONTAINERS" == "x" ]] || [[ "x$TIMEOUT_MINUTES" == "x" ]] || [[ "x$TARGET_LIST" == "x" ]] || [[ "x$FUZZER_LIST" == "x" ]]
then
    echo "Usage: $0 NUM_CONTAINERS TIMEOUT_MINUTES TARGET FUZZER"
    echo ""
    echo "Example:"
    echo "  sudo -E ./run.sh 2 30 kamailio chatafl-enhanced"
    echo ""
    echo "Parameters:"
    echo "  NUM_CONTAINERS   - Number of parallel containers (e.g., 2)"
    echo "  TIMEOUT_MINUTES  - Fuzzing timeout in minutes (e.g., 30)"
    echo "  TARGET           - Target program (e.g., kamailio, lightftp, live555)"
    echo "  FUZZER           - Fuzzer to use (aflnet, chatafl, chatafl-cl1, chatafl-cl2, chatafl-enhanced)"
    echo ""
    echo "Note: Make sure to run setup.sh first to build Docker images"
    exit 1
fi

if [ -z $KEY ]; then
    echo "NO OPENAI API KEY PROVIDED! Please set the KEY environment variable"
    echo "Example: export KEY=\"your-api-key\" && sudo -E ./run.sh ..."
    exit 1
fi

# Update the openAI key
echo "Updating OpenAI API key in source files..."
for x in ChatAFL ChatAFL-CL1 ChatAFL-CL2 ChatAFL-Enhanced;
do
  sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$KEY\"/" $x/chat-llm.h
done

# Copy the different versions of ChatAFL to the benchmark directories
echo "Copying ChatAFL variants to benchmark directories..."
for subject in ./benchmark/subjects/*/*; do
  rm -r $subject/aflnet 2>&1 >/dev/null
  cp -r aflnet $subject/aflnet

  rm -r $subject/chatafl 2>&1 >/dev/null
  cp -r ChatAFL $subject/chatafl
  
  rm -r $subject/chatafl-cl1 2>&1 >/dev/null
  cp -r ChatAFL-CL1 $subject/chatafl-cl1
  
  rm -r $subject/chatafl-cl2 2>&1 >/dev/null
  cp -r ChatAFL-CL2 $subject/chatafl-cl2
  
  rm -r $subject/chatafl-enhanced 2>&1 >/dev/null
  cp -r ChatAFL-Enhanced $subject/chatafl-enhanced
done

# Execute fuzzing
PFBENCH="$PWD/benchmark"
cd $PFBENCH

PATH=$PATH:$PFBENCH/scripts/execution:$PFBENCH/scripts/analysis
TIMEOUT=$(( ${TIMEOUT_MINUTES} * 60 ))
SKIPCOUNT="${SKIPCOUNT:-1}"
TEST_TIMEOUT="${TEST_TIMEOUT:-5000}"

echo ""
echo "========================================="
echo "Starting Fuzzing Execution"
echo "========================================="
echo "NUM_CONTAINERS: ${NUM_CONTAINERS}"
echo "TIMEOUT: ${TIMEOUT}s (${TIMEOUT_MINUTES} minutes)"
echo "TARGET: ${TARGET_LIST}"
echo "FUZZER: ${FUZZER_LIST}"
echo "SKIPCOUNT: ${SKIPCOUNT}"
echo "TEST_TIMEOUT: ${TEST_TIMEOUT}ms"
echo "========================================="
echo ""

PFBENCH=$PFBENCH PATH=$PATH NUM_CONTAINERS=$NUM_CONTAINERS TIMEOUT=$TIMEOUT SKIPCOUNT=$SKIPCOUNT TEST_TIMEOUT=$TEST_TIMEOUT scripts/execution/profuzzbench_exec_all.sh ${TARGET_LIST} ${FUZZER_LIST}