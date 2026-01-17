#!/bin/bash

# ChatAFL-Enhanced Build and Integration Script
# This script builds ChatAFL-Enhanced modules and integrates them into the fuzzing environment

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHATAFL_ENHANCED_DIR="$SCRIPT_DIR/ChatAFL-Enhanced"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}ChatAFL-Enhanced Build Script${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""

# Check if ChatAFL-Enhanced directory exists
if [ ! -d "$CHATAFL_ENHANCED_DIR" ]; then
    echo -e "${RED}ERROR: ChatAFL-Enhanced directory not found!${NC}"
    exit 1
fi

# Step 1: Check dependencies
echo -e "${YELLOW}[1/5] Checking dependencies...${NC}"
DEPS_OK=1

check_dep() {
    if pkg-config --exists $1 2>/dev/null; then
        echo -e "  ✓ $1"
    else
        echo -e "  ${RED}✗ $1 missing${NC}"
        DEPS_OK=0
    fi
}

check_dep libcurl
check_dep json-c
check_dep libpcre2-8

if [ $DEPS_OK -eq 0 ]; then
    echo -e "${RED}Missing dependencies. Installing...${NC}"
    sudo apt-get update
    sudo apt-get install -y libcurl4-openssl-dev libjson-c-dev libpcre2-dev graphviz
    echo -e "${GREEN}Dependencies installed${NC}"
fi

# Step 2: Update OpenAI API Key
if [ ! -z "$KEY" ]; then
    echo -e "${YELLOW}[2/5] Updating OpenAI API Key...${NC}"
    sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$KEY\"/" $CHATAFL_ENHANCED_DIR/chat-llm.h
    echo -e "${GREEN}API Key updated${NC}"
else
    echo -e "${YELLOW}[2/5] No API Key provided (KEY env var not set), skipping...${NC}"
fi

# Step 3: Build ChatAFL-Enhanced modules
echo -e "${YELLOW}[3/5] Building ChatAFL-Enhanced modules...${NC}"
cd "$CHATAFL_ENHANCED_DIR"

# Create Makefile if only Makefile.enhanced exists
if [ ! -f "Makefile" ] && [ -f "Makefile.enhanced" ]; then
    cp Makefile.enhanced Makefile
fi

make clean
make standalone

if [ $? -eq 0 ]; then
    echo -e "${GREEN}Standalone build successful${NC}"
else
    echo -e "${RED}Standalone build failed${NC}"
    exit 1
fi

make integrated

if [ $? -eq 0 ] && [ -f "libchatafl-enhanced.a" ]; then
    SIZE=$(stat -c%s libchatafl-enhanced.a)
    echo -e "${GREEN}Static library built: libchatafl-enhanced.a (${SIZE} bytes)${NC}"
else
    echo -e "${RED}Integrated build failed${NC}"
    exit 1
fi

cd "$SCRIPT_DIR"

# Step 4: Run integration tests
echo -e "${YELLOW}[4/5] Running integration tests...${NC}"
if [ -f "$SCRIPT_DIR/test_integration.sh" ]; then
    bash "$SCRIPT_DIR/test_integration.sh"
else
    echo -e "${YELLOW}Integration test script not found, skipping...${NC}"
fi

# Step 5: Copy to benchmark directories (if they exist)
if [ -d "$SCRIPT_DIR/benchmark/subjects" ]; then
    echo -e "${YELLOW}[5/5] Copying to benchmark directories...${NC}"
    for subject in ./benchmark/subjects/*/*; do
        if [ -d "$subject" ]; then
            rm -rf "$subject/chatafl-enhanced" 2>/dev/null
            cp -r ChatAFL-Enhanced "$subject/chatafl-enhanced"
            echo "  ✓ Copied to $subject"
        fi
    done
    echo -e "${GREEN}ChatAFL-Enhanced copied to all benchmark subjects${NC}"
else
    echo -e "${YELLOW}[5/5] No benchmark directory found, skipping copy...${NC}"
fi

echo ""
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}Build Complete!${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""
echo "ChatAFL-Enhanced is ready to use."
echo ""
echo "To enable enhanced mode:"
echo "  export CHATAFL_ENHANCED=1"
echo "  export CEGAR_CACHE_DIR=\$(pwd)/output/.cegar_cache"
echo ""
echo "To run AFL with enhancements:"
echo "  ./afl-fuzz -E -i seeds/ -o output/ -N PROTOCOL -P PROTOCOL \\"
echo "             -m none -t 1000 -- ./target @@"
echo ""
echo "To visualize STT:"
echo "  cd output/.stt_export"
echo "  dot -Tpng stt_cycle_100.dot -o stt_100.png"
echo ""

exit 0
