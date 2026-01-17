#!/bin/bash
echo "Installing system dependencies for ChatAFL and ChatAFL-Enhanced..."
sudo apt-get update
sudo apt-get install -y docker python3 python3-pip \
    libcurl4-openssl-dev libjson-c-dev libpcre2-dev graphviz

echo "Installing Python packages..."
pip3 install matplotlib pandas

echo "Dependencies installed successfully"
echo ""
echo "For ChatAFL-Enhanced, the following are required:"
echo "  - libcurl4-openssl-dev (HTTP client for LLM)"
echo "  - libjson-c-dev (JSON parsing)"
echo "  - libpcre2-dev (Regex for parseability verification)"
echo "  - graphviz (STT visualization)"