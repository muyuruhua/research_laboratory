#!/bin/bash

# Build ChatAFL-Enhanced Docker Image
# Usage: ./build_docker_enhanced.sh [tag]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="chatafl-enhanced"
TAG="${1:-latest}"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}Building ChatAFL-Enhanced Docker Image${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""

# Check if Dockerfile exists
if [ ! -f "$SCRIPT_DIR/ChatAFL-Enhanced/Dockerfile" ]; then
    echo -e "${RED}ERROR: Dockerfile not found in ChatAFL-Enhanced/${NC}"
    exit 1
fi

# Build the Docker image
echo -e "${YELLOW}Building Docker image: ${IMAGE_NAME}:${TAG}${NC}"
echo "This may take several minutes..."
echo ""

cd "$SCRIPT_DIR/ChatAFL-Enhanced"

docker build -t ${IMAGE_NAME}:${TAG} . 2>&1 | tee /tmp/docker_build.log

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo ""
    echo -e "${GREEN}======================================${NC}"
    echo -e "${GREEN}Docker Image Built Successfully!${NC}"
    echo -e "${GREEN}======================================${NC}"
    echo ""
    echo "Image: ${IMAGE_NAME}:${TAG}"
    echo ""
    echo "To run the container:"
    echo "  docker run -it ${IMAGE_NAME}:${TAG} /bin/bash"
    echo ""
    echo "To run AFL fuzzing in container:"
    echo "  docker run -it -v \$(pwd)/seeds:/seeds -v \$(pwd)/output:/output \\"
    echo "             ${IMAGE_NAME}:${TAG} \\"
    echo "             afl-fuzz -E -i /seeds -o /output -N PROTOCOL -P PROTOCOL \\"
    echo "             -m none -t 1000 -- /target @@"
    echo ""
    echo "Environment variables are pre-set:"
    echo "  - CHATAFL_ENHANCED=1"
    echo "  - CEGAR_CACHE_DIR=/opt/aflnet/.cegar_cache"
    echo ""
else
    echo ""
    echo -e "${RED}======================================${NC}"
    echo -e "${RED}Docker Build Failed!${NC}"
    echo -e "${RED}======================================${NC}"
    echo ""
    echo "Check the log at: /tmp/docker_build.log"
    exit 1
fi

cd "$SCRIPT_DIR"
exit 0
