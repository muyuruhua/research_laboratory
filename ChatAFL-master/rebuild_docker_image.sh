#!/bin/bash
# rebuild_docker_image.sh - 重新构建包含修复后Enhanced的Docker镜像

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "=========================================="
echo " 重新构建LightFTP Docker镜像"
echo "=========================================="
echo ""

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[1/4]${NC} 检查修复后的Enhanced二进制..."
if [ ! -f "ChatAFL-Enhanced/afl-fuzz" ]; then
    echo -e "${RED}✗${NC} ChatAFL-Enhanced/afl-fuzz不存在！"
    echo "请先运行: cd ChatAFL-Enhanced && make clean && make"
    exit 1
fi

ENHANCED_SIZE=$(stat -c%s "ChatAFL-Enhanced/afl-fuzz")
ENHANCED_TIME=$(stat -c%y "ChatAFL-Enhanced/afl-fuzz")
echo -e "${GREEN}✓${NC} Enhanced binary: $(numfmt --to=iec-i --suffix=B $ENHANCED_SIZE), 编译时间: $ENHANCED_TIME"

echo ""
echo -e "${YELLOW}[2/4]${NC} 检查Dockerfile..."
DOCKERFILE="benchmark/subjects/FTP/LightFTP/Dockerfile"
if [ ! -f "$DOCKERFILE" ]; then
    echo -e "${RED}✗${NC} $DOCKERFILE不存在！"
    exit 1
fi

echo -e "${GREEN}✓${NC} 找到Dockerfile"

# 检查Dockerfile是否包含chatafl-enhanced
if ! grep -q "chatafl-enhanced" "$DOCKERFILE"; then
    echo -e "${YELLOW}⚠${NC} Dockerfile中未包含chatafl-enhanced，需要添加..."
    echo "  正在更新Dockerfile..."
    
    # 备份原始Dockerfile
    cp "$DOCKERFILE" "$DOCKERFILE.bak"
    
    # 在chatafl-cl2后添加chatafl-enhanced
    sed -i '/COPY --chown=ubuntu:ubuntu chatafl-cl2 chatafl-cl2/a \
\
COPY --chown=ubuntu:ubuntu ChatAFL-Enhanced chatafl-enhanced\
RUN cd chatafl-enhanced \&\& \\\
    make clean all $MAKE_OPT \&\& \\\
    cd llvm_mode \&\& make $MAKE_OPT' "$DOCKERFILE"
    
    echo -e "${GREEN}✓${NC} Dockerfile已更新（备份为Dockerfile.bak）"
else
    echo -e "${GREEN}✓${NC} Dockerfile已包含chatafl-enhanced"
fi

echo ""
echo -e "${YELLOW}[3/4]${NC} 备份当前镜像（如果存在）..."
if docker images | grep -q "lightftp"; then
    echo "  → 备份当前lightftp镜像为lightftp:old"
    docker tag lightftp:latest lightftp:old 2>/dev/null || true
    echo -e "${GREEN}✓${NC} 已备份"
else
    echo "  → 无需备份（镜像不存在）"
fi

echo ""
echo -e "${YELLOW}[4/4]${NC} 重新构建lightftp镜像..."
echo ""
echo "这将执行以下操作："
echo "  1. 删除旧的lightftp镜像"
echo "  2. 从头构建新镜像（包含修复后的Enhanced）"
echo "  3. 预计耗时: 5-10分钟"
echo ""
read -p "是否继续? (y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "已取消"
    exit 0
fi

echo ""
echo "开始构建..."

# 构建上下文必须是项目根目录（包含所有fuzzer代码）
BUILD_CONTEXT="$SCRIPT_DIR"
DOCKERFILE="$SCRIPT_DIR/benchmark/subjects/FTP/LightFTP/Dockerfile"

# 删除旧镜像
docker rmi lightftp:latest 2>/dev/null || true

# 重新构建
cd "$BUILD_CONTEXT"
docker build \
    -f "$DOCKERFILE" \
    -t lightftp \
    --build-arg MAKE_OPT="-j$(nproc)" \
    . 2>&1 | tee /tmp/docker_build.log

if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}✓ Docker镜像构建成功！${NC}"
    echo ""
    
    # 验证新镜像中的Enhanced版本
    echo "验证新镜像中的Enhanced binary..."
    DOCKER_ENHANCED_SIZE=$(docker run --rm lightftp stat -c%s /home/ubuntu/chatafl-enhanced/afl-fuzz 2>/dev/null)
    DOCKER_ENHANCED_TIME=$(docker run --rm lightftp stat -c%y /home/ubuntu/chatafl-enhanced/afl-fuzz 2>/dev/null)
    
    echo "Docker内Enhanced: $(numfmt --to=iec-i --suffix=B $DOCKER_ENHANCED_SIZE), 时间: $DOCKER_ENHANCED_TIME"
    echo "本地Enhanced:     $(numfmt --to=iec-i --suffix=B $ENHANCED_SIZE), 时间: $ENHANCED_TIME"
    
    if [ "$DOCKER_ENHANCED_SIZE" -eq "$ENHANCED_SIZE" ]; then
        echo -e "${GREEN}✓ 大小匹配！${NC}"
    else
        echo -e "${YELLOW}⚠ 大小不匹配，可能需要检查${NC}"
    fi
    
    echo ""
    echo "=========================================="
    echo -e "${GREEN}完成！${NC}"
    echo "=========================================="
    echo ""
    echo "下一步: 运行验证测试"
    echo "  ./verify_fix.sh"
    echo ""
    echo "或运行完整测试:"
    echo "  ./compare_fuzzers_docker.sh LightFTP FTP 60"
    echo ""
else
    echo ""
    echo -e "${RED}✗ 构建失败！${NC}"
    echo "查看日志: cat /tmp/docker_build.log"
    exit 1
fi
