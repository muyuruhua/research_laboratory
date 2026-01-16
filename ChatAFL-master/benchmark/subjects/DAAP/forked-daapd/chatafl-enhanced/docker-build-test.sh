#!/bin/bash
# 测试Docker构建（不实际构建，只检查配置）

echo "════════════════════════════════════════════════════════"
echo "  Docker构建配置检查"
echo "════════════════════════════════════════════════════════"
echo ""

# 1. 检查是否有Dockerfile引用
echo "[1/4] 检查Dockerfile..."
if [ -f "../benchmark/Dockerfile" ]; then
    echo "  ✓ benchmark/Dockerfile 存在"
    if grep -q "chatafl-enhanced" ../benchmark/Dockerfile; then
        echo "  ✓ Dockerfile包含chatafl-enhanced引用"
    else
        echo "  ⚠ Dockerfile未明确引用chatafl-enhanced"
    fi
else
    echo "  ⚠ benchmark/Dockerfile 不存在"
fi
echo ""

# 2. 检查setup.sh是否复制ChatAFL-Enhanced
echo "[2/4] 检查setup.sh配置..."
if grep -q "ChatAFL-Enhanced" ../setup.sh; then
    echo "  ✓ setup.sh包含ChatAFL-Enhanced"
    grep "ChatAFL-Enhanced" ../setup.sh | head -5
else
    echo "  ✗ setup.sh不包含ChatAFL-Enhanced"
fi
echo ""

# 3. 检查benchmark目录中的副本
echo "[3/4] 检查benchmark副本..."
SUBJECTS=("BFTPD" "LightFTP" "ProFTPD")
for subj in "${SUBJECTS[@]}"; do
    if [ -d "../benchmark/subjects/FTP/$subj/chatafl-enhanced" ]; then
        if [ -f "../benchmark/subjects/FTP/$subj/chatafl-enhanced/afl-fuzz" ]; then
            SIZE=$(stat -c%s "../benchmark/subjects/FTP/$subj/chatafl-enhanced/afl-fuzz" | numfmt --to=iec-i)
            echo "  ✓ $subj/chatafl-enhanced (afl-fuzz: $SIZE)"
        else
            echo "  ⚠ $subj/chatafl-enhanced 存在但无afl-fuzz"
        fi
    else
        echo "  ✗ $subj/chatafl-enhanced 不存在"
    fi
done
echo ""

# 4. 检查是否需要重新运行setup.sh
echo "[4/4] 检查同步状态..."
if [ -f "afl-fuzz" ]; then
    LOCAL_TIME=$(stat -c%Y afl-fuzz)
    NEEDS_SYNC=false
    
    for subj in "${SUBJECTS[@]}"; do
        REMOTE_FILE="../benchmark/subjects/FTP/$subj/chatafl-enhanced/afl-fuzz"
        if [ -f "$REMOTE_FILE" ]; then
            REMOTE_TIME=$(stat -c%Y "$REMOTE_FILE")
            if [ "$LOCAL_TIME" -gt "$REMOTE_TIME" ]; then
                NEEDS_SYNC=true
                echo "  ⚠ $subj/chatafl-enhanced 过时 (需要更新)"
            fi
        fi
    done
    
    if [ "$NEEDS_SYNC" = true ]; then
        echo ""
        echo "  ⚠ 需要重新运行: sudo KEY='your_key' ./setup.sh"
    else
        echo "  ✓ 所有副本都是最新的"
    fi
else
    echo "  ✗ 本地afl-fuzz不存在"
fi
echo ""

# 最终建议
echo "════════════════════════════════════════════════════════"
echo "📋 Docker构建建议:"
echo ""
echo "1. 已完成本地编译: ✓"
echo "2. 已复制到benchmark: $([ -d '../benchmark/subjects/FTP/BFTPD/chatafl-enhanced' ] && echo '✓' || echo '✗')"
echo "3. Docker镜像构建: $(docker images | grep -q chatafl-enhanced && echo '✓' || echo '⚠ 待构建')"
echo ""
echo "如需构建Docker镜像，运行:"
echo "  cd .."
echo "  sudo KEY='your_openai_key' ./setup.sh"
echo ""
echo "注意: setup.sh会自动复制ChatAFL-Enhanced到所有benchmark目录"
echo "════════════════════════════════════════════════════════"
