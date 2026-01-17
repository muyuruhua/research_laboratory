#!/bin/bash
# verify_setup_optimization.sh - 验证setup.sh和Docker构建是否使用-O3优化

echo "=========================================="
echo " 验证优化配置"
echo "=========================================="
echo ""

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[1/4]${NC} 检查Makefile.enhanced优化标志..."
if grep -q "CFLAGS.*-O3" ChatAFL-Enhanced/Makefile.enhanced; then
    echo -e "${GREEN}✓${NC} Makefile.enhanced使用-O3优化"
    grep "CFLAGS.*-O3" ChatAFL-Enhanced/Makefile.enhanced | head -1
else
    echo -e "${RED}✗${NC} Makefile.enhanced未使用-O3！"
    grep "CFLAGS.*-O" ChatAFL-Enhanced/Makefile.enhanced | head -1
fi

echo ""
echo -e "${YELLOW}[2/4]${NC} 检查setup.sh是否使用Makefile.enhanced..."
if grep -q "make -f Makefile.enhanced" setup.sh; then
    echo -e "${GREEN}✓${NC} setup.sh正确使用Makefile.enhanced"
    grep "make -f Makefile.enhanced" setup.sh | head -2
else
    echo -e "${RED}✗${NC} setup.sh未使用Makefile.enhanced！"
fi

echo ""
echo -e "${YELLOW}[3/4]${NC} 检查主Makefile优化标志..."
if grep -q "CFLAGS.*-O3" ChatAFL-Enhanced/Makefile; then
    echo -e "${GREEN}✓${NC} 主Makefile使用-O3优化"
    grep "CFLAGS.*-O3" ChatAFL-Enhanced/Makefile | head -1
else
    echo -e "${YELLOW}⚠${NC} 主Makefile优化标志："
    grep "CFLAGS.*-O" ChatAFL-Enhanced/Makefile | head -1
fi

echo ""
echo -e "${YELLOW}[4/4]${NC} 检查当前编译的二进制..."
if [ -f ChatAFL-Enhanced/afl-fuzz ]; then
    SIZE=$(stat -c%s ChatAFL-Enhanced/afl-fuzz)
    TIME=$(stat -c%y ChatAFL-Enhanced/afl-fuzz | cut -d' ' -f1,2 | cut -d'.' -f1)
    echo -e "${GREEN}✓${NC} Enhanced binary存在"
    echo "  大小: $(numfmt --to=iec-i --suffix=B $SIZE)"
    echo "  编译时间: $TIME"
    
    # 检查是否使用-O3编译（通过编译时间判断是否是今天的优化版本）
    TODAY=$(date +%Y-%m-%d)
    if echo "$TIME" | grep -q "$TODAY"; then
        echo -e "${GREEN}✓${NC} 二进制是今天编译的（可能包含-O3优化）"
    else
        echo -e "${YELLOW}⚠${NC} 二进制不是今天编译的，可能需要重新编译"
    fi
else
    echo -e "${RED}✗${NC} afl-fuzz二进制不存在"
fi

echo ""
echo "=========================================="
echo " 总结"
echo "=========================================="
echo ""
echo "配置检查："
echo "  Makefile.enhanced: $(grep -q 'CFLAGS.*-O3' ChatAFL-Enhanced/Makefile.enhanced && echo '✓ -O3' || echo '✗ 非-O3')"
echo "  主Makefile:        $(grep -q 'CFLAGS.*-O3' ChatAFL-Enhanced/Makefile && echo '✓ -O3' || echo '✗ 非-O3')"
echo "  setup.sh:          $(grep -q 'Makefile.enhanced' setup.sh && echo '✓ 使用Makefile.enhanced' || echo '✗ 未使用')"
echo ""

if grep -q "CFLAGS.*-O3" ChatAFL-Enhanced/Makefile.enhanced && \
   grep -q "CFLAGS.*-O3" ChatAFL-Enhanced/Makefile && \
   grep -q "Makefile.enhanced" setup.sh; then
    echo -e "${GREEN}✓ 所有配置正确！Docker镜像构建将使用-O3优化${NC}"
    echo ""
    echo "建议："
    echo "  1. 等待当前Docker构建完成"
    echo "  2. 运行验证测试: ./verify_fix.sh"
else
    echo -e "${YELLOW}⚠ 部分配置需要检查${NC}"
fi
