#!/bin/bash
# check_build_status.sh - 检查Docker镜像构建状态

echo "检查Docker镜像构建状态..."
echo ""

# 检查构建日志最后一行
if [ -f /tmp/docker_build.log ]; then
    echo "最后5行构建日志:"
    tail -5 /tmp/docker_build.log
    echo ""
    
    # 检查是否完成
    if grep -q "Successfully built" /tmp/docker_build.log; then
        echo "✓ 构建已完成！"
        
        # 验证新镜像
        echo ""
        echo "验证新镜像中的Enhanced版本..."
        docker run --rm lightftp stat -c "%s %y" /home/ubuntu/chatafl-enhanced/afl-fuzz
        
    elif grep -q "ERROR" /tmp/docker_build.log; then
        echo "✗ 构建失败！"
        echo ""
        echo "错误信息:"
        grep "ERROR" /tmp/docker_build.log | tail -5
        
    else
        echo "⏳ 构建进行中..."
        current_step=$(grep -o "Step [0-9]*/40" /tmp/docker_build.log | tail -1)
        echo "当前: $current_step"
    fi
else
    echo "⚠ 构建日志文件不存在"
fi
