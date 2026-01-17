#!/bin/bash
# monitor_docker_build.sh - 实时监控Docker构建进度

LOG_FILE="/tmp/docker_build.log"
LAST_LINES=0

echo "=========================================="
echo " Docker构建实时监控"
echo "=========================================="
echo ""
echo "日志文件: $LOG_FILE"
echo "按Ctrl+C停止监控"
echo ""

# 检查日志文件是否存在
if [ ! -f "$LOG_FILE" ]; then
    echo "等待构建开始..."
fi

# 实时显示新增的日志行
while true; do
    if [ -f "$LOG_FILE" ]; then
        # 计算当前行数
        CURRENT_LINES=$(wc -l < "$LOG_FILE")
        
        # 如果有新行，显示它们
        if [ $CURRENT_LINES -gt $LAST_LINES ]; then
            NEW_LINES=$((CURRENT_LINES - LAST_LINES))
            tail -n $NEW_LINES "$LOG_FILE"
            LAST_LINES=$CURRENT_LINES
            
            # 显示进度
            CURRENT_STEP=$(grep -o "Step [0-9]*/40" "$LOG_FILE" | tail -1)
            if [ -n "$CURRENT_STEP" ]; then
                STEP_NUM=$(echo "$CURRENT_STEP" | cut -d'/' -f1 | cut -d' ' -f2)
                PROGRESS=$((STEP_NUM * 100 / 40))
                echo -ne "\r进度: $CURRENT_STEP ($PROGRESS%)    "
            fi
        fi
        
        # 检查是否完成
        if grep -q "Successfully built" "$LOG_FILE"; then
            echo -e "\n\n✓ 构建成功！"
            break
        fi
        
        # 检查是否失败
        if grep -q "ERROR" "$LOG_FILE"; then
            echo -e "\n\n✗ 构建失败！"
            echo "错误信息:"
            grep "ERROR" "$LOG_FILE" | tail -5
            break
        fi
    fi
    
    sleep 2
done
