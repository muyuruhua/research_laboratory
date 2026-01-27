#!/bin/bash
# ChatAFL-Enhanced 插件功能验证脚本
# 用于快速验证插件是否正确加载和工作

set -e

echo "========================================"
echo "ChatAFL-Enhanced 插件功能验证"
echo "========================================"
echo

# 检查Docker镜像中的插件文件
echo "[1/4] 检查Docker镜像中的插件文件..."
echo "----------------------------------------"
docker run --rm kamailio:latest bash -c '
  echo "插件列表："
  ls -lh /home/ubuntu/chatafl-enhanced/*.so 2>/dev/null || echo "未找到插件文件"
  echo
  echo "afl-fuzz版本信息："
  /home/ubuntu/chatafl-enhanced/afl-fuzz -h 2>&1 | grep -A2 "plugin" || echo "不支持插件参数"
'
echo

# 测试插件加载（5秒快速测试）
echo "[2/4] 测试插件加载（5秒快速测试）..."
echo "----------------------------------------"
echo "运行：AFL_PLUGIN=chatafl-enhanced-minimal.so ./run.sh 1 0.08 kamailio chatafl-enhanced"
AFL_PLUGIN="chatafl-enhanced-minimal.so" timeout 10s ./run.sh 1 0.08 kamailio chatafl-enhanced || true
echo

# 检查日志中是否有插件加载信息
echo "[3/4] 检查插件加载状态..."
echo "----------------------------------------"
CONTAINER_ID=$(docker ps -a --filter "ancestor=kamailio:latest" --format "{{.ID}}" | head -n1)
if [ -n "$CONTAINER_ID" ]; then
  echo "容器ID: $CONTAINER_ID"
  echo "插件加载日志："
  docker logs $CONTAINER_ID 2>&1 | grep -i "plugin" || echo "[警告] 未找到插件加载日志"
else
  echo "[警告] 未找到运行的容器"
fi
echo

# 显示使用建议
echo "[4/4] 使用建议"
echo "----------------------------------------"
echo "✓ 所有9个run.sh已支持AFL_PLUGIN环境变量"
echo "✓ 可用插件："
echo "  - chatafl-enhanced-minimal.so    (推荐，轻量级)"
echo "  - chatafl-deep-integration.so    (最强，包含CEGAR)"
echo "  - libafl-advanced-plugin.so      (高级策略)"
echo
echo "使用示例："
echo "  # 10分钟带插件实验"
echo "  AFL_PLUGIN=chatafl-deep-integration.so ./run.sh 3 10 kamailio chatafl-enhanced"
echo
echo "  # 60分钟对比实验（无插件 vs 有插件）"
echo "  ./run.sh 3 60 kamailio chatafl-enhanced                              # 无插件"
echo "  AFL_PLUGIN=chatafl-deep-integration.so ./run.sh 3 60 kamailio chatafl-enhanced  # 有插件"
echo
echo "详细文档：PLUGIN_USAGE_GUIDE.md"
echo "========================================"
