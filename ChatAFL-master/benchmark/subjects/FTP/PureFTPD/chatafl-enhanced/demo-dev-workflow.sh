#!/bin/bash
# 开发模式完整演示脚本

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║   ChatAFL-Enhanced 开发模式完整演示                        ║"
echo "╚═══════════════════════════════════════════════════════════╝"
echo ""

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 步骤 1
echo -e "${GREEN}步骤 1: 启动开发容器${NC}"
echo -e "${YELLOW}命令: ./dev-sync.sh start${NC}"
echo ""
echo "这将："
echo "  • 创建容器 chatafl-enhanced-dev"
echo "  • 挂载当前目录到容器的 /opt/aflnet"
echo "  • 保持容器运行状态"
echo ""
read -p "按回车继续演示步骤 2..."

# 步骤 2
clear
echo -e "${GREEN}步骤 2: 模拟代码修改${NC}"
echo -e "${YELLOW}场景: 在 afl-fuzz.c 添加一条调试日志${NC}"
echo ""
echo "在宿主机编辑（VS Code / Vim）："
echo "  vim afl-fuzz.c"
echo ""
echo "添加代码（示例）："
cat << 'EOF'
  // 在主循环开始处添加
  if (cycles_wo_finds == 0) {
      SAYF("[DEBUG] Starting new fuzzing cycle\n");
  }
EOF
echo ""
echo -e "${BLUE}由于使用 Volume 挂载，修改立即同步到容器！${NC}"
echo ""
read -p "按回车继续演示步骤 3..."

# 步骤 3
clear
echo -e "${GREEN}步骤 3: 重新编译${NC}"
echo -e "${YELLOW}命令: ./dev-sync.sh sync${NC}"
echo ""
echo "执行流程："
echo "  1. 检查容器状态 ✓"
echo "  2. 在容器内执行 make clean"
echo "  3. 重新编译所有模块"
echo "  4. 验证二进制文件"
echo "  5. 检查新增模块（llm-cost-tracker, state-graph）"
echo ""
echo "预计耗时: 10-15 秒"
echo ""
read -p "按回车继续演示步骤 4..."

# 步骤 4
clear
echo -e "${GREEN}步骤 4: 测试新编译的二进制${NC}"
echo -e "${YELLOW}命令: ./dev-sync.sh shell${NC}"
echo ""
echo "进入容器后可以："
echo "  • 验证二进制: ./afl-fuzz -h"
echo "  • 检查符号表: nm afl-fuzz | grep DEBUG"
echo "  • 运行快速测试: ./afl-fuzz -i in -o out -- ./target"
echo "  • 查看日志: cat llm-cost-report.txt"
echo ""
echo "退出容器: 输入 exit"
echo ""
read -p "按回车继续演示步骤 5..."

# 步骤 5
clear
echo -e "${GREEN}步骤 5: 自动监控模式（可选）${NC}"
echo -e "${YELLOW}命令: ./dev-sync.sh watch${NC}"
echo ""
echo "功能："
echo "  • 监控 .c、.h、.cc、.cpp 文件变化"
echo "  • 检测到修改时自动触发 make"
echo "  • 实时显示编译输出"
echo ""
echo "示例场景："
echo "  1. 启动监控: ./dev-sync.sh watch"
echo "  2. 在 VS Code 修改并保存 chat-llm.c"
echo "  3. 脚本自动检测并编译"
echo "  4. 10秒后新二进制就绪"
echo ""
echo -e "${BLUE}适合长时间开发会话！${NC}"
echo ""
read -p "按回车查看完整工作流..."

# 完整工作流
clear
echo -e "${GREEN}完整开发工作流示例${NC}"
echo "════════════════════════════════════════════════════════════"
echo ""
echo -e "${YELLOW}# 第一天 - 初始设置${NC}"
echo "cd ChatAFL-Enhanced"
echo "./dev-sync.sh start                  # 启动容器（仅需一次）"
echo ""
echo -e "${YELLOW}# 开发循环（可重复多次）${NC}"
echo "vim afl-fuzz.c                       # 1. 修改代码"
echo "./dev-sync.sh sync                   # 2. 编译（10秒）"
echo "./dev-sync.sh shell                  # 3. 测试"
echo "  └─> ./afl-fuzz -h                  #    验证"
echo "  └─> exit                           #    退出容器"
echo ""
echo -e "${YELLOW}# 修复小问题时（更快）${NC}"
echo "vim chat-llm.c                       # 修复拼写错误"
echo "./dev-sync.sh rebuild                # 快速编译（8秒，无 clean）"
echo ""
echo -e "${YELLOW}# 长时间开发会话${NC}"
echo "./dev-sync.sh watch                  # 启动自动监控"
echo "# 现在只需在 VS Code 保存文件，自动编译！"
echo ""
echo -e "${YELLOW}# 运行完整测试${NC}"
echo "./dev-sync.sh shell"
echo "cd /opt/aflnet"
echo "./afl-fuzz -i tutorials/lightftp/in -o out -N tcp://127.0.0.1/21 ./lightftp"
echo ""
echo -e "${YELLOW}# 结束工作（可选）${NC}"
echo "./dev-sync.sh stop                   # 停止容器（数据保留）"
echo ""
echo "════════════════════════════════════════════════════════════"
echo ""

# 对比表格
echo -e "${GREEN}性能对比${NC}"
echo "┌────────────────┬──────────┬──────────┬──────────┐"
echo "│ 方法           │ 同步时间 │ 编译时间 │ 总耗时   │"
echo "├────────────────┼──────────┼──────────┼──────────┤"
echo "│ setup.sh 重建  │   0秒    │  5-10分  │  5-10分  │"
echo "│ docker cp      │  30秒    │  1-2分   │  2-3分   │"
echo "│ dev-sync sync  │   0秒    │  10-15秒 │  10-15秒 │"
echo "│ dev-sync watch │  自动    │  8-10秒  │  8-10秒  │"
echo "└────────────────┴──────────┴──────────┴──────────┘"
echo ""
echo -e "${GREEN}性能提升: 20-30倍 🚀${NC}"
echo ""

echo "════════════════════════════════════════════════════════════"
echo -e "${BLUE}演示结束！现在可以运行:${NC}"
echo -e "  ${YELLOW}./dev-sync.sh start${NC}   - 开始开发"
echo -e "  ${YELLOW}cat QUICK_DEV_REFERENCE.txt${NC}   - 查看速查表"
echo -e "  ${YELLOW}cat DEV_MODE_GUIDE.md${NC}   - 阅读完整文档"
echo "════════════════════════════════════════════════════════════"
