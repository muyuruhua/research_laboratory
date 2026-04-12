#!/bin/bash

# Volume挂载开发模式运行脚本
# 用法：./run_dev.sh NUM_CONTAINERS TIMEOUT_MINUTES TARGET FUZZER

PFBENCH="$PWD/benchmark"
cd $PFBENCH

PATH=$PATH:$PFBENCH/scripts/execution:$PFBENCH/scripts/analysis
NUM_CONTAINERS=$1
TIMEOUT=$(( ${2:-1440} * 60))
SKIPCOUNT="${SKIPCOUNT:-1}"
TEST_TIMEOUT="${TEST_TIMEOUT:-5000}"

export TARGET_LIST=$3
export FUZZER_LIST=$4
export PROJECT_ROOT="$PFBENCH/.."  # ChatAFL-master根目录

if [[ "x$NUM_CONTAINERS" == "x" ]] || [[ "x$TIMEOUT" == "x" ]] || [[ "x$TARGET_LIST" == "x" ]] || [[ "x$FUZZER_LIST" == "x" ]]
then
    echo "Usage: $0 NUM_CONTAINERS TIMEOUT TARGET FUZZER"
    echo "Example: $0 1 30 lightftp chatafl-opt"
    echo ""
    echo "Volume挂载开发模式："
    echo "  - 本地代码实时挂载到容器"
    echo "  - 修改本地文件后无需重新构建镜像"
    echo "  - 只需重启容器即可测试"
    echo ""
    echo "LLM API key 设置："
    echo "  export KEY=\"sk-...\""
    echo "  ./run_dev.sh 1 20 mosquitto-v2.0.18 chatafl-opt"
    exit 1
fi

# ── LLM API Key 验证 ──────────────────────────────────────────────
if [[ -z "${KEY}" ]]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ⚠  WARNING: KEY 环境变量为空！                             ║"
    echo "║                                                            ║"
    echo "║  LLM 功能（语法假设、种子富集、高原突破）将全部失效。        ║"
    echo "║  ChatAFL-Opt 将回退到纯硬编码模式运行。                     ║"
    echo "║                                                            ║"
    echo "║  设置方法:  export KEY=\"sk-...\"                            ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    read -t 10 -p "继续运行（无LLM模式）？[y/N] " confirm
    if [[ "${confirm}" != "y" && "${confirm}" != "Y" ]]; then
        echo "已取消。请先设置 KEY 后重试。"
        exit 1
    fi
    echo "[WARN] 以无LLM模式继续运行..."
else
    echo "[✓] KEY 已设置 (长度=${#KEY}, 前缀=${KEY:0:8}...)"
fi

# 使用开发版本的执行脚本（带Volume挂载）
PFBENCH=$PFBENCH PATH=$PATH NUM_CONTAINERS=$NUM_CONTAINERS TIMEOUT=$TIMEOUT \
  SKIPCOUNT=$SKIPCOUNT TEST_TIMEOUT=$TEST_TIMEOUT KEY="$KEY" PROJECT_ROOT="$PROJECT_ROOT" \
  scripts/execution/profuzzbench_exec_all_dev.sh ${TARGET_LIST} ${FUZZER_LIST}
