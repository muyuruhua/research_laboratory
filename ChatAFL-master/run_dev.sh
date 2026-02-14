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
    exit 1
fi

# 使用开发版本的执行脚本（带Volume挂载）
PFBENCH=$PFBENCH PATH=$PATH NUM_CONTAINERS=$NUM_CONTAINERS TIMEOUT=$TIMEOUT \
  SKIPCOUNT=$SKIPCOUNT TEST_TIMEOUT=$TEST_TIMEOUT KEY="$KEY" PROJECT_ROOT="$PROJECT_ROOT" \
  scripts/execution/profuzzbench_exec_all_dev.sh ${TARGET_LIST} ${FUZZER_LIST}
