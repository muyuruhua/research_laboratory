#!/bin/bash

# ── StateAFL 扩展（开闭：新增独立用法与同步段，不改下方既有流程）──────────
# 用法：
#   ./setup.sh           原有全量流程（KEY 检查 + fuzzer 同步 + 全部镜像），
#                        并追加构建全部 *-stateafl 镜像
#   ./setup.sh stateafl  仅同步 stateafl 源码并构建 *-stateafl 镜像（无需 KEY）
#   FORCE=0 ./setup.sh stateafl  同上，但已存在的 *-stateafl 镜像跳过（幂等）

# 同步 stateafl 源码到含 Dockerfile-stateafl 的 subject 目录（构建上下文需要；
# 以 Dockerfile-stateafl 的存在为准——新增目标放入该文件即自动纳入同步与构建）
sync_stateafl_sources() {
  for dockerfile in ./benchmark/subjects/*/*/Dockerfile-stateafl; do
    [ -f "$dockerfile" ] || continue
    subject="$(dirname "$dockerfile")"
    rm -rf $subject/stateafl
    cp -r stateafl $subject/stateafl
    rm -rf $subject/stateafl/.git
  done;
}

if [ "${1:-}" = "stateafl" ]; then
    sync_stateafl_sources
    PFBENCH="$PWD/benchmark"
    cd $PFBENCH
    PFBENCH=$PFBENCH scripts/execution/profuzzbench_build_stateafl.sh
    exit $?
fi

if [ -z $KEY ]; then
    echo "NO OPENAI API KEY PROVIDED! Please set the KEY environment variable"
    exit 0
fi

# Update the openAI key
for x in ChatAFL ChatAFL-CL1 ChatAFL-CL2 LoopFuzz;
do
  sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$KEY\"/" $x/chat-llm.h
done

# Copy the different versions of ChatAFL to the benchmark directories
for subject in ./benchmark/subjects/*/*; do
  rm -r $subject/aflnet 2>&1 >/dev/null
  cp -r aflnet $subject/aflnet

  rm -r $subject/chatafl 2>&1 >/dev/null
  cp -r ChatAFL $subject/chatafl
  
  rm -r $subject/chatafl-cl1 2>&1 >/dev/null
  cp -r ChatAFL-CL1 $subject/chatafl-cl1
  
  rm -r $subject/chatafl-cl2 2>&1 >/dev/null
  cp -r ChatAFL-CL2 $subject/chatafl-cl2
  
  rm -r $subject/LoopFuzz $subject/loopfuzz 2>&1 >/dev/null
  cp -r LoopFuzz $subject/loopfuzz
done;

# StateAFL 源码同步（仅覆盖含 Dockerfile-stateafl 的目标；镜像由
# profuzzbench_build_all.sh 末尾追加的 stateafl 构建段统一构建）
sync_stateafl_sources

# Build the docker images

PFBENCH="$PWD/benchmark"
cd $PFBENCH
PFBENCH=$PFBENCH scripts/execution/profuzzbench_build_all.sh
