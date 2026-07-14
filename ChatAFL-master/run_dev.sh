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
    echo "Example: $0 1 30 lightftp loopfuzz"
    echo "Known fuzzers: aflnet,chatafl,chatafl-cl1,chatafl-cl2,loopfuzz,all"
    echo ""
    echo "Volume挂载开发模式："
    echo "  - 本地代码实时挂载到容器"
    echo "  - 修改本地文件后无需重新构建镜像"
    echo "  - 只需重启容器即可测试"
    echo ""
    echo "LLM API key 设置："
    echo "  export KEY=\"sk-...\""
    echo "  ./run_dev.sh 1 20 mosquitto-v2.0.18 loopfuzz"
    exit 1
fi

normalize_fuzzer_list() {
    local raw="$1" item canon out=""
    for item in $(echo "$raw" | tr ',' ' '); do
        case "$item" in
            loopfuzz|LoopFuzz) canon="loopfuzz" ;;
            aflnet|chatafl|chatafl-cl1|chatafl-cl2|all) canon="$item" ;;
            "")
                continue
                ;;
            *)
                echo "[ERROR] Unknown fuzzer: $item" >&2
                echo "[ERROR] Known fuzzers: aflnet,chatafl,chatafl-cl1,chatafl-cl2,loopfuzz,all" >&2
                exit 2
                ;;
        esac
        out="${out:+$out,}$canon"
    done
    if [[ -z "$out" ]]; then
        echo "[ERROR] Empty fuzzer list" >&2
        exit 2
    fi
    echo "$out"
}

validate_target_list() {
    local raw="$1" item
    for item in $(echo "$raw" | tr ',' ' '); do
        case "$item" in
            lightftp|bftpd|proftpd|pure-ftpd|exim|live555|kamailio|forked-daapd|lighttpd1|mosquitto|mosquitto-v2.0.18|mosquitto-v2.1.2|all)
                ;;
            "")
                continue
                ;;
            *)
                echo "[ERROR] Unknown target: $item" >&2
                echo "[ERROR] Known targets: lightftp,bftpd,proftpd,pure-ftpd,exim,live555,kamailio,forked-daapd,lighttpd1,mosquitto,mosquitto-v2.0.18,mosquitto-v2.1.2,all" >&2
                exit 2
                ;;
        esac
    done
}

validate_target_list "$TARGET_LIST"
FUZZER_LIST="$(normalize_fuzzer_list "$FUZZER_LIST")" || exit $?
export FUZZER_LIST

# ── LLM API Key 验证 ──────────────────────────────────────────────
if [[ -z "${KEY}" ]]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║  ⚠  WARNING: KEY 环境变量为空！                             ║"
    echo "║                                                            ║"
    echo "║  LLM 功能（语法假设、种子富集、高原突破）将全部失效。        ║"
    echo "║  LoopFuzz 将回退到纯硬编码模式运行。                     ║"
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

# ── 全效果模式默认值 ──────────────────────────────────────────────────
# run_dev.sh 独立运行时（非从 run_ablation.sh 调用），默认启用全部策略：
#   Hypothesis 语法生成 ON，自适应阈值 ON（初始=512），CEGAR ON，
#   Frontier bonus ON，State-aware prompt ON。
# 这四个 CHATAFL_NO_* 开关仅在消融实验中被 run_ablation.sh 显式设置。
# run_ablation.sh 在调用前 export CHATAFL_FROM_ABLATION=1，
# 此时 run_dev.sh 完全透传调用者已设置的变量，不做任何覆盖。
if [ "${CHATAFL_FROM_ABLATION:-0}" != "1" ]; then
    # 独立运行 = 全效果：不设置任何 NO_* 标志，全部策略生效
    # 自适应 plateau 阈值默认从 512 开始（与 ChatAFL 基线对齐）
    :
fi

# 使用开发版本的执行脚本（带Volume挂载）
# 透传全部消融变量到 profuzzbench，确保 run_ablation.sh 设置的
# NO_REFINEMENT / NO_FRONTIER / NO_ADAPTIVE / NO_STATE_PROMPT / ABLATION_THRESHOLD
# 以及 CHATAFL_HYPOTHESIS（wo_all 消融组设为 0）无一遗漏地进入 Docker 容器。
PFBENCH=$PFBENCH PATH=$PATH NUM_CONTAINERS=$NUM_CONTAINERS TIMEOUT=$TIMEOUT \
  SKIPCOUNT=$SKIPCOUNT TEST_TIMEOUT=$TEST_TIMEOUT KEY="$KEY" PROJECT_ROOT="$PROJECT_ROOT" \
  CHATAFL_HYPOTHESIS="${CHATAFL_HYPOTHESIS:-}" \
  CHATAFL_NO_REFINEMENT="${CHATAFL_NO_REFINEMENT:-}" \
  CHATAFL_NO_FRONTIER="${CHATAFL_NO_FRONTIER:-}" \
  CHATAFL_NO_ADAPTIVE="${CHATAFL_NO_ADAPTIVE:-}" \
  CHATAFL_NO_STATE_PROMPT="${CHATAFL_NO_STATE_PROMPT:-}" \
  CHATAFL_NO_ADMISSION="${CHATAFL_NO_ADMISSION:-}" \
  CHATAFL_ADMISSION_LOG="${CHATAFL_ADMISSION_LOG:-}" \
  CHATAFL_ABLATION_THRESHOLD="${CHATAFL_ABLATION_THRESHOLD:-}" \
  CHATAFL_MAX_TOKENS="${CHATAFL_MAX_TOKENS:-}" \
  scripts/execution/profuzzbench_exec_all_dev.sh ${TARGET_LIST} ${FUZZER_LIST}
