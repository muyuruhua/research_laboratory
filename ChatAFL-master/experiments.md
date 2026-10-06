# LoopFuzz v3 全优化 120 分钟验证命令清单（真实网关版，无 mock）

> 生成日期：2026-10-06。代码基线：commit `dffc7cefb` + `1a0fddc0e`（含 cov_script v3 重打补丁、
> cap 排序修复、PATH 目标哈希解析）。**全部命令使用真实 LLM 网关，不用 mock。**
> 其余 8 个 target：把 `bftpd` 换成 `exim / live555 / kamailio / lighttpd1 / pure-ftpd /
> forked-daapd / lightftp / proftpd`（注意：forked-daapd 的 cov 重放目前会中途终止，
> 属该 target 专项问题，其 cov 字段验证结果暂不可用）。
>
> **真实网关事实（决定预期）**：① grammar+enrichment 真实耗时 25–40 分钟（含在 120 分钟内，
> 属正常）；② `CHATAFL_LLM_TIMEOUT_MS=300000` 必须带（默认 120s 在今天网关下大量超时）；
> ③ 默认自适应阈值（512–700）下 120 分钟 plateau 几乎不触发（实测 0–2 个候选）——
> 满效果层的候选数为 0 是**预期现象**，机制验证靠命令 2/3 的阈值强制层（同样真实网关）。

---

## 命令 1【主命令】真实网关 · 满效果 C/D/E 三 arm 并行（120 分钟 ×3，墙钟 ~135 min）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh bftpd 1 120 -g direct,gated_fixed,calibrated
```

> 与 10-06 上午已跑过的同命令相比，本次将首次覆盖：重打补丁后的 cov_script（idx 全程严格
> 递增而非队列段常数）、新 commit 的 `fuzzer_commit` 字段。三容器并行 ~18GB。
> `sudo -E` 可用但非必需（docker 组权限即可；sudo 需交互密码，且结果目录归 root、解包要 `sudo tar`）。

## 命令 2【机制层·arm D】真实网关 + fixed8 组（60 分钟，可与命令 1 并行发起）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh bftpd 1 60 -g fixed8
```

> fixed8 = 满效果 arm D + 固定 plateau 阈值 8（组自带变量——父 shell 导出的阈值会被
> run_ablation 的 arm 隔离 unset 吞掉，这是实测过的坑）。真实网关下 plateau 响应延迟
> 最高 ~67s（300s 上限内），fuzz ~30 分钟（enrichment 占 ~25）预期产出数十个真实候选 →
> 验证 trial 门控、decision 先行、provisional admit/expire。已知边界：provisional 在
> 600+ 队列下可能 30s TTL 内未被调度即 expire（desc_execs=0，已两次复现——本身是论文
> §4.3 的实证发现）；convert/budget-expire 更可能出现在 24h 正式 run。

## 命令 3【机制层·arm C】真实网关 + run_dev 导出（30 分钟，可与命令 1 并行发起）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && export CHATAFL_NO_ADMISSION=1 && export CHATAFL_NO_ADAPTIVE=1 && export CHATAFL_ABLATION_THRESHOLD=8 && sudo -E ./run_dev.sh 1 30 bftpd loopfuzz
```

> run_dev.sh 路径白名单透传导出（消融组隔离不适用于此路径）。预期：run-config start
> `arm=loopfuzz-direct`（Fix1 强证据）且 `admission_forced_promo>0`（直通 force-admit 路径）。

---

## 审计（每条命令结束后执行；sudo 跑的 run 解包需 sudo tar）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && rm -rf /tmp/v && mkdir -p /tmp/v

# 解包：命令 1 三 arm + 命令 2 fixed8；命令 3 目录从其终端输出/日志提取（与其它 run_dev run 同命名空间）
for L in direct gated_fixed calibrated fixed8; do
  D=$(ls -d ablation/results-bftpd_ablation_${L}_202610* | tail -1)
  mkdir -p /tmp/v/$L && sudo tar xzf $D/out-bftpd-loopfuzz_1.tar.gz -C /tmp/v/$L
done
sudo chown -R $(id -u):$(id -g) /tmp/v

# 四条审计逐目录执行
for O in /tmp/v/direct/out-bftpd-loopfuzz /tmp/v/gated_fixed/out-bftpd-loopfuzz \
         /tmp/v/calibrated/out-bftpd-loopfuzz /tmp/v/fixed8/out-bftpd-loopfuzz; do
  echo "==================== $O ===================="
  python3 loopfuzz/revision_20260920/audit_loopfuzz.py $O | tail -18            # A. Fix1-7 硬不变量（arm-aware）
  python3 loopfuzz/revision_20260920/p03_canonical_coverage.py $O --check-monotone | head -6   # B. P0-3
  python3 loopfuzz/revision_20260920/rq1_calibration_analysis.py $O | tail -10                # C. P0-5+P0-4
  python3 loopfuzz/revision_20260920/bitmap_source_mapping.py $O --window-min 10 | tail -4    # D. bitmap↔source 映射
  head -1 $O/run-config.jsonl | python3 -c "
import json,sys; d=json.loads(sys.stdin.read())
for k in ['arm','fuzzer_sha256','target_sha256','seeds_sha256','config_hash','image_digest',
          'fuzzer_commit','episode_energy_cap','code_reward_semantics','llm_total_call_cap']:
    print(f'  {k:22s}: {str(d.get(k))[:60]}')"
  echo "  llm-calls: $(wc -l < $O/llm-calls.jsonl) rows; cov header: $(head -1 $O/cov_over_time.csv)"
done

# 跨 arm 单因素一致性（P0-2 核心）：fuzzer/seeds/image 哈希三 arm 必须完全一致、
# fuzzer_commit 必须等于已发布 commit、config_hash 仅随 arm 变化
for L in direct gated_fixed calibrated; do
  head -1 /tmp/v/$L/out-bftpd-loopfuzz/run-config.jsonl \
    | python3 -c "import json,sys;d=json.loads(sys.stdin.read());print(d['arm'],d['fuzzer_commit'],d['fuzzer_sha256'][:16],d['seeds_sha256'][:16],d['image_digest'][:20])"
done

# cov v3 三件套（重打补丁后 idx 应全程严格递增，含队列段）
O=/tmp/v/gated_fixed/out-bftpd-loopfuzz
awk -F, 'NR>1{print $6}' $O/cov_over_time.csv | sort -n -c && echo "idx strictly increasing: YES"
tail -1 $O/cov_over_time.csv | cut -d, -f1
python3 -c "import json;print('campaign_end:', json.load(open('$O/cov_over_time.csv.audit'))['campaign_end'])"

# arm E 后验记账（采样驱动需 24h，见边界说明）
grep -E "^(arm|calibration)" /tmp/v/calibrated/out-bftpd-loopfuzz/fuzzer_stats
```

## 通过标准

| 层 | 通过标准 |
|---|---|
| 命令 1（三 arm） | audit 硬不变量全过（episode 能量≤512 且多数恰封顶、reward 口径、零变异/中断不更新后验、cov v3）；**候选 0–2 属预期**；`fuzzer_commit` == 提交的 commit；四哈希非 unknown 且三 arm 一致；llm-calls 为真实网关记录（served model、延迟最高 ~300s）；E `calibration=1` |
| 命令 2（fixed8） | 候选数十个；`0 executed trial 原生入队`；decision 先行；provisional>0 且门控 P∧U∧R∧¬G_code∧G_state（TTL 内未调度致 desc_execs=0 属已知边界）；descendant_execs≤64 |
| 命令 3（arm C） | start `arm=loopfuzz-direct`；`admission_forced_promo>0` |
| 全部 | p03：`decreases after rebuild: 0`、2h run 判 censored；idx 严格递增；末行时间==campaign_end；rq1 三基线裁决正常输出；映射 r 与比率正常输出 |

## 诚实边界（真实网关 120 分钟内验证不到的）

1. **E 的 Thompson 采样驱动**：bftpd ~235 states × 5 轮 ROUND_ROBIN 热身 ≈ 需 1175 次
   selection，120 分钟仅 ~50 episodes → 结构性未激活（D/E 调度差异尚未生效），只能 24h 验证。
2. **durable promotion**（候选需同时满足 新edge∧U∧R）与 provisional convert/budget-expire：
   短窗概率低/受 TTL-调度延迟限制，24h 正式 run 覆盖。
3. **forked-daapd**：cov 重放中途终止（target 专项问题，待查），其 cov 字段不作为判据。
4. 机制验证数据（fixed8/arm C）因阈值偏离论文正式配置，**只用于机制确认，不进论文数据集**。

## 可选加验（真实网关）

```bash
# cap 强制：5 次真实调用后全部拒发（注意这会饿死后续 LLM 功能，仅作微验证）
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && export CHATAFL_LLM_TOTAL_CALL_CAP=5 && sudo -E ./run_dev.sh 1 8 bftpd loopfuzz
# 验证：grep -c cap-refused <out>/llm-calls.jsonl > 0（enrichment 多线程下 ok 数可能略超 5，属良性竞态）
```

## 附：脚本索引（均在 repo 内，commit dffc7cefb + 1a0fddc0e + 3c1704a70）

`LoopFuzz/afl-fuzz.c`（Fix1-7+身份固化+PATH 哈希）· `LoopFuzz/chat-llm.c/h`（llm-calls+cap 强制+原文归档）·
`LoopFuzz/sha256.c/h` · `benchmark/subjects/*/*/cov_script.sh`×9（v3 重打：严格递增 idx）·
`run_ablation.sh`（编排层，含 fixed8/16/32/64/fixed8ttl 组 + 批次时间戳打印）· `run_dev.sh`
（结果目录时间戳打印 + env 透传）· `benchmark/scripts/execution/profuzzbench_exec_common_dev.sh`
（env 透传+镜像 digest）· `loopfuzz/revision_20260920/`{audit_loopfuzz, p03_canonical_coverage,
rq1_calibration_analysis, bitmap_source_mapping, llm_mock}.py

---

## 正式实验：九目标 × C/D/E × 1580 min + γ 敏感性（论文 §六 Table 5 完整矩阵）

> 每条命令 = 紧凑一条格式（与本文"命令 1"同结构，仅 `120` → `1580`）。
> 三个 arm 并行（`ABLATION_PARALLEL=6`），墙钟 ~26.3h/目标。
> **建议先 `git commit` 确认代码基线**，再开始跑。**run_dev.sh 与 run_ablation.sh
> 均会在开头打印结果目录时间戳**——事后用该时间戳检索 `ablation/results-*/` 或 `benchmark/results-*/`。

### C/D/E 三 arm（每目标一条命令）

```bash
# ① exim
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh exim 1 1580 -g direct,gated_fixed,calibrated
# ② live555
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh live555 1 1580 -g direct,gated_fixed,calibrated
# ③ kamailio
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh kamailio 1 1580 -g direct,gated_fixed,calibrated
# ④ lighttpd1
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh lighttpd1 1 1580 -g direct,gated_fixed,calibrated
# ⑤ pure-ftpd
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh pure-ftpd 1 1580 -g direct,gated_fixed,calibrated
# ⑥ forked-daapd
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh forked-daapd 1 1580 -g direct,gated_fixed,calibrated
# ⑦ lightftp
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh lightftp 1 1580 -g direct,gated_fixed,calibrated
# ⑧ bftpd
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh bftpd 1 1580 -g direct,gated_fixed,calibrated
# ⑨ proftpd
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh proftpd 1 1580 -g direct,gated_fixed,calibrated
```

### γ 敏感性（cal_gamma099 / cal_gamma100，每目标一条命令）

```bash
# ① exim
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh exim 1 1580 -g calibrated,cal_gamma099,cal_gamma100
# ② live555
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh live555 1 1580 -g calibrated,cal_gamma099,cal_gamma100
# ③ kamailio
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh kamailio 1 1580 -g calibrated,cal_gamma099,cal_gamma100
# ④ lighttpd1
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh lighttpd1 1 1580 -g calibrated,cal_gamma099,cal_gamma100
# ⑤ pure-ftpd
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh pure-ftpd 1 1580 -g calibrated,cal_gamma099,cal_gamma100
# ⑥ forked-daapd
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh forked-daapd 1 1580 -g calibrated,cal_gamma099,cal_gamma100
# ⑦ lightftp
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh lightftp 1 1580 -g calibrated,cal_gamma099,cal_gamma100
# ⑧ bftpd
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh bftpd 1 1580 -g calibrated,cal_gamma099,cal_gamma100
# ⑨ proftpd
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh proftpd 1 1580 -g calibrated,cal_gamma099,cal_gamma100
```

### 串行一行版（拷进终端自动循环全部 9 目标）

```bash
# C/D/E 三 arm（~237h ≈ 10 天）
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && for T in exim live555 kamailio lighttpd1 pure-ftpd forked-daapd lightftp bftpd proftpd; do echo "===== TARGET: $T ====="; sudo -E ./run_ablation.sh $T 1 1580 -g direct,gated_fixed,calibrated; done

# γ 敏感性（~237h ≈ 10 天）
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && for T in exim live555 kamailio lighttpd1 pure-ftpd forked-daapd lightftp bftpd proftpd; do echo "===== TARGET: $T ====="; sudo -E ./run_ablation.sh $T 1 1580 -g calibrated,cal_gamma099,cal_gamma100; done
```

### 每个 run 结束后：审计命令

```bash
# 解包（按开头打印的时间戳检索）
T=<目标名>; L=<arm 标签>; TS=<时间戳前 8 位，如 20261007>
D=$(ls -d ablation/results-${T}_ablation_${L}_${TS}T* | tail -1)
rm -rf /tmp/a && mkdir /tmp/a && sudo tar xzf $D/out-${T}-loopfuzz_1.tar.gz -C /tmp/a && sudo chown -R $(id -u):$(id -g) /tmp/a
O=/tmp/a/out-${T}-loopfuzz
python3 loopfuzz/revision_20260920/audit_loopfuzz.py $O | tail -18
python3 loopfuzz/revision_20260920/p03_canonical_coverage.py $O --check-monotone | head -6
python3 loopfuzz/revision_20260920/rq1_calibration_analysis.py $O | tail -10
python3 loopfuzz/revision_20260920/bitmap_source_mapping.py $O --window-min 30 | tail -4
```

### 算力预算（论文 §六 Table 5 设计值）

| 阶段 | run 数 | 每 run | 总时长 |
|---|---|---|---|
| C/D/E（3 arm × 9 目标 × 1 run） | 27 | 26.3h | ~710h ≈ 30 天 |
| γ 敏感性（3 组 × 9 目标 × 1 run） | 27 | 26.3h | ~710h ≈ 30 天 |
| **合计** | **54** | | **~1420h ≈ 59 天（串行）** |

> 论文设计为每 arm 每 target 10 runs（共 540 runs），算力允许时按上述命令把 `1` 改为 `10`。
