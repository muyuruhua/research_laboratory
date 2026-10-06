# LoopFuzz v3 全优化验证命令清单（一条命令版）

> 生成日期：2026-10-06。每条验证命令均为单行 export 链形式，可直接复制执行。
> 其余 8 个 target：把 `bftpd` 换成 `exim / live555 / kamailio / lighttpd1 / pure-ftpd /
> forked-daapd / lightftp / proftpd` 即可。
>
> 分层说明：命令 1 = 真实网关满效果三 arm（主命令）；命令 2/3 = 机制层（mock + 阈值 8，
> 验证 admission/provisional/forced 路径；默认阈值下 plateau 在短窗口不触发，
> 机制验证必须靠它们）。mock run 只用于机制验证，数据不可用于论文。

---

## 命令 1【主命令】真实网关 · 满效果 C/D/E 三 arm 并行（120 分钟 ×3，墙钟 ~135 min）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY="sk-vjJeCI9TNGvDkwPkQYdW0pT2SuWgEPFYUK7qXVcHyUV0QmYI" && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_TIMEOUT_MS=300000 && sudo -E ./run_ablation.sh bftpd 1 120 -g direct,gated_fixed,calibrated
```

> - `CHATAFL_LLM_TIMEOUT_MS=300000` 必须带：真实网关长生成经常超默认 120s
>   （三次实测，enrichment 为此停滞 25–40 分钟）。
> - `sudo -E` 可用但非必需（本机在 docker 组内可免 sudo；sudo 需交互输密码）。
> - 三容器并行 ~18GB；grammar/enrichment 真实耗时 25–40 分钟属正常。

## 命令 2【可选·机制层 arm D】mock + fixed8 组（45 分钟，墙钟 ~55 min）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && setsid nohup python3 $PWD/loopfuzz/revision_20260920/llm_mock.py >/tmp/llm_mock.log 2>&1 & sleep 1 && cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY=sk-mock && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_BASE=http://172.17.0.1:8099/v1/chat/completions && ./run_ablation.sh bftpd 1 45 -g fixed8 && pkill -f llm_mock.py
```

> fixed8 = 满效果 arm D + 固定 plateau 阈值 8（组自带变量，容器 env 已 docker inspect 实证）。
> 阈值必须是组自带变量——父 shell 导出会被 run_ablation 的 arm 隔离 unset 吞掉
> （2026-10-05 两次消融 e2e 零候选的真实根因）。预期：候选数十个、provisional>0、
> decision 先行、0 trial 原生入队、descendant_execs≤64。

## 命令 3【可选·机制层 arm C】mock + 直通反事实（30 分钟，墙钟 ~40 min）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && setsid nohup python3 $PWD/loopfuzz/revision_20260920/llm_mock.py >/tmp/llm_mock.log 2>&1 & sleep 1 && cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && export KEY=sk-mock && export SKIPCOUNT=100 && export CHATAFL_MAX_TOKENS=4096 && export CHATAFL_LLM_BASE=http://172.17.0.1:8099/v1/chat/completions && export CHATAFL_NO_ADMISSION=1 && export CHATAFL_NO_ADAPTIVE=1 && export CHATAFL_ABLATION_THRESHOLD=8 && ./run_dev.sh 1 30 bftpd loopfuzz && pkill -f llm_mock.py
```

> run_dev.sh 路径白名单透传导出（已实证）。预期：run-config start `arm=loopfuzz-direct`
> （Fix1 强证据）且 `admission_forced_promo>0`（直通 force-admit 路径）。

---

## 审计（每条命令结束后执行；对命令 1 的三个 arm 与命令 2/3 各跑一遍）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && rm -rf /tmp/v && mkdir -p /tmp/v

# 解包（命令 1 的三 arm + 命令 2 的 fixed8；命令 3 的目录从其日志提取）
for L in direct gated_fixed calibrated fixed8; do
  D=$(ls -d ablation/results-bftpd_ablation_${L}_* | tail -1)
  mkdir -p /tmp/v/$L && sudo tar xzf $D/out-bftpd-loopfuzz_1.tar.gz -C /tmp/v/$L
done
DC=$(grep -o 'results-bftpd_[0-9A-Za-z_-]*' /tmp/v_mechC.log 2>/dev/null | head -1)   # 若跑了命令 3
[ -n "$DC" ] && mkdir -p /tmp/v/devC && sudo tar xzf "benchmark/$DC/out-bftpd-loopfuzz_1.tar.gz" -C /tmp/v/devC

# 四条审计逐目录执行
for O in /tmp/v/*/out-bftpd-loopfuzz; do
  echo "==================== $O ===================="
  python3 loopfuzz/revision_20260920/audit_loopfuzz.py $O | tail -18          # A. Fix1-7 硬不变量
  python3 loopfuzz/revision_20260920/p03_canonical_coverage.py $O --check-monotone | head -6   # B. P0-3
  python3 loopfuzz/revision_20260920/rq1_calibration_analysis.py $O | tail -10                # C. P0-5+P0-4
  head -1 $O/run-config.jsonl | python3 -c "
import json,sys; d=json.loads(sys.stdin.read())
for k in ['arm','no_admission','calibration','fuzzer_sha256','target_sha256','seeds_sha256',
          'config_hash','image_digest','episode_energy_cap','code_reward_semantics']:
    print(f'  {k:22s}: {str(d.get(k))[:60]}')"                                    # D. 身份固化
  echo "  llm-calls: $(wc -l < $O/llm-calls.jsonl) rows; cov header: $(head -1 $O/cov_over_time.csv)"
done

# 跨 arm 单因素一致性（P0-2 核心）：三 arm 哈希必须完全一致
for L in direct gated_fixed calibrated; do
  head -1 /tmp/v/$L/out-bftpd-loopfuzz/run-config.jsonl \
    | python3 -c "import json,sys;d=json.loads(sys.stdin.read());print(d['arm'],d['fuzzer_sha256'][:16],d['seeds_sha256'][:16],d['image_digest'][:20])"
done

# arm E 后验调度（无需 LLM 候选，episode 级即可验证）
python3 -c "
import json
th=[json.loads(l).get('sampled_theta') for l in open('/tmp/v/calibrated/out-bftpd-loopfuzz/state-episodes.jsonl')]
th=[t for t in th if t is not None and t>=0]
print('distinct sampled_theta values:', len(set(th)), '(>1 = Thompson 采样在驱动选择)')"
```

---

## 通过标准

| 层 | 通过标准 |
|---|---|
| 命令 1（三 arm） | audit 硬不变量全过（episode 能量≤512、reward 口径、完成度门控、cov v3 idx/终值行/audit）；**候选 0–2 属预期**（默认阈值 120 分钟窗口不触发 plateau，非失败）；llm-calls 为真实网关记录（served model 非空、延迟最高 ~300s）；跨 arm 三哈希一致、arm 字段正确；E `calibration=1` 且 sampled_theta 多值 |
| 命令 2（fixed8） | `ALL HARD INVARIANTS PASS`；**provisional>0** 且门控 P∧U∧R∧¬G_code∧G_state；decision 先行；0 trial 原生入队；descendant_execs≤64 |
| 命令 3（devC） | run-config start `arm=loopfuzz-direct`；`admission_forced_promo>0` |
| 全部 | p03：`decreases after rebuild: 0`、短 run 判 censored；rq1：RQ1 条件概率 + BS 三基线 + 裁决行正常输出（NO 亦通过——P0-4 诚实裁决） |

## 可选加验

```bash
# P0-3 旧数据一次性复核（无需新 run）
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master && python3 loopfuzz/revision_20260920/p03_canonical_coverage.py --legacy-json loopfuzz/revision_20260920/filled_run_evidence_20260930.json --check-monotone
# 期望：642 runs，raw decreases 199 → 0，642/642 support@24h
```

## 边界与提醒

1. 满效果层候选为 0 是预期（论文 D-arm 候选全部来自 24h 饱和期）；机制靠命令 2/3。
2. durable promotion（新edge∧U∧R 同时满足）与 provisional censor（停机时仍存活）在短窗口
   可能不出现，属窗口限制而非缺陷，24h 正式 run 必然覆盖。
3. sudo 运行时结果目录归 root，审计解包需 `sudo tar`（上方命令已带）。
4. **机制验证 ≠ 正式实验**：论文正式数据 = 真实网关 + 满效果 + 1580 分钟（先 `git commit`
   固化 fuzzer_commit）：`./run_ablation.sh <T> 1 1580 -g direct,gated_fixed,calibrated`。

## 附：脚本索引

`LoopFuzz/afl-fuzz.c`（Fix1-7+身份固化）· `LoopFuzz/chat-llm.c/h`（llm-calls+cap 强制）·
`LoopFuzz/sha256.c/h`（哈希）· `benchmark/subjects/*/*/cov_script.sh`×9（cov v3）·
`run_ablation.sh`（编排层，含 fixed8/16/32/64 组）· `loopfuzz/revision_20260920/`
{audit_loopfuzz, p03_canonical_coverage, rq1_calibration_analysis, llm_mock}.py
