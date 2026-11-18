# 修复与验证清单

> 16:23更新：紧邻cap5000批次的10条Exim断连变异输入已按证据分类解决。根因实测：havoc变异产生≥3条非法命令，Exim默认`smtp_max_synprot_errors`计满后以`500 Too many syntax or protocol errors`+FIN正常结束会话（fuzz/回放配置一致，客户端与账本无异常）——"每条输入全部帧送达"对SMTP变异语料是不可满足判据。修复在审计侧：`audit_smoke.py`新增服务端拒绝分类，仅当帧账本证明有序关闭且全部已试帧完整送达、hash锚定的回放转录含服务器终止响应（≥1条前置4xx/5xx）时，该输入记为`server_rejected`仍判incomplete、归档`coverage_complete=false`不变；无证据或与其他异常并存仍判死。新增正反例测试，单测73/73。原失败审计与诊断已另存（`audit_smoke.strict-failure-retained.log`），12个归档/hash逐字节未动、未重跑campaign，同命令重审计exit0：375项PASS、10条全部带证据逐条列出；正向32-cap批次回归exit0不变。仍不能称全部变异回放通过（10条如实为server-rejected incomplete）。

> 12:51最新更新：按用户要求仅验证mock，真实网关由用户手动执行。新增共享LLM预算和launcher传参修复；正向Exim四Q1臂各三重复12路并行，目标cap32／LLM cap8，87.166秒完成；12实际exit0、非OOM，严格审计93/93、93/93、93/93、96/96，384次执行/reset/charged、24有效种子完整回放168帧、96campaign请求加12启动预检逐次对账全部通过。LLM API22/22、共享预算11/11、mock审计69/69通过。紧邻的目标cap5000批次中9/12归档有10条Exim协议错误断连输入，严格失败保留（16:23已按证据分类解决，见上方更新）；不能称全部变异回放通过。权威结果及适用范围见 [本轮终验报告](next_closure_20261117T0231Z/REPORT.md)。下文历史表格保持其对应范围。

2026-11-17，北京时间。下列历史容器清点快照为09:41:41；其后已执行新的诊断及Exim限时工程实验，结果以上方12:51终验更新及本轮报告为准。

不能将“ProFTPD q1d1 单次快速补跑通过”扩大为“全部问题修复”。此前只报告该重复，遗漏了其他目标的 Q1 失败与未完成结果。旧总报告也不是最新修复回放的完整清点。

状态定义：**通过**仅覆盖列明的证据范围；**部分通过**表示已有修复或子集验证但尚缺验收；**未通过**表示现有证据存在明确失败；**未验证**表示尚无足够证据。正常退出、完整回放、机制触发、效果改善是不同检查项。

## 1. 修复代码与运行管线

| ID | 检查项 | 当前状态与证据 | 完成条件 |
| --- | --- | --- | --- |
| C01 | Q1 预算读取、缺失/重复文件拒绝、配置与统计一致性 | 此前 12 项正反例记录通过；本轮未复跑。代码：`verify_q1_repeat.py`、`test_q1_verify_negatives.py` | 验证器通过不替代实际归档验收；每个纳入结果的重复均需通过身份和账本检查 |
| C02 | Q1 target/arm/policy/code-retain/campaign 身份与批次绑定 | 已有 `verify_q1_identity.py` 和 Python 编排器固定目录/唯一 campaign 检查；部分实际批次仍缺重复或报告 | 不以 glob 选取旧样本替代缺项；每个批次输出逐重复身份与终态审计 |
| C03 | 调用配额与执行起止账本 | 本轮Exim12重复共1094对执行起止/reset/charged一致，campaign-final各一条；原单次q1d1的3748对证据保留，通过范围限所测批次 | 对纳入批次的其他重复逐一核验；记录 configured/effective cap、实际 charged、idle/reflow 与停止原因 |
| C04 | 15 分钟截止与收尾时间 | 本轮12重复并行fuzz60秒、总上限300秒，实际141.32秒、12exit0非OOM，四launcher正常收尾；此前失败截止保留 | 其他实际启动入口也必须给回放、统计与归档留时间，不能以外层杀停后缺账本视作成功 |
| C05 | 32 条快速回放上限 | 已实现仅 smoke 可启用；最新结果明确 `replay_truncated=true`、`coverage_complete=false` | 快速验证可通过；正式覆盖终点需回放该结果的全部保存语料并复核，不要求额外 fuzz |
| C06 | 独立任务并行与资源准入 | 本轮实例隔离控制器9/9回归，四臂及12容器实际并行完成、精确归属与清理，无误停；此前24误停失败保留 | 后续使用该入口，审计并发日志与资源预留；不能把仍含逐臂循环的旧 shell 当作全臂并行证明 |
| C07 | 停止后状态与归档收集 | 状态修复已完成：此前17个滞留running按Docker终态校正，81个失败日志与State已保留、26个缺归档原目录已恢复；本轮另24个误停容器证据与8目录状态已处理。原失败实验仍失败 | 不能把恢复原始材料等同于补齐未发生的实验或丢失终端账本；新批次逐一验收 |
| C08 | v4 深层工件、逐帧账本与缺证据拒绝 | 代码已具备严格逐帧检查；此前 coverage 60 项、smoke audit 57 项测试通过记录，本轮未复跑；仍有实际严格回放失败 | 修复实际失败后重放并审计；测试数本身不构成目标通过证据 |
| C09 | sampled-v5 日志和帧账本的自动深层核验 | 自动核验已修复：原始replay/reset日志、帧账本、输入身份/hash及实际发送逐条重建；缺失/篡改/部分发送反例已通过。本轮coverage61/61与smoke62/62；最新12重复384条输入1144逐帧事件自动通过，旧独立q1d1证据保留 | 新批次仍需实际逐归档运行核验；部分回放必须标记coverage_complete=false |
| C10 | session gcda 落盘与源码—二进制构建关联 | 有逐会话导入及成功重放证据；历史 `replay-validation-summary.json` 仍明确 `source_binary_build_association=not-verified`；未找到足以关闭全部落盘故障注入要求的统一终验 | 如相关例外策略依赖构建关系，补构建 provenance；以当前策略验证落盘隔离、缺失/陈旧 gcda 拒绝，或保留该限制并排除不合格结果 |
| C11 | 归档Python助手快照及挂载 | 已修复快照遗漏*.py；启动前普通文件校验及--mount拒绝缺源；本轮12实际容器exit0、归档mock材料齐全 | 原12exit125失败不改写；事后恢复另附provenance |
| C12 | 校准阶段时间截止的终端配额行 | 已将campaign-final移到共享退出路径，最终stats同步；contract selftest与12份实际归档均通过 | 每个纳入结果的归档必须恰好一条终端行，终态与配额计数一致 |
| C13 | LLM跨fork／线程共享调用上限 | 共享mmap／robust锁，发出前预留，死亡不退还，启动前初始化；本地11/11；两批共24实际归档各8条唯一预留与8次campaign请求通过 | Token阈值仅基于已报告完成用量；不得宣称硬token预算 |
| C14 | launcher传递LLM调用上限 | 白名单修复；四路实际launcher stub保留cap7，当前12容器有效cap8 | 后续新协议仍核对start/end和独立上游统计 |
| C15 | LLM原始交换／预留／完成／预检用量对账 | 正向12归档全部通过；每次req与预留字节相同、resp与usage一致、独立mock次数一致、启动日志用量独立加总；6类篡改反例拒绝 | cap对账通过不能替代保存语料回放审计 |


## 2. 保存语料的目标修复与验收

八核心臂：`pvstop1`、`salvage1`、`nollm1`、`wrapgate1`、`native1`、`calibrated1`、`cal_ewma1`、`cal_run_rate1`。该表不将核心臂通过等同于 Q1 四臂通过。

| 目标 | 当前证据与状态 | 尚需完成 |
| --- | --- | --- |
| Bftpd | `audit_bftpd_master_v2_20261116.txt` 八核心臂各三重复通过 | 后续 Q1 单独验收；不能沿用核心臂结果回答 Q1 |
| Exim | `audit_exim_master_v2_20261116.txt` 八核心臂各三重复通过；另有历史 24/24 全语料复验 | 后续 Q1 单独验收 |
| LightFTP | `audit_lightftp_master_v2_20261116.txt` 八核心臂各三重复通过 | 后续 Q1 单独验收 |
| Pure-FTPd | 原 master 审计 7/8；后续固定语料修复回放已将 `nollm1` r1/r2/r3 全部跑完：141/141、150/150、136/136；replay/audit exit 均 0、terminal complete、reset 全成功 | **严格验收未通过**：r1/r2/r3 实际有 21/19/15 条帧缺口，旧审计误报已修复；不得再将处理条数视为完整发送。原归档 hash 关联已完成，构建关联仍未证实；新 Q1 失败另列 |
| Live555 | 原 master 审计 7/8；后续 `calibrated1` r3 已完整回放 172/172，replay/audit exit 均 0、terminal complete、reset 全成功 | 固定语料修复验证通过；形成关联原归档的统一八臂终验；新 Q1 失败另列 |
| ProFTPD | 最新 masterv4 的七臂共 21 次严格回放：16 complete、5 incomplete；`pvstop1` 另有未关闭问题，详见第 3 节 | 修复导致这些输入回放失败的代码或环境，保留输入并复验；以同一严格策略生成全八臂、24 重复终验 |
| Kamailio | 本轮只读核对 11-16 主批次八核心臂 24 个原始归档：24/24 exit 0、terminal complete，9,122 条完整回放、回放 reset 全成功、无异常；135,319 条 fuzz reset 中 6 条失败均为停机取消，逐一只关联未执行的 invocation_refused，没有 invocation_start | 核心归档的 reset/停机问题已解释并通过；尚缺统一综合审计报告；Q1 四臂 exit 1 另列，不能以核心臂结果代替 |
| forked-daapd | 11-16 新核心批次15/24不完整；旧端口参数ABI错误已修复，剩余原种子旧队列ID/路径导致HTTP500关连接已实际复现；cal_ewma1/r3 OOM证据排除 | 原序列严格失败保留。未来实验以显式新fixture/种子/campaign验证，不沿用11-15旧PASS；Q1另列 |
| Lighttpd1 | `audit_lighttpd1_final_fp5f818ed7_20261115.txt` 所列 11-16 八核心臂各三重复通过 | 后续 Q1 单独验收 |

Pure-FTPd / Live555 最新修复回放目录：`replay_verify_partial_masterv2_20261116T1945_v3/`。每个子目录保存 `replay.exit-code`、`audit.exit-code`、`cov.csv.v4/terminal.json`。原失败证据保持原样；单独回放通过不等同于重新执行 fuzz campaign。

Kamailio 本轮核查的源归档：`results-kamailio_ablation_{pvstop1,salvage1,cal_ewma1}_20261116T163255/` 以及 `results-kamailio_ablation_{wrapgate1,native1,nollm1,calibrated1,cal_run_rate1}_20261116T173833/`。6 次停机取消分别在 `calibrated1/r3`、`native1/r1`、`nollm1/r2`、`pvstop1/r2`、`salvage1/r2`、`wrapgate1/r2`；证据为各 tar 内 `reset-events.jsonl` 与 `execution-events.jsonl`。每个已执行调用仍必须有成功 reset，取消且未执行的拒绝尝试单列。

## 3. ProFTPD 逐重复严格回放

最新严格策略：`20261116b-frame-ledger-strict-proptpd-v4-pureftpd-sm-v1`。七臂工件：`proftpd_archive_replay_masterv4_remaining_20261116T2110/`。

| 臂 | 重复 1 | 重复 2 | 重复 3 |
| --- | --- | --- | --- |
| cal_ewma1 | 367/367 complete | 342/342 complete | 327/327 complete |
| cal_run_rate1 | 337/337 complete | 356/356 complete | 343/343 complete |
| calibrated1 | 353/353 complete | 354/354 complete | 371/371 complete |
| salvage1 | 361/361 complete | 373/373 complete | 385/385 complete |
| native1 | 385/385 complete | 368 条中 2 条帧账本不完整 | 358/358 complete |
| nollm1 | 324 条中 3 条帧账本不完整 | 319 条中 1 条帧账本不完整 | 330 条中 1 条帧账本不完整 |
| wrapgate1 | 357 条中 1 条帧账本不完整 | 357/357 complete | 338/338 complete |
| pvstop1（单独批次） | 后续 masterv3：405 条中 1 条帧账本不完整 | 后续 masterv3 complete | masterv3 当前严格回放有 1 条实际失败；此前 manifest 漏列 |

21 次 masterv4 回放都有 terminal、reset 全成功、无 replay anomaly，但其中 5 次存在 `frame-ledger-incomplete`，仍未通过。manifest 明确 `completed=false`、`completed_count=16`。

`pvstop1` 第 1 重复证据：`proftpd_archive_replay_masterv3_20261116T2031/results/pvstop1_run1/cov_over_time.csv.v5/terminal.json`。较早策略的 complete 不替代最新严格策略的检查。

通过条件：逐条输入 hash 与帧长度/数量/实际发送字节吻合，reset、服务就绪、退出/关闭策略和 gcda 落盘均满足；异常输入不得删去或放宽标准后改称完整。修复后用保存语料回放即可，不以重新 fuzz 为默认要求。

## 4. Q1 四臂实际结果清点

以下使用每个 target/arm 按目录时间戳排序的最新尝试，用于发现缺失和失败，不是挑选可比较样本。较早有效样本没有被删去，也没有被静默替换进新批次。逐目录路径、归档列表、98 个已记录容器的 Docker 终态见 `REPAIR_VALIDATION_INVENTORY_20261117.json`。

| 目标 | q1a1 | q1b1 | q1c1 | q1d1 |
| --- | --- | --- | --- | --- |
| Bftpd | 仅 1 个容器记录，exit 137，无归档 | 3 个 exit 137，无归档 | 3 个 exit 0，有归档；待终验 | 3 个 exit 0，有归档；待终验 |
| Exim | 3 个 exit 137，有失败归档 | 3 个 exit 137，无归档 | 3 个 exit 1 | 3 个 exit 1 |
| LightFTP | 3 个 exit 137，有失败归档 | 3 个 exit 137，无归档 | 3 个 exit 1 | 3 个 exit 1 |
| Pure-FTPd | 3 个 exit 137 | 3 个 exit 137 | 3 个 exit 137 | 3 个 exit 137 |
| Live555 | 3 个 exit 137，有失败归档 | 3 个 exit 137，无归档 | 3 个 exit 1 | 3 个 exit 1 |
| ProFTPD | 3 个 exit 0，有归档；待统一终验 | 3 个 exit 0，有归档；待统一终验 | 3 个 exit 0，有归档；待统一终验 | 原批次 2 个 exit 0、1 个 exit 137；另有独立 600 秒 r3 快速补跑通过 |
| Kamailio | 3 个 exit 1 | 3 个 exit 1 | 3 个 exit 1 | 3 个 exit 1 |
| forked-daapd | 仅 1 个容器记录，exit 137，无归档 | 3 个 exit 1，无归档 | 3 个 exit 1，无归档 | 3 个 exit 1，无归档 |
| Lighttpd1 | 3 个 exit 137，有失败归档 | 3 个 exit 137，无归档 | 未找到结果目录 | 未找到结果目录 |

部分 `.sample_status` 仍写 running，但对应容器已 exit 137。当前 Docker 没有运行容器；该字段滞留不能当作实验仍在推进。

Q1 单重复通过条件：exit 0；归档可读且 status/manifest/campaign 身份一致；配置 start/end 完整；target/protocol/policy/code-retain 与请求一致；执行 start/end 成对且 charged 一致；每次已执行调用 reset 成功；mock 配置/请求/成本账本齐全；回放终态与完整性范围如实标记。Q1 三重复比较还需同一比较协议、构建身份、逐重复种子记录及跨臂配对关系、回放身份，并逐重复报告实际预算和停止原因；三个重复不要求使用同一个 RNG seed。

5,000 是当前脚本的调用预算上限，不是快速完整性验证必须达到的次数。时间截止结果如实标记 time-censored，不能称等调用剂量。若要主张 fixed-call 比较，才需满足预定有效剂量和停止契约；`q1b1` 的 parked quota 必须单独处理。也可预先选择一致的固定时长方案，但不能将已有 600 秒和 900 秒样本直接混作同条件三重复。

## 5. 最新 q1d1 单次快速补跑

工件：`q1d_repeat3_repair_20261117T011436Z/`；完整检查见 `validation.json`。

| 项目 | 实测 |
| --- | --- |
| 总耗时 / fuzz 时间上限 / 总上限 | 647.3 秒 / 600 秒 / 900 秒 |
| Docker / OOM | exit 0 / false |
| 单归档完整性检查 | 34/34 通过 |
| 目标调用 / 配额记账 / 执行前 reset | 3,748 / 3,748 / 3,748 成功 |
| 回放输入 / 完整队列 | 32 / 254 |
| 回放 reset / 帧数 / 异常 | 32/32 成功 / 128 帧已独立人工核对 / 0 |
| mock 请求 | 199，含 1 次预检 |
| terminal、mock 统计、归档 | 均存在 |
| 原失败归档 | hash 未变，保持失败证据 |
| 完整覆盖 / fixed-dose 效果比较资格 / 合并原批次 | false / false / false |

该次 34 项包括状态与身份、归档读取、配置起止、终止契约、target/protocol/build、mock 配置、Q1 policy、code-retain、执行坐标/配对/reset、采样回放、scope/version、预算/配额/统计、summary/分支一致性、截止、原失败归档不变、独立 campaign、RNG 保留以及运行时间变化披露。它是单重复快速验证，不计作全批次或同条件三重复通过。

## 6. Q1–Q3 结果与真实网关验证

| ID | 项目 | 当前状态 | 验收要求 |
| --- | --- | --- | --- |
| E01 | Q1 资源节省/回流效果 | 全目标比较未完成；最新单次补跑只证明执行和归档完整 | 对照 direct/idle/reflow/code-retain，核对 saved/idle/reflow 的实际去向，报告绝对覆盖、实际调用、单位调用收益、时间与 LLM 成本；完整且同条件的结果进入比较 |
| E02 | Q2 根生命周期与剂量匹配 | 已有独立 BFTPD 三重复旧批次 `q2_salvage_ordmatch_pair_audit.json`，配对条件 ready；不能泛化到新主批次或真实网关 | 每根 admit/terminal/productivity 唯一连接、后代剂量一致；每臂每重复至少 10 个正剂量根、相同 per-root cap、中位剂量比 0.80–1.25 是现有 smoke 判据，须注明其用途与来源 |
| E03 | Q2 效果方向 | 上述 BFTPD 旧批次 bitmap-slot 增益差三个重复均为负，均值 -23.913/千次后代调用；不是源码分支，也不是 salvage 胜出的证据 | 如实报告负向/不支持结果；完整性通过不要求方法胜出，不通过改指标或筛掉重复制造正向效果 |
| E04 | Q3 机制触发 | 已有 BFTPD 旧批次三重复机制 ready 证据；calibrated applied=44/45/42、changed=16/29/19；其他目标/新批次不可继承 | 所选批次每重复有实际改变选择、正奖励、完成窗口和后验更新；未触发记 unresolved。随后与 EWMA/run-rate/wrapgate 同条件比较效果 |
| G01 | 真实网关配置与连通性 | 用户要求自行手动执行；要求前一次真实客户端预检HTTP401，无效令牌，失败证据保留 | 后续不自动执行或索取KEY；mock通过不能证明真实网关连通 |
| G02 | 真实网关小规模运行 | 未启动，由用户手动执行 | 本轮只交付mock所列工程验收；真实campaign须独立记录配置、请求、用量和终态 |
| G03 | 真实网关效果比较 | 无结果，由用户手动执行 | 同条件协议、完整回放及所有重复独立验收；不以mock替代 |

真实网关启动前需要工程完整性和可用配置。效果是否正向、Q1 是否打满 5,000 次，以及完整论文级比较不是额外的启动要求；这些按各自实验协议验收。受影响目标尚有失败时，可修复该目标或明确限定先行目标的范围，不能把排除目标写作已通过。

## 7. 尚需处理的具体工作

- ProFTPD、Pure-FTPd：旧失败输入的服务端真实关闭已定位并实测；新客户端会严格拒绝假通过。原输入/config不变时不得通过重连、删除尾帧或改限制改判；旧结果仍不合格。Pure等历史构建溯源not-verified仍保留。
- DAAP：旧ID/路径与reset fixture失配已实测；ABI/提前EOF修复不使原序列变完整。需要不同fixture/种子时另立新campaign，不覆盖旧结果。
- Live555固定语料修复172/172已通过；Kamailio核心24归档的停机取消已解释，历史Q1仍单列。
- 本轮Exim12重复工程验收通过；全目标历史Q1的失败、缺重复及缺关键账本仍不能离线补造。此前600秒Exim12个exit125容器材料已恢复并生成有provenance的衍生归档，10857对执行/reset/charged一致，原exit125与hash不变，不标端到端PASS。
- 前轮Exim采样384/792条输入，完整覆盖未完成；最新32次正向批次保存的24种子已完整回放，仍不能证明机制或正向效果。紧邻cap5000批次40条中10条变异输入严格失败，原失败保留；16:23已按服务端拒绝证据分类重审计exit0，10条如实记为server-rejected incomplete，不得改称完整。
- 真实fuzz campaign未启动。用户明确自行手动执行；一次早于该要求的客户端预检401已保留。当前交付仅覆盖mock，后续不再自动请求真实网关。

## 8. 证据索引

- 逐目标/逐臂最新尝试、真实容器终态、补跑 34 项原始检查：`REPAIR_VALIDATION_INVENTORY_20261117.json`。
- 最新快速补跑：`q1d_repeat3_repair_20261117T011436Z/REPORT.md`、`manifest.json`、`completion.json`、`validation.json`。
- Pure-FTPd / Live555 修复回放：`replay_verify_partial_masterv2_20261116T1945_v3/`。
- ProFTPD：`proftpd_archive_replay_masterv4_remaining_20261116T2110/manifest.json` 及 `results/*/cov_over_time.csv.v5/terminal.json`；`pvstop1` 另见 `proftpd_archive_replay_masterv3_20261116T2031/`。
- 审计标准：`EVALUATION_CRITERIA.md`；项目外原始说明：`/home/ckt/Documents/000_2026_test_dev/Key_Experiment/ablation_20261113/audition.md`。
- 原始修复/测试历史：`/home/ckt/Documents/000_2026_test_dev/Key_Experiment/ablation_20261113/codex_reaudit_fixes_20261116/verification.md`。其中的旧运行状态及未完成项须结合后续工件，不直接当作当前状态。
