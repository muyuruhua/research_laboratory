# Rebuttal Checklist for 12 Reviewer Concerns

本文档按“审稿意见 → 当前状态 → 还差什么 → 建议回复话术”整理，基于当前稿件 [main.tex](main.tex) 与 [references.bib](references.bib) 的实际状态。

---

## 1. Ablation 结果自我推翻核心论点

### 审稿意见
Ablation 中多个 ablated 变体在 code-edge coverage 上高于 full system，甚至 `All Controls Off` 更高，这会直接挑战“每个控制组件都至关重要”的主张。

### 当前状态
- 已部分回应。
- 当前稿件已经主动收缩主张，不再宣称每个 exposed control 都一致、稳定、必要。
- 文中明确承认 ablation 只能支持更窄的机制诊断，且目前只有 CEGR 的证据相对稳定。
- 但数据反转本身仍然存在，没有被实验上消除。

### 依据
- [main.tex](main.tex#L433-L462)

### 还差什么
- 最理想：补做更完整 ablation，或者补 admission / repair / verifier 层面的中间指标，说明为什么 code-edge 终点不总是单调对应机制价值。
- 次优：把全文核心论点继续收缩到“closed-loop runtime validation 整体控制策略优于 open-loop assistance”，避免“每个模块 individually necessary”。

### 建议回复话术
- 感谢审稿人指出这一点。我们同意当前 ablation snapshot 不支持“每个 exposed control component 对 terminal code-edge coverage 均一致必要”的强结论。
- 因此我们已经修改论文，明确将 Table 3 重新定位为机制诊断而非因果归因，并将结论收缩为：在当前完成的 ablation 子集中，CEGR 是唯一显示出相对稳定支持的 exposed mechanism，而 frontier weighting、state-context prompting 与 adaptive triggering 呈现 target-dependent interaction。
- 我们不再声称 Table 3 能证明所有控制开关对最终 coverage 均单调有益。

---

## 2. 10 个 target 只报告了 6 个

### 审稿意见
实验结果严重不完整，论文宣称 10-target benchmark，但主结果只报了 6 个。

### 当前状态
- 已部分回应。
- 稿件已明确写出 benchmark suite 有 10 个 target，但当前 normalized comparison 仅报告 6 个。
- 另外 4 个 target 现在已被明示为 pending，而不是隐含忽略。
- 主表也显式列出了 pending rows。

### 依据
- [main.tex](main.tex#L30-L30)
- [main.tex](main.tex#L266-L268)
- [main.tex](main.tex#L380-L395)

### 还差什么
- 最理想：补齐 4 个 target 的重复实验与主表。
- 次优：在 rebuttal 中解释 pending targets 的原因（trace audit / repetition protocol 尚未完成，而非 selective reporting）。

### 建议回复话术
- 我们同意当前 quantitative section 尚未覆盖完整 10-target suite。
- 为避免选择性报告的误解，我们已在修订稿中明确说明：当前 normalized comparison 仅包含 6 个已完成 repeated 24-hour summaries 与 trace checks 的 targets，并显式列出 4 个 pending targets；这些 pending targets 不参与任何 aggregate claim、ranking statement 或 summary statistic。
- 我们将该限制作为当前版本的范围约束，而非隐式忽略。

---

## 3. 缺乏统计显著性检验

### 审稿意见
论文提到 Mann-Whitney U，但原稿主表没有真正执行统计检验，且若干提升可能不显著。

### 当前状态
- 已回应。
- 方法部分现在明确写了 two-sided exact Mann-Whitney U。
- 主表增加了显著性标记。
- 结果解读也区分了 statistically significant 与 descriptive differences。

### 依据
- [main.tex](main.tex#L277-L279)
- [main.tex](main.tex#L380-L401)

### 还差什么
- 可选加强：在 rebuttal 中列出关键 target 的 p-value，尤其是 ProFTPD、Exim、Kamailio。
- 若篇幅允许，可在附录附上 per-run terminal values。

### 建议回复话术
- 我们接受这一意见，并已在修订稿中补充 exact two-sided Mann-Whitney U test。
- Table 2 现已用显著性标记区分 stronger evidence 与 descriptive improvement，并在正文中明确说明 ProFTPD 和 Exim 的 code-edge improvement 在当前 five-run matrix 下仍属于 descriptive rather than statistically decisive evidence。
- 我们据此收缩了整体结论，避免以非显著差异支撑强主张。

---

## 4. Code-edge 提升小且不一致，IPSM 有循环论证嫌疑

### 审稿意见
主要指标 code-edge coverage 提升幅度小，Kamailio 甚至落后；IPSM-edge 是系统内生指标，存在循环论证风险。

### 当前状态
- 已部分回应。
- 稿件已将 code-edge coverage 明确设为 primary endpoint。
- IPSM-edge count 被降级为 secondary diagnostic，而非 standalone efficacy claim。
- 但数据层面的“小幅提升 / target-dependent”问题仍然存在。

### 依据
- [main.tex](main.tex#L277-L279)
- [main.tex](main.tex#L381-L395)
- [main.tex](main.tex#L470-L470)

### 还差什么
- 若要更强回应，需要补更多真实 end-point（如 bug yield、crash triage、admission outcomes）来减少对 IPSM 的依赖。
- 也可补附录说明 IPSM-edge 与 code-edge 的关系只是 campaign diagnostic，不是替代指标。

### 建议回复话术
- 我们同意 code-edge coverage 是更关键的 endpoint，因此已在修订稿中将其明确设为 primary endpoint，并将 IPSM-edge count 重新定位为 state-exploration diagnostic。
- 我们也已收缩解读：当前结果显示 LoopFuzz 在多数 reported targets 上有更强 final outcomes，但 improvement 的幅度与显著性均依赖 target；Kamailio 仍然构成 trade-off case。
- 我们不再将 IPSM-edge count 作为独立充分证据，而是将其与 code-edge coverage 联合解读。

---

## 5. 没有真实漏洞 / CVE

### 审稿意见
没有 bug / CVE 结果会让审稿人质疑实用价值。

### 当前状态
- 未真正满足。
- 论文现在只是更明确地承认：当前 draft 不报告新 CVEs 或 newly confirmed bugs。
- 这避免了过度宣传，但无法替代漏洞发现结果本身。

### 依据
- [main.tex](main.tex#L279-L279)
- [main.tex](main.tex#L477-L477)

### 还差什么
- 最理想：补充 crash triage、去重、可复现 bug 或至少 confirmed crash counts。
- 若暂时做不到，rebuttal 里只能把论文定位为 campaign-control paper，而不是 bug-discovery paper。

### 建议回复话术
- 我们认可这一限制。当前版本的实证重点是 campaign control and exploration quality，而不是 fully normalized bug-finding yield.
- 因此我们已在修订稿中明确声明：本文当前不将未统一 triage 的 crash artifacts 提升为 vulnerability claims，也不将 coverage result 等同于 confirmed bug-finding superiority。
- 若后续 camera-ready / artifact update 能完成统一 crash triage，我们会优先补充该部分结果。

---

## 6. BibTeX 作者格式问题

### 审稿意见
多个 BibTeX 条目的作者格式错误，如 `sgf_usenix22`、`aflnet`、`chatafl`、RFC 作者等。

### 当前状态
- 已基本回应。
- 这些关键条目已修正为正确作者格式。
- SGF 页码也已修正。
- `docter_documentation_guided_fuzzing_2022` 的 key 仍沿用旧拼写，但不影响编译。

### 依据
- [references.bib](references.bib#L1-L50)
- [references.bib](references.bib#L160-L167)

### 还差什么
- 可选：是否把 `docter_...` 的 BibTeX key 统一重命名为 `docTer_...` 或其他更一致形式。

### 建议回复话术
- 感谢指出。我们已系统修正相关 BibTeX author formatting，包括 SGF、AFLNet、ChatAFL 以及多个 RFC 条目，并同时纠正了 SGF 的 metadata（含页码）。
- 对机构作者如 `{{OpenRCE}}` 和 `{{LLVM Project}}`，我们保留原写法，因为这是 BibTeX 对机构作者的正确处理方式。

---

## 7. Table 2 与 Table 3 数据矛盾

### 审稿意见
两张表中 “Full VeriSPFuzz / Full LoopFuzz” 数值不一致，说明数据来自不同批次实验，容易引发选择性报告怀疑。

### 当前状态
- 已回应。
- 现在表注和正文都明确说明：ablation control 来自 dedicated ablation batches，不能与 main comparison batch 直接做数值比较。
- 这已经把“矛盾”重新解释为“不同批次实验来源”。

### 依据
- [main.tex](main.tex#L433-L454)

### 还差什么
- 最理想：如果有空间，可在 rebuttal 中补一句说明为什么两类 batch 分开执行（时间、配置矩阵、实验组织原因）。

### 建议回复话术
- 我们接受这一疑问，并已在修订稿中显式说明：Table 2 与 Table 3 的 full-control rows 来自不同 experiment batches。
- 因此 Table 3 的 full row 仅作为 within-batch ablation reference point，用于解释其对应的 `Δ` 值，而不能与 Table 2 的 main-comparison full row 进行直接数值比较。
- 修订稿不再把这两个 full rows 暗示为同一批数据。

---

## 8. 缺少 SGF / Bleem / Logos / MBFuzzer 等更强基线

### 审稿意见
只与 AFLNet + ChatAFL 比较，可能显得在回避更强对手。

### 当前状态
- 已部分回应。
- 论文现在明确承认 SGF、Bleem、Logos、MBFuzzer 是重要 nearby baselines。
- 但当前 artifact-level evaluation 仍未包含 direct head-to-head reproduction。

### 依据
- [main.tex](main.tex#L121-L131)
- [main.tex](main.tex#L482-L482)

### 还差什么
- 最理想：补一到两个最关键 baseline 的 direct reproduction，至少是 SGF 或 MBFuzzer。
- 若做不到，只能在 rebuttal 中更积极承认 limitation，而非回避。

### 建议回复话术
- 我们同意 AFLNet 与 ChatAFL 不是唯一 relevant baselines。
- 因此修订稿已明确将 SGF、Bleem、Logos 与 MBFuzzer 标记为重要 nearby baselines，并将当前未完成 direct reproduced comparison 的事实视为 limitation，而不是隐含这些系统 weaker 的证据。
- 当前版本选择 AFLNet 与 ChatAFL 作为 primary comparison，是因为它们与本文 artifact 的 implementation lineage 最接近；但我们不再将其表述为“唯一合理对照组”。

---

## 9. Mosquitto 公平性严重存疑

### 审稿意见
AFLNet / ChatAFL 的 MQTT 支持由作者自行补充，无法独立核实，可能系统性偏向本文方法。

### 当前状态
- 已部分回应。
- 论文现在明确写出：Mosquitto 是 matched-support comparison，不是 off-the-shelf baseline comparison。
- 还进一步说明这更像 feasibility evidence under matched support，而非 broad superiority claim。
- 但 baseline support 仍是作者实现，公平性风险仍在。

### 依据
- [main.tex](main.tex#L268-L272)
- [main.tex](main.tex#L484-L484)

### 还差什么
- 最理想：公开补丁、脚本、或单独 artifact note，让别人能复现 MQTT baseline support。
- 如果没有，只能继续把 Mosquitto 的解读压得更谨慎。

### 建议回复话术
- 我们认可 Mosquitto row 的公平性要求高于 off-the-shelf baselines。
- 因此修订稿已明确将该结果限定为 matched-support comparison，并进一步收缩其解读：该行更应被视为在 matched support 下的 feasibility evidence，而不是对 MQTT fuzzing 的广义 superiority claim。
- 我们不会再将 Mosquitto 单独作为最强胜利证据来支撑全文核心结论。

---

## 10. semantic drift 未量化，admission rate / repair rate 未报告

### 审稿意见
如果 semantic drift 是核心动机，就应该报告其发生率、拒绝率、修复率、admission rate。

### 当前状态
- 已部分回应。
- 论文现在明确说明 semantic drift 只是 motivating failure mode，不是已量化的 headline metric。
- 也明确写出：parseability pass rate、response-grounded acceptance rate、CEGR repair outcomes 等日志可恢复，但当前还未统一归一化。

### 依据
- [main.tex](main.tex#L106-L117)
- [main.tex](main.tex#L287-L287)
- [main.tex](main.tex#L484-L484)

### 还差什么
- 若想真正满足这一条，需要补 admission-rate table 或 appendix。
- 至少应给出若干 representative targets 的 parseability / acceptance / CEGR-success summary。

### 建议回复话术
- 我们接受这一意见，并已在修订稿中降低 semantic drift 的论证强度：当前版本仅将其作为 motivating failure mode and auditable trace category，而不再把它表述为已量化的 cross-target prevalence claim。
- 同时，我们在修订稿中明确指出系统日志足以恢复 parseability pass rate、response-grounded acceptance rate 与 CEGR repair outcomes；但这些 summaries 目前尚未在所有 reported targets 上完成统一 normalization。
- 我们同意这是一项重要补充，并将其列为优先后续工作。

---

## 11. 关键超参数缺乏依据

### 审稿意见
`β`、`80 rounds`、`30%`、`64 calls`、`0.25 / 0.5` 等参数没有敏感性分析或理论依据，容易被看成精细调参。

### 当前状态
- 已部分回应。
- 当前稿件已经把这些参数解释为 reported control policy，而不是 global optimality claim。
- Threats 中也明确承认没有完整 sensitivity study。

### 依据
- [main.tex](main.tex#L189-L205)
- [main.tex](main.tex#L480-L480)

### 还差什么
- 最理想：补 sensitivity experiment。
- 次优：在 rebuttal 中强调这些参数的角色是 engineering bounds / coarse control policy，而非 per-target tuning outcome。

### 建议回复话术
- 我们同意当前版本并未提供 full hyperparameter sensitivity analysis。
- 因此修订稿已明确收缩表述：这些参数被报告为 auditable control-policy constants and engineering bounds，而不是经过全局最优搜索得到的 universal settings。
- 我们也在 threats to validity 中显式承认缺乏完整 sensitivity study，并避免再将这些常数包装为具有更强普适性的理论最优选择。

---

## 12. “Veri” 前缀误导 formal verification

### 审稿意见
“Veri” 很容易让 SE 审稿人误解为 formal verification。

### 当前状态
- 已回应。
- 系统和标题已经改成 `LoopFuzz`。
- 引言中也明确解释该名称强调 closed-loop admission and refinement，而不是 formal verification。

### 依据
- [main.tex](main.tex#L17-L17)
- [main.tex](main.tex#L44-L55)

### 还差什么
- 基本不缺，只需保证全文后续材料里不再出现旧名称或 “verified” 暗示。

### 建议回复话术
- 我们接受这一命名层面的误导风险，因此已将系统名称与论文标题统一修改为 `LoopFuzz`。
- 修订稿同时在引言中明确说明：本文强调的是 closed-loop runtime admission and refinement，而不是 formal verification of the protocol, model, or target implementation.

---

## 总结建议

### 当前最强可守住的主张
- `LoopFuzz` 的贡献应被表述为：**在当前已完成的 6-target repeated comparison 上，closed-loop runtime-validated LLM assistance 比 direct open-loop assistance 更稳健；但 exposed sub-controls 的 individually necessary claim、full-suite completeness、bug-finding yield 与 admission-rate quantification 仍然不足。**

### 当前最危险的 4 个点
1. Ablation 反向（意见 1）
2. 没有 bug / CVE（意见 5）
3. 缺少强基线 reproduction（意见 8）
4. 没有 admission / repair 统计（意见 10）

### rebuttal 写法原则
- 不要硬顶数据层面的弱点。
- 先承认，再收缩 claim，再强调已修订的文字边界。
- 把论文定位成 **campaign-control / runtime-validation paper**，而不是 **bug-yield-dominance paper**。
- 反复强调：当前 strongest evidence 是 “closed-loop control is more robust than open-loop insertion on the reported subset”，不是 “every component is individually proven necessary on the full suite.”
