当前版本的一些重要的问题，请仔细琢磨，看看如何解决这些弱项：

在摘要和正文里承认了没有LoopFuzz-no-admission 因果消融，没有 candidate-level P/U/R/G admission log，、外部 baseline 只能作为 diagnostic，token budget 也不完全公平。这些问题对高水平期刊审稿人会非常显眼。论文当前的核心证据是 integrated-policy evidence，而不是 admission controller 的严格因果证明。

因果说服力是最大短板。论文证明了 LoopFuzz integrated policy 有效，但没有证明 admission controller 本身导致收益。

建议考虑，投稿前必须修的 5 个问题

补 LoopFuzz-no-admission arm
这是最关键。没有它，所有期刊的审稿人都会问：收益到底来自 admission controller，还是 token budget、temperature、frontier scheduling、plateau trigger？
补 candidate-level admission logs
至少记录：candidate id、P/U/R/G pass/fail、response code、state transition、coverage delta、promotion decision、latency。否则“runtime admission”只能是设计 claim，不能是机制证据。
做 token fairness 对照
至少加 controlled ChatAFL+4096 或 LoopFuzz-2048。当前 LoopFuzz token 用量明显更高，容易被质疑不是方法强，而是 LLM budget 多。
弱化摘要里的自我否定句
现在摘要太诚实，但对 editor 不友好。可以保留 limitation，但不要第一屏就说“not causal estimate”。建议改成“we further identify the missing no-admission arm and candidate-level logs as future causal-analysis requirements”。
把 external baselines 的定位讲清楚
NSFuzz、MBFuzzer 如果不能同管线比较，就不要让读者以为你们在做公平 head-to-head。最好增加 1-2 个 same-pipeline external baseline，哪怕只在代表 targets 上跑。

| **修复项**                                                      | **重要性** | **对接收概率影响** |
| --------------------------------------------------------------------- | ---------------- | ------------------------ |
| LoopFuzz-no-admission arm，最好覆盖 5–9 个 primary targets           | 最高             | 极大                     |
| candidate-level P/U/R/G logs                                          | 最高             | 极大                     |
| token budget fairness：ChatAFL+4096 或 LoopFuzz-2048                  | 很高             | 很大                     |
| productive IPSM-edge analysis                                         | 高               | 很大                     |
| same-pipeline external baseline，至少 StateAFL 或 NSFuzz 部分 targets | 中高             | 明显加分                 |
| Forked-daapd failure case 深挖                                        | 中高             | 加分                     |
| artifact package 可复现性说明                                         | 中高             | 加分                     |

现在，最影响接收概率的不是论文写作了，而是这 3 个证据

第一，no-admission arm。
这是决定生死的实验。没有它，审稿人会说：你们没有证明 runtime admission controller 有效，只证明了一个复杂系统整体有效。补上后，论文从“工程组合”变成“机制清楚的网络协议 fuzzing controller”。

第二，candidate-level P/U/R/G accounting。
你们现在提出了 P/U/R/G，但没有 admission denominator、P fail、U fail、R fail、G fail、promotion ratio。这个会让方法像“好看的设计图”，而不是“被实验证明的机制”。补上后，论文说服力会大幅上升。

第三，token fairness。
目前 LoopFuzz 的 LLM budget 更高，controlled ChatAFL 的 max_tokens 是 2048，LoopFuzz 是 4096，而且实际 token usage 也更高。审稿人很容易质疑：是不是花了更多 LLM budget 才赢？补一个 fairness arm 后，这个攻击点会明显变弱。

我在考虑 可能不投 computers & security， 在考虑 投 Journal of Network and Computer Applications  这个是JCR Q1，稍微更好一点，但是也更难

要看最终的实验成果如何，所以 以上这几项 和CVE就是关键。
