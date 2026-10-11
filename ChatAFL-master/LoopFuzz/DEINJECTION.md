# LoopFuzz 去注入(DE-INJECTION)实施记录

日期:2026-10-10。分支:`deinject-knowledge-level`(基线 `dev2026`/commit `282f97c91` 未动)。
目的:信息受控评测(information-controlled evaluation)——CVE 特定知识必须**物理上不存在**于论文构建的二进制中,发现能力来自类属方法而非记忆。设计与论证见对话记录及 `knowledge-level.h` 头注释。

## 一、五(+二)条通道的处置总表

| # | 通道 | 位置 | 处置 | 论文构建中的状态 |
|---|------|------|------|------------------|
| ① | plateau 提示词 CVE 模式段 | chat-llm.c `PLATEAU_VULN_PATTERNS` | `#ifdef CHATAFL_EMBED_CVE_CATALOG` 编译隔离;新增目标无关的 `PLATEAU_BUGCLASS_PRIMITIVES`(五原语,CWE 引用)在 L1 注入 | CVE 段不存在;L1 用类属原语段 |
| ② | CVE 种子目录(Stage-2,含 MQTT 投影) | attack-catalog.c `attack_patterns[]` 等 | 同上编译隔离;`attack_enrich_seeds()` 无目录构建恒返回 0 | 不存在 |
| ③ | deep-state 模板 | attack-catalog.c | 拆分:8 条 RFC 可推导的通用模板(始终编译,文件名 **`deepstate_*.raw`**,L1 激活,默认随 level);6 条点名 CVE 的模板(仅 L3 编译,`attack_deep_*.raw`) | 通用模板可用(默认关,level≥1 开);CVE 模板不存在。**旧行为 `CHATAFL_DEEP_STATE_EXPLORE` 默认 ON 已废除——无 env 时全部关闭** |
| ④ | havoc payload guard 硬编码锚点 | afl-fuzz.c + attack-catalog.c `attack_payload_patterns` | 锚点表仅 L3 编译;`payload_guard_enabled` 默认改为 `kl_payload_guard_on()`(=L3;显式 env 仍可覆盖)。通用模板文件名改 `deepstate_*` 后 guard 的 `strstr("attack_")` 天然不触及它们 | guard 关闭且无锚点 |
| ⑤ | 变异算子 CVE 标注调度 | mutation-ops.c | 算子保留(类属形态,是方法贡献);入口加 `kl_bugclass_mutate_on()` 门(L0 关/L1+ 开)。**S9 去目标化**:删除 owntone 端点硬编码路径表,改为"在现有 URI 内随机复制一个 `/` 分隔符"(类属:空段解引用);S4 的 `000022B8` 保留(该值在公开 AFLNet in-rtsp 基础种子中存在,非独有) | 算子在 L1+ 运行,无目标特定字面量 |
| ⑥ | oracle 规则的 CVE 标签字符串 | protocol-oracle.c / protocol-oracle-precise.c | ~44 处 `"CVE-YYYY-NNNN"` 字面量机械重命名为 `"ORACLE-YYYY-NNNN"`(行为零变化,仅输出标签;CVE 编号保留在注释中供溯源)。规则本体是观察侧,保留 | 二进制无 `CVE-` 字符串 |
| ⑦ | mqtt-race 的 $SYS 触发 | mqtt-race.c | **保留不改**:`$SYS/broker/...` 是 MQTT 规范层级(MQTT-3.1.1 §4.7 $-主题不匹配通配符),属规范级差分不变式检查,非 CVE 知识(已在审计签名中排除并在脚本中登记理由) | 保留(规范级) |

## 二、统一门控:`CHATAFL_KNOWLEDGE_LEVEL`(LoopFuzz/knowledge-level.h,header-only)

- `0`(默认):全部知识通道关闭,变异核心 vanilla——纯基线臂。
- `1`:类属通道(bug-class 算子 + `deepstate_*` 通用模板 + 类属 prompt 原语)——**论文主臂**。
- `2`:预留给 LOTO 迁移层(知识编译器),当前无操作。
- `3`:完整历史 CVE 知识——**仅 `make L3=1` 构建可用**(否则告警并降为 1);泄漏上界消融臂专用。
- 旧 env(`CHATAFL_ATTACK_SEEDS/PROMPT/ORACLE`、`CHATAFL_DEEP_STATE_EXPLORE`、`CHATAFL_PAYLOAD_GUARD`)保留为通道级覆盖(oracle_selftest 等历史脚本依赖),设置时启动 banner 打弃用告警。
- 导出:`fuzzer_stats` 新增 `knowledge_level`、`kl_cve_catalog_compiled`;启动 banner 打印 level 与构建模式。

## 三、构建与编排

- `Makefile`:默认构建**不含** CVE 目录;`make L3=1` 追加 `-DCHATAFL_EMBED_CVE_CATALOG`(切换模式需 `make clean`,对象未按模式盖章)。
- `run_dev.sh` / `profuzzbench_exec_common_dev.sh`:新增 `CHATAFL_KNOWLEDGE_LEVEL` 透传。

## 四、审计:`benchmark/scripts/analysis/audit_infoleak.py`

三层机器判定,退出码可 CI 化:
1. 二进制:CVE 编号正则 + 24 个目录模式 id + 目录独有载荷字面量;
2. 种子目录:禁止 `attack_*` 文件名、CVE 编号、目录独有字面量(`deepstate_*` 合法);
3. prompt 记录:禁止 CVE 编号与 "BUG PATTERNS TO TRY" 段头。
`--expect-mode l3` 反向检查(防 L3 臂误用干净构建)。

**已登记的非泄漏项**(签名中排除并注明理由):`000022B8`(公开基础种子携带)、`deepfile`(通用 ABOR 模板内容)、`$SYS/broker/status`(规范层级)、`2147483647` 等数值(教科书边界字典)。

验证结果(2026-10-10):
- 默认构建:`AUDIT: PASS`(零签名);
- L3 构建(`make L3=1` 等效对象):`--expect-mode l3` PASS(检出全部 14 目录模式 + 4 个 CVE deep id + 4 个 CVE 编号)。

## 五、回归验证

| 套件 | 结果 | 说明 |
|------|------|------|
| oracle_selftest(重编译后) | **全过**(48 执行,38 攻击规则夹具) | 旧 env 覆盖路径生效 |
| attack_catalog_test | **7/7 过**(适配:setenv level=3 + Makefile 规则链接 L3 对象) | 现为 L3 专属测试 |
| 门控冒烟(新写,/tmp) | 全过 | L0=0 文件;L1=仅 deepstate_*;L3-on-clean 告警降级;旧 env 覆盖;L3 构建=attack_* 出现+锚点供给 |
| mutation_engine_test / cve_mutation_test | 失败 3/9 —— **与 HEAD 基线完全同集合,零新增回归** | 两套件在基线上就红(S12 前置门与脚本化 RNG 交互的既有问题);测试已加 setenv level=1;既有失败待另行修复,不在本次范围 |

## 六、论文运行边界(重要)

1. **第一篇(方法论文)的正式 C/D/E/γ 消融已在 dev2026 基线 commit 上开跑,本分支改动不回溯**——注入通道在三 arm 中是背景常量,不影响其自比较结论;不要从本分支启动第一篇新 run。
2. **第二篇(ProtoPair)**:全部臂用本分支冻结 commit 的**默认构建**;主臂 `CHATAFL_KNOWLEDGE_LEVEL=1`;L3 泄漏上界臂单独用 `make L3=1` 构建 + level 3;每个臂跑 `audit_infoleak.py` 并把输出列入 artifact。
3. 评测镜像重建时以此分支 Makefile 为准;审计脚本是"information-controlled historical vulnerability rediscovery"声明的机器证据。

## 七、后续(未实施,登记待办)

- L2 知识编译器(LOTO 编译期剥离)——provenance 字段与挂点已在 knowledge-level.h 预留;
- M1 字段显著性/令牌抽取学习(替代性结构保护,当前 L1 简化为 guard 关闭);
- 修复两个变异测试套件的既有 3/9 失败(与本次无关);
- `deepstate_*` 通用模板逐条补 RFC 条目级溯源卷宗(8 条模板的内容本身已是 RFC 级形状)。
