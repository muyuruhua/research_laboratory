# ChatAFL-Enhanced 完整功能启用配置

## ✅ 已完成的修改

**文件**: `compare_fuzzers_docker.sh`  
**修改日期**: 2026-01-22

---

## 🎯 启用的环境变量

以下环境变量已添加到 ChatAFL-Enhanced 容器启动配置中：

```bash
# 核心功能
-e CHATAFL_ENHANCED=1                # 启用Enhanced模式（总开关）
-e CHATAFL_CEGAR_ENABLE=1            # 启用CEGAR反例引导精炼

# CEGAR 配置
-e CHATAFL_CEGAR_INTERVAL=1000       # CEGAR触发间隔（每1000次执行）
-e CHATAFL_LLM_BUDGET_HOURLY=100     # LLM调用预算（每小时100次）
-e CHATAFL_CEGAR_MAX_RETRIES=3       # CEGAR最大重试次数
-e CHATAFL_CEGAR_FAST_FAIL=1         # 启用快速失败机制
-e CHATAFL_CEGAR_MONITOR=1           # 启用性能监控

# Verifier 配置
-e CHATAFL_VERIFIER_LOG=1            # 启用验证器日志
-e CHATAFL_VERIFIER_DEBUG=1          # 启用验证器调试模式

# 调度器配置
-e CHATAFL_PLATEAU_THRESHOLD=100     # 覆盖率平台期阈值（100轮）
-e CHATAFL_USE_EVENT_BUS=1           # 启用事件总线
```

---

## 📊 各环境变量功能说明

| 环境变量 | 默认值 | 作用 | 性能影响 |
|---------|--------|------|---------|
| **CHATAFL_ENHANCED** | 0 (关闭) | Enhanced模式总开关 | - |
| **CHATAFL_CEGAR_ENABLE** | 0 (关闭) | 启用反例引导精炼 | 🔴 高（LLM调用） |
| **CHATAFL_CEGAR_INTERVAL** | 5000 | CEGAR触发频率 | ⚠️ 值越小开销越大 |
| **CHATAFL_LLM_BUDGET_HOURLY** | 50 | LLM调用预算限制 | - |
| **CHATAFL_CEGAR_MAX_RETRIES** | 3 | 精炼失败重试次数 | ⚠️ 中等 |
| **CHATAFL_CEGAR_FAST_FAIL** | 0 (关闭) | 快速放弃无效精炼 | ✅ 降低开销 |
| **CHATAFL_CEGAR_MONITOR** | 0 (关闭) | 性能监控统计 | ⚠️ 轻微 |
| **CHATAFL_VERIFIER_LOG** | 0 (关闭) | 验证器日志记录 | ⚠️ 轻微 |
| **CHATAFL_VERIFIER_DEBUG** | 0 (关闭) | 详细调试信息 | ⚠️ 中等 |
| **CHATAFL_PLATEAU_THRESHOLD** | 1000 | 平台期检测阈值 | - |
| **CHATAFL_USE_EVENT_BUS** | 0 (关闭) | 模块间事件通信 | ⚠️ 轻微 |

---

## 🔍 如何验证功能已启用

### 方法1：查看日志输出

运行测试后，检查Enhanced日志：

```bash
cat comparison_results/*/enhanced.log | grep -E "CEGAR|Verifier|State Graph|Enhanced"
```

**预期输出**：
```
[+] CEGAR enabled (interval=1000, budget=100/hour)
[+] Verifier logging enabled
[+] State Graph initialized (4096 nodes, 8192 transitions)
[+] State Scheduler initialized (plateau_threshold=100)
```

如果看到：
```
[+] CEGAR disabled (set CHATAFL_CEGAR_ENABLE=1 to enable)
```
说明环境变量未生效。

---

### 方法2：检查输出目录

Enhanced版本会生成额外的文件：

```bash
ls -la comparison_results/*/chatafl-enhanced/
```

**预期文件结构**：
```
chatafl-enhanced/
├── fuzzer_stats          # 标准AFL统计
├── plot_data             # 覆盖率曲线
├── .stt_export/          # ✅ State Transition Tree导出
│   └── state_graph_*.dot
├── .cegar_cache/         # ✅ CEGAR缓存
│   └── refinement_*.json
├── .verifier_stats       # ✅ Verifier统计信息
└── queue/                # 测试用例队列
```

如果没有 `.stt_export/` 和 `.cegar_cache/` 目录，说明功能未启用。

---

## 🚀 使用方法

### 基础用法（10分钟快速测试）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
./compare_fuzzers_docker.sh LightFTP FTP 10
```

### 推荐用法（60分钟完整测试）

```bash
# 60分钟测试，足够触发平台期检测和LLM介入
./compare_fuzzers_docker.sh LightFTP FTP 60
```

### 长期评估（4小时）

```bash
# 适合评估CEGAR精炼效果和状态调度优势
./compare_fuzzers_docker.sh Kamailio SIP 240
```

---

## 📈 性能预期

| 测试时长 | ChatAFL执行速度 | Enhanced执行速度 | 差异原因 |
|---------|----------------|-----------------|---------|
| **0-10分钟** | ~11 exec/s | ~7 exec/s | Enhanced有验证开销 |
| **10-60分钟** | ~11 exec/s | ~8 exec/s | CEGAR开始触发 |
| **60+分钟** | ~10 exec/s | ~8 exec/s | 状态调度优化生效 |

**关键指标**（60分钟后）：
- ✅ **路径发现**: Enhanced应该发现更多有效路径（+10-30%）
- ✅ **状态覆盖**: Enhanced覆盖更多协议状态
- ✅ **LLM有效性**: 通过CEGAR验证，LLM生成的有效消息比例提升
- ⚠️ **执行速度**: Enhanced会慢30-40%，但有效性更高

---

## 🔧 调优建议

### 如果性能太慢

```bash
# 降低CEGAR触发频率
-e CHATAFL_CEGAR_INTERVAL=5000       # 从1000改为5000

# 减少LLM预算
-e CHATAFL_LLM_BUDGET_HOURLY=50      # 从100改为50

# 关闭调试日志
# 注释掉或删除这两行：
# -e CHATAFL_VERIFIER_DEBUG=1
```

### 如果想更激进探索

```bash
# 增加CEGAR触发频率
-e CHATAFL_CEGAR_INTERVAL=500        # 更频繁的精炼

# 增加LLM预算
-e CHATAFL_LLM_BUDGET_HOURLY=200     # 更多LLM调用

# 降低平台期阈值
-e CHATAFL_PLATEAU_THRESHOLD=50      # 更早触发LLM介入
```

---

## 📝 测试报告说明

运行完成后，查看对比报告：

```bash
cat comparison_results/LightFTP_*/report.txt
```

**新增的Enhanced特有统计**：
```
========== Enhanced特有功能 ==========
STT导出文件数: 5              # 状态图快照
CEGAR缓存数: 12               # 精炼记录
Verifier拒绝率: 23.5%         # 服务器拒绝的消息比例
有效语法生成率: 76.5%         # LLM生成的可接受消息
平台期突破次数: 3             # LLM介入的次数
状态覆盖数: 42               # 发现的协议状态数
```

---

## ⚠️ 已知限制

1. **LLM依赖**: 需要配置LLM API（通过环境变量或配置文件）
2. **性能开销**: 启用所有功能会降低30-40%执行速度
3. **内存占用**: State Graph和CEGAR缓存会占用额外内存
4. **Docker限制**: 某些目标可能因内存限制导致ASAN崩溃

---

## 🎯 下一步

1. **运行完整测试** (60分钟):
   ```bash
   ./compare_fuzzers_docker.sh LightFTP FTP 60
   ```

2. **检查Enhanced特有输出**:
   ```bash
   ls -la comparison_results/*/chatafl-enhanced/.stt_export/
   ls -la comparison_results/*/chatafl-enhanced/.cegar_cache/
   ```

3. **可视化状态图**:
   ```bash
   dot -Tpng comparison_results/*/chatafl-enhanced/.stt_export/state_graph_final.dot -o state_graph.png
   ```

4. **分析CEGAR精炼效果**:
   ```bash
   cat comparison_results/*/chatafl-enhanced/.cegar_cache/*.json | jq '.refinement_success_rate'
   ```

---

## 📞 故障排除

### 问题1: 日志显示 "CEGAR disabled"

**检查**：环境变量是否传递到容器
```bash
docker inspect enhanced_LightFTP_* | grep -A 10 Env
```

### 问题2: 没有生成 .stt_export/

**原因**：可能未达到导出条件（需要至少发现5个状态）

### 问题3: Enhanced版本崩溃

**检查**：ASAN内存限制
```bash
# 在Docker容器启动命令中添加：
-e AFL_SKIP_CRASHES=1
```

---

**更新日期**: 2026-01-22  
**配置状态**: ✅ 完整功能已启用  
**下次审查**: 测试结果验证后
