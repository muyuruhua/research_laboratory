# ChatAFL-Enhanced 优化集成快速指南

**版本**: 优化版 v2.0  
**更新日期**: 2026-01-18  
**状态**: ✅ 已优化并准备测试

---

## 🎯 主要优化

### 1. 降低 CEGAR 触发频率
- **旧版本**: 每 100 次 rejection 触发一次
- **新版本**: 每 1000 次 rejection 触发一次（默认）
- **可配置**: 通过环境变量调整

### 2. LLM Budget 控制
- 每小时最多 30 次 LLM 调用（默认）
- 防止API费用失控
- 超出限额自动暂停 CEGAR

### 3. 快速失败机制
- 连续失败 10 次后进入 5 分钟冷却期
- 避免浪费时间在无效的 LLM 调用上

### 4. 性能监控
- 实时追踪 CEGAR 时间占比
- 目标：< 10% 总时间
- 超出预算时发出警告

### 5. 默认禁用
- CEGAR 默认关闭，需显式启用
- 避免意外开销

---

## 📦 文件结构

```
ChatAFL-Enhanced/
├── afl-fuzz.c              # 已添加优化的 CEGAR 钩子
├── cegar-optimized.h       # 优化的配置和接口
├── cegar-optimized.c       # 运行时控制实现
├── verifier_extended.c     # 从容器恢复的验证器
├── state-graph.h           # 状态转移图
├── verifier.c/h            # 基础验证模块
├── cegar-refinement.c/h    # CEGAR 主逻辑
└── state-scheduler.c/h     # 状态调度器
```

---

## 🚀 构建方式

### 方式1: 轻量级版本（默认，推荐）
```bash
cd ChatAFL-Enhanced
make clean && make
# 结果：无 Enhanced 模块，性能最佳
```

### 方式2: Enhanced 版本（优化后）
```bash
cd ChatAFL-Enhanced
make clean && make CHATAFL_ENHANCED=1
# 结果：包含 CEGAR/Verifier，但默认禁用
```

---

## ⚙️ 运行配置

### 不启用 CEGAR（性能测试，推荐）
```bash
# 直接运行，CEGAR 不会被激活
./afl-fuzz -i in -o out -N tcp://127.0.0.1/2200 -- ./target
```

### 启用 CEGAR（默认配置）
```bash
# 使用默认的优化配置
export CHATAFL_CEGAR_ENABLE=1
./afl-fuzz -i in -o out -N tcp://127.0.0.1/2200 -- ./target
```

### 启用 CEGAR（自定义配置）
```bash
# 完全控制
export CHATAFL_CEGAR_ENABLE=1
export CHATAFL_CEGAR_INTERVAL=1000       # 触发间隔（rejection次数）
export CHATAFL_LLM_BUDGET_HOURLY=30      # 每小时最大LLM调用数
export CHATAFL_CEGAR_MAX_RETRIES=3       # 最大重试次数
export CHATAFL_CEGAR_FAST_FAIL=1         # 启用快速失败
export CHATAFL_CEGAR_MONITOR=1           # 启用性能监控

./afl-fuzz -i in -o out -N tcp://127.0.0.1/2200 -- ./target
```

### 激进模式（测试用）
```bash
export CHATAFL_CEGAR_ENABLE=1
export CHATAFL_CEGAR_INTERVAL=100        # 更频繁触发
export CHATAFL_LLM_BUDGET_HOURLY=100     # 更高预算
./afl-fuzz ...
```

### 最小模式（生产用）
```bash
export CHATAFL_CEGAR_ENABLE=1
export CHATAFL_CEGAR_INTERVAL=10000      # 极少触发
export CHATAFL_LLM_BUDGET_HOURLY=10      # 严格预算
export CHATAFL_CEGAR_FAST_FAIL=1         # 必须启用
./afl-fuzz ...
```

---

## 📊 统计信息

CEGAR 统计会在程序结束时自动打印：

```
===== CEGAR Statistics =====
  Triggers:           23
  LLM Calls:          69
  Successes:          0 (0.0%)
  Failures:           69 (100.0%)
  Cache Hits:         0
  Total Time:         345000 ms (345.0 sec)
  Avg Time/Call:      5000 ms
  Consecutive Fails:  10
  Cooldown:           0 seconds remaining

CEGAR time usage: 57.5% of total fuzzing time
[!] CEGAR exceeded time budget (57.5% > 10%)
```

---

## 🔧 性能对比测试

### 测试场景
```bash
# 1. 基准测试（无 CEGAR）
cd ChatAFL-Enhanced
make clean && make
# 重新构建 Docker 并运行
cd ../benchmark/subjects/FTP/LightFTP
docker build -t lightftp .
cd ../../../../
./compare_fuzzers_docker.sh LightFTP FTP 60

# 2. 优化 CEGAR 测试
cd ChatAFL-Enhanced
make clean && make CHATAFL_ENHANCED=1
# 重新构建 Docker 并运行
export CHATAFL_CEGAR_ENABLE=1
export CHATAFL_CEGAR_INTERVAL=1000
export CHATAFL_CEGAR_FAST_FAIL=1
cd ../benchmark/subjects/FTP/LightFTP
docker build -t lightftp .
cd ../../../../
./compare_fuzzers_docker.sh LightFTP FTP 60
```

### 预期结果
| 版本 | 路径数 | 覆盖率 | CEGAR占比 |
|------|--------|--------|-----------|
| **旧版 Enhanced** | 55 | 0.67% | 50-60% ⚠️ |
| **无 CEGAR** | 140 | 0.84% | 0% ✅ |
| **优化 CEGAR** | 130-140 | 0.80-0.84% | < 10% ✅ |

---

## 🐛 故障排除

### CEGAR 未启动
```bash
# 检查编译选项
nm afl-fuzz | grep cegar_config_init
# 应该有输出

# 检查环境变量
echo $CHATAFL_CEGAR_ENABLE
# 应该是 1

# 查看日志
# 应该看到: "CEGAR enabled: interval=..."
```

### CEGAR 过于频繁
```bash
# 增大触发间隔
export CHATAFL_CEGAR_INTERVAL=5000

# 或者禁用
unset CHATAFL_CEGAR_ENABLE
```

### LLM 调用失败
```bash
# 检查 OpenAI API Key
echo $KEY

# 检查网络
curl https://api.openai.com

# 启用快速失败，避免浪费时间
export CHATAFL_CEGAR_FAST_FAIL=1
```

### 时间占比过高
```bash
# 查看统计
grep "CEGAR time usage" output.log

# 如果 > 10%，增大触发间隔
export CHATAFL_CEGAR_INTERVAL=2000

# 或降低 LLM budget
export CHATAFL_LLM_BUDGET_HOURLY=10
```

---

## 📈 下一步

### 短期（本次测试）
- [ ] 构建轻量级版本（无 CEGAR）
- [ ] 运行 60 分钟对比测试
- [ ] 验证性能恢复到 140 paths

### 中期（如需启用 CEGAR）
- [ ] 构建 Enhanced 版本
- [ ] 配置保守的触发策略
- [ ] 运行A/B测试，对比开销

### 长期（优化方向）
- [ ] 实现异步 CEGAR 处理
- [ ] 添加智能触发预测
- [ ] 集成本地语法修复

---

## 📞 问题报告

如遇到问题，请收集以下信息：
1. 构建命令（make 或 make CHATAFL_ENHANCED=1）
2. 环境变量设置
3. CEGAR 统计输出
4. fuzzer_stats 文件

---

## ✅ 优化总结

| 优化项 | 旧版本 | 新版本 | 改进 |
|--------|--------|--------|------|
| 触发频率 | 每100次 | 每1000次 | **10x 减少** |
| LLM Budget | 无限制 | 30次/小时 | **防失控** |
| 失败处理 | 一直重试 | 10次后暂停 | **快速失败** |
| 时间监控 | 无 | 实时追踪 | **可见性** |
| 默认状态 | 强制启用 | 默认禁用 | **安全** |
| 性能影响 | 50-60% | < 10% | **5-6x 改善** |

**结论**: 优化版 CEGAR 应该能够在不影响性能的情况下提供额外的测试能力。
