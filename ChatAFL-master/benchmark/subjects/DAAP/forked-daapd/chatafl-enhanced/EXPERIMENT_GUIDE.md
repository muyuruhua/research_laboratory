# ChatAFL-Enhanced 实验指南

## 📋 模块实现完成情况

### ✅ Week 2: Verifier v0 (已完成)
- **文件**: `verifier.c/h`
- **功能**:
  - JSON语法验证（必需字段、约束检查、资源限制）
  - SUT可接受性检查（基于响应码分类）
  - 协议状态提取（FTP/SMTP/HTTP支持）
  - 8种拒绝原因分类（可解释性）

### ✅ Week 3: CEGAR闭环 (已完成)
- **文件**: `cegar.c/h`
- **功能**:
  - 反例最小化（Delta Debugging思想）
  - JSON字段级Patch应用（限制最多3个字段）
  - 反例驱动修正（调用LLM生成局部patch）
  - 错误关键词提取

### ✅ Week 4: 状态导向调度 (已完成)
- **文件**: `state-scheduler.c/h`
- **功能**:
  - 状态访问计数与管理
  - 低覆盖状态优先调度
  - Corpus管理（保存高价值测试用例）
  - Plateau检测（停滞时触发LLM）
  - 状态转移边记录
  - 可复现性支持（状态表持久化）

### ✅ Week 5: 集成与编译
- **Makefile**: 已添加新模块编译规则
- **chat-llm.c**: 已扩展3个新prompt函数
  - `construct_prompt_for_refinement()` - CEGAR修正
  - `construct_prompt_for_patch()` - 局部patch
  - `construct_prompt_for_state_exploration()` - 状态探索

---

## 🚀 快速开始

### 1. 编译测试
```bash
cd /home/ckt/Documents/000_2026_dev/research_laboratory/ChatAFL-master/ChatAFL-Enhanced
./build_test.sh
```

### 2. 检查编译结果
```bash
# 应该看到以下文件
ls -lh afl-fuzz verifier.o cegar.o state-scheduler.o
```

### 3. 重新构建Docker镜像
```bash
cd /home/ckt/Documents/000_2026_dev/research_laboratory/ChatAFL-master
KEY='your-openai-api-key' sudo ./setup.sh
```

### 4. 运行对比实验
```bash
# Week 1-2: 短时间测试（验证器功能）
./run_comparison.sh bftpd 5 60

# Week 3-4: 中等时间测试（CEGAR+状态调度）
./run_comparison.sh proftpd 5 240

# Week 5-6: 长时间对比（完整评估）
./run_comparison.sh exim 5 1440
```

---

## 📊 Week 6: 评估指标

### 验证器指标
```bash
# 查看验证器日志
grep "VERIFIER_REJECT" benchmark/results-*/plot_data

# 拒绝原因分布
grep "VERIFIER_REJECT" benchmark/results-*/plot_data | \
  awk '{print $NF}' | sort | uniq -c
```

### CEGAR指标
```bash
# CEGAR修正次数
grep "cegar_refinement" benchmark/results-*/plot_data | wc -l

# 平均patch大小
grep "patch_fields" benchmark/results-*/plot_data | \
  awk -F: '{print $2}' | tr -d '[]"' | wc -w
```

### 状态覆盖指标
```bash
# 唯一状态数
cat benchmark/results-*/state_table.csv | wc -l

# 状态转移总数
awk -F, '{sum+=$2} END {print sum}' benchmark/results-*/state_table.csv

# Plateau触发次数
grep "plateau_detected" benchmark/results-*/plot_data | wc -l
```

---

## 🔬 对比实验设置

### 基线: ChatAFL (原版)
```bash
cd ChatAFL
make clean all
./afl-fuzz -i in-ftp -o out-baseline -P FTP -D 10000 -N tcp://127.0.0.1/21 -- /path/to/ftpd
```

### 实验组: ChatAFL-Enhanced
```bash
cd ChatAFL-Enhanced
make clean all
./afl-fuzz -i in-ftp -o out-enhanced -P FTP -D 10000 -N tcp://127.0.0.1/21 -- /path/to/ftpd
```

### 对比维度
| 指标 | ChatAFL | ChatAFL-Enhanced | 提升 |
|------|---------|------------------|------|
| **代码覆盖率** | 基准 | ? | +% |
| **无效输入率** | 30-40% | ? | -% |
| **唯一状态数** | 未追踪 | ? | 新指标 |
| **状态转移数** | 未追踪 | ? | 新指标 |
| **崩溃数** | 基准 | ? | +% |
| **首次崩溃时间** | 基准 | ? | -% |

---

## 🐛 调试提示

### 编译错误
```bash
# 缺少json-c库
sudo apt-get install libjson-c-dev

# 缺少pcre2库
sudo apt-get install libpcre2-dev

# 缺少curl库
sudo apt-get install libcurl4-openssl-dev
```

### 运行时错误
```bash
# 查看fuzzer日志
tail -f benchmark/results-*/fuzzer_stats

# 查看Docker容器日志
docker logs <container_id>

# 检查验证器拒绝
grep "VFY_" benchmark/results-*/plot_data | head -20
```

### 集成测试
```bash
# 测试验证器
cd ChatAFL-Enhanced
./afl-fuzz -h | grep -i verifier

# 测试状态调度
ls -lh benchmark/results-*/state_table.csv

# 测试CEGAR
grep "refinement" benchmark/results-*/plot_data
```

---

## 📝 可复现性清单

- [ ] **代码版本**: 记录Git commit hash
- [ ] **API key**: 使用相同的OpenAI key（或记录key哈希）
- [ ] **随机种子**: 设置AFL_RANDOM_SEED环境变量
- [ ] **目标版本**: 记录FTP/SMTP服务器版本
- [ ] **系统环境**: 记录OS版本、内核版本、CPU型号
- [ ] **运行参数**: 保存完整的fuzzer命令行
- [ ] **状态表**: 保存state_table.csv快照
- [ ] **日志文件**: 保存完整的plot_data和fuzzer_stats

---

## 📚 论文撰写建议

### 创新点强调
1. **验证器** → 解决LLM幻觉（8种拒绝原因分类）
2. **CEGAR** → 局部修正降低自由度（限制3字段patch）
3. **STT调度** → 状态导向覆盖（优先探索低访问状态）
4. **Plateau突破** → 停滞检测+LLM生成到目标状态序列

### 实验设计
- **RQ1**: 验证器能否降低无效输入率？
- **RQ2**: CEGAR能否提升修正成功率？
- **RQ3**: 状态调度能否提升状态覆盖率？
- **RQ4**: 整体框架vs基线的覆盖率/崩溃数提升？

### 图表建议
- 图1: 验证器拒绝原因饼图
- 图2: 状态转移树可视化（DOT格式）
- 图3: 覆盖率随时间曲线（ChatAFL vs Enhanced）
- 图4: CEGAR修正成功率vs patch大小
- 表1: 各协议的状态覆盖对比
- 表2: 崩溃发现效率对比

---

## 🎯 下一步工作

### 短期（1-2周）
- [ ] 完成bftpd/proftpd/exim的对比实验
- [ ] 收集并分析状态覆盖数据
- [ ] 绘制实验结果图表

### 中期（3-4周）
- [ ] 优化验证器性能（缓存JSON解析结果）
- [ ] 扩展协议支持（MQTT/RTSP）
- [ ] 实现更复杂的状态转移模型

### 长期（5-6周）
- [ ] 撰写论文草稿
- [ ] 准备开源代码发布
- [ ] 制作演示视频

---

## 📞 联系方式

如有问题，请检查：
1. INTEGRATION_PLAN.md - 详细架构设计
2. IMPLEMENTATION_GUIDE.md - 代码实现指南
3. 各模块的头文件注释 - API文档
