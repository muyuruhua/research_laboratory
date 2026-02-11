# 🚀 ChatAFL-Opt 快速开始指南

## 📋 前提条件

- ✅ 编译成功（已完成）
- ✅ 环境变量：`KEY` (OpenAI API key)
- ✅ 目标程序（如 LightFTP）
- ✅ 种子文件

---

## 🎯 使用场景

### 场景 1: 原版 AFL（默认，无扩展）

```bash
# 不设置 AFL_ENABLE_CHATAFL_OPT
./afl-fuzz -i seeds -o results \
  -N tcp://127.0.0.1/21 \
  -P FTP \
  -t 5000 \
  -- /bin/true

# 特点：
# - 完全原版 AFL 行为
# - 零性能开销
# - 无 LLM 集成
```

---

### 场景 2: ChatAFL-Opt 完整模式

```bash
# 1. 启用扩展
export AFL_ENABLE_CHATAFL_OPT=1
export KEY="sk-xxxxx"  # 你的 OpenAI API key

# 2. 运行
./afl-fuzz -i seeds -o results \
  -N tcp://127.0.0.1/21 \
  -P FTP \
  -t 5000 \
  -- /bin/true

# 特点：
# - 5 个模块全部启用
# - Hypothesis 生成（平台期时）
# - Verifier 验证（采样 10%）
# - CEGAR 精化（验证失败时）
# - State Scheduler 调度（新覆盖时）
# - Integration Layer 协调（变异前）
```

**预期输出**:
```
[*] Extension manager initialized
[*] Registering ChatAFL-Opt extension
[+] Initializing ChatAFL-Opt extension
[+] Initializing Hypothesis module for protocol: FTP
[+] Initializing Verifier module (SUT: 127.0.0.1:21)
[+] Initializing CEGAR module
[+] Initializing State Scheduler module
[+] ChatAFL-Opt initialized successfully (H+V+C+S pipeline ready)
...
[+] Plateau detected (1000 execs without progress). Generating hypotheses via LLM...
[+] Generated 3 new hypotheses (total: 3)
...
```

---

## 📊 监控扩展状态

### 查看统计信息

ChatAFL-Opt 会在退出时输出统计：

```
ChatAFL-Opt Statistics:
  Hypotheses generated : 15
  Verifications done   : 234
  CEGAR refinements    : 8
  State updates        : 45
  LLM assists          : 3
  States discovered    : 12
  Transitions recorded : 28
```

### 导出的文件

如果设置了 `AFL_OUT_DIR` 环境变量：

```bash
export AFL_OUT_DIR=/path/to/results

# 退出时会生成：
results/
  ├── hypotheses.json          # 所有假设
  ├── state_tree.dot           # 状态树（Graphviz）
  └── chatafl_opt_stats.txt    # 详细统计
```

---

## 🔧 配置选项

### 环境变量

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `AFL_ENABLE_CHATAFL_OPT` | 启用扩展 | 未设置（禁用） |
| `KEY` | OpenAI API key | 必需 |
| `AFL_OUT_DIR` | 输出目录 | 当前目录 |

### 扩展内部配置

可在 `chatafl_opt_extension.c` 中修改：

```c
// 第 60-65 行
priv->plateau_threshold = 1000;          // 平台期阈值
priv->verification_sampling_rate = 0.10; // 验证采样率（10%）
```

---

## 🧪 测试示例

### 测试 1: LightFTP

```bash
# 1. 准备环境
cd ChatAFL-Opt
export AFL_ENABLE_CHATAFL_OPT=1
export KEY="sk-xxxxx"

# 2. 准备种子
mkdir -p seeds
echo -e "USER anonymous\r\nPASS test\r\nQUIT\r\n" > seeds/seed.txt

# 3. 启动 LightFTP（Docker）
docker run -d --name lightftp -p 2200:2200 lightftp

# 4. 运行 fuzzing
./afl-fuzz -i seeds -o results-lightftp \
  -N tcp://127.0.0.1/2200 \
  -P FTP \
  -t 5000 \
  -- /bin/true

# 5. 观察输出
# 看到 [ChatAFL-Opt] 消息 = 扩展正常工作

# 6. 清理
docker stop lightftp && docker rm lightftp
```

---

### 测试 2: 对比实验

```bash
# 运行原版 AFL（对照组）
unset AFL_ENABLE_CHATAFL_OPT
./afl-fuzz -i seeds -o baseline -N tcp://127.0.0.1/21 -P FTP -- /bin/true &
PID_BASELINE=$!

# 运行 ChatAFL-Opt（实验组）
export AFL_ENABLE_CHATAFL_OPT=1
./afl-fuzz -i seeds -o chatafl-opt -N tcp://127.0.0.1/21 -P FTP -- /bin/true &
PID_CHATAFL=$!

# 运行 60 分钟后对比
sleep 3600
kill $PID_BASELINE $PID_CHATAFL

# 对比结果
echo "Baseline paths: $(ls baseline/queue | wc -l)"
echo "ChatAFL-Opt paths: $(ls chatafl-opt/queue | wc -l)"
```

---

## 🐛 故障排查

### 问题 1: 扩展未初始化

**症状**: 没有看到 `[ChatAFL-Opt]` 消息

**检查**:
```bash
# 1. 确认环境变量
echo $AFL_ENABLE_CHATAFL_OPT  # 应输出 "1"

# 2. 确认 protocol_name
./afl-fuzz -i seeds -o out -N tcp://127.0.0.1/21 -P FTP -- /bin/true
# 必须指定 -P 参数
```

---

### 问题 2: LLM API 错误

**症状**: 看到 "LLM enrichment failed" 警告

**检查**:
```bash
# 1. 验证 API key
echo $KEY  # 应输出你的 key

# 2. 测试 API 连接
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $KEY"
```

---

### 问题 3: 性能下降

**原因**: 验证采样率过高

**解决**:
```c
// 修改 chatafl_opt_extension.c 第 64 行
priv->verification_sampling_rate = 0.05; // 降到 5%

// 重新编译
make clean && make
```

---

## 📈 性能优化建议

### 1. 调整验证采样率

```c
// 高性能模式（采样 5%）
priv->verification_sampling_rate = 0.05;

// 平衡模式（采样 10%，默认）
priv->verification_sampling_rate = 0.10;

// 深度验证模式（采样 20%）
priv->verification_sampling_rate = 0.20;
```

### 2. 调整平台期阈值

```c
// 快速响应（500 次）
priv->plateau_threshold = 500;

// 默认（1000 次）
priv->plateau_threshold = 1000;

// 保守模式（2000 次）
priv->plateau_threshold = 2000;
```

---

## 📚 进阶用法

### 添加自定义扩展

```c
// 1. 创建 my_extension.c
static fuzzer_extension_t my_extension = {
    .name = "MyExtension",
    .init = my_init,
    .on_new_coverage = my_callback,
    .enabled = true,
    .priority = 50
};

fuzzer_extension_t* get_my_extension(void) {
    return &my_extension;
}

// 2. 在 afl-fuzz.c main() 中注册
if (getenv("AFL_ENABLE_MY_EXTENSION")) {
    register_extension(ext_mgr, get_my_extension());
}

// 3. 编译
make clean && make

// 4. 启用
export AFL_ENABLE_MY_EXTENSION=1
./afl-fuzz ...
```

---

## 🎯 最佳实践

1. **首次运行**: 先用原版 AFL 建立基线
2. **启用扩展**: 对比 ChatAFL-Opt 的改进
3. **监控日志**: 注意 LLM 调用频率
4. **调整参数**: 根据目标调整采样率
5. **保存结果**: 导出假设和状态树供分析

---

## 📞 支持

- 📖 完整文档: `PLUGIN_ARCHITECTURE.md`
- 🔧 架构说明: `README_OPTIMIZATION.md`
- ✅ 验证脚本: `./verify_plugin_architecture.sh`
- 🧪 快速测试: `./quick_test.sh`

---

**祝 Fuzzing 愉快！** 🎉
