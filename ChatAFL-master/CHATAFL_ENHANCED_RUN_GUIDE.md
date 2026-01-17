# ChatAFL-Enhanced 运行指南

## 📖 目录

- [快速开始](#快速开始)
- [使用run.sh运行](#使用runsh运行)
- [配置说明](#配置说明)
- [完整示例](#完整示例)
- [与其他版本对比](#与其他版本对比)

---

## 🚀 快速开始

### 基本用法

```bash
# 在项目根目录运行
./run.sh <NUM_CONTAINERS> <TIMEOUT_MINUTES> <TARGET> <FUZZER>
```

### 运行ChatAFL-Enhanced

```bash
# 示例：使用2个容器，运行24小时，目标为lightftp
./run.sh 2 1440 lightftp chatafl-enhanced
```

---

## 🔧 使用run.sh运行

### 参数说明

| 参数 | 说明 | 示例 |
|------|------|------|
| `NUM_CONTAINERS` | 并行容器数量 | `2`, `4`, `10` |
| `TIMEOUT_MINUTES` | 运行时长（分钟） | `60` (1小时), `1440` (24小时) |
| `TARGET` | 目标程序 | `lightftp`, `live555`, `dnsmasq` |
| `FUZZER` | Fuzzer名称 | `chatafl-enhanced` |

### 添加ChatAFL-Enhanced支持

当前**run.sh需要修改**才能支持`chatafl-enhanced`。需要在`profuzzbench_exec_all.sh`中添加对应分支。

---

## ⚙️ 配置说明

### 环境变量（可选）

```bash
# 跳过前N次测试（默认1）
export SKIPCOUNT=1

# 测试超时时间（毫秒，默认5000）
export TEST_TIMEOUT=5000

# 启用ChatAFL-Enhanced模式
export CHATAFL_ENHANCED=1

# CEGAR缓存目录
export CEGAR_CACHE_DIR=$PWD/benchmark/results/.cegar_cache
```

### 完整命令示例

```bash
# 设置环境变量
export SKIPCOUNT=1
export TEST_TIMEOUT=5000
export CHATAFL_ENHANCED=1
export CEGAR_CACHE_DIR=$PWD/benchmark/results/.cegar_cache

# 运行fuzzing
./run.sh 2 1440 lightftp chatafl-enhanced
```

---

## 📝 完整示例

### 示例1: 单目标单Fuzzer

```bash
# LightFTP + ChatAFL-Enhanced，2容器，24小时
./run.sh 2 1440 lightftp chatafl-enhanced
```

### 示例2: 单目标多Fuzzer对比

```bash
# 对比测试：同时运行多个版本
./run.sh 4 1440 lightftp aflnet,chatafl,chatafl-enhanced
```

### 示例3: 多目标单Fuzzer

```bash
# 在多个目标上测试ChatAFL-Enhanced
./run.sh 2 1440 lightftp,live555,dnsmasq chatafl-enhanced
```

### 示例4: 短时间测试

```bash
# 快速测试（1小时）
./run.sh 1 60 lightftp chatafl-enhanced
```

---

## 🆚 与其他版本对比

### Fuzzer选项

| Fuzzer名称 | 说明 | 特性 |
|-----------|------|------|
| `aflnet` | 原始AFLNet | 基础网络协议fuzzing |
| `chatafl` | ChatAFL基础版 | + LLM语法提取 |
| `chatafl-cl1` | ChatAFL-CL1 | + 持续学习v1 |
| `chatafl-cl2` | ChatAFL-CL2 | + 持续学习v2 |
| `chatafl-enhanced` | **ChatAFL-Enhanced** | + **Verifier + CEGAR + STT** |

### 性能对比命令

```bash
# 同时运行所有版本进行对比
./run.sh 10 1440 lightftp aflnet,chatafl,chatafl-cl1,chatafl-cl2,chatafl-enhanced
```

---

## 🔨 修改profuzzbench_exec_all.sh以支持Enhanced

### 需要添加的代码

在`benchmark/scripts/execution/profuzzbench_exec_all.sh`中，每个目标（如lightftp）都需要添加：

```bash
if [[ $FUZZER == "chatafl-enhanced" ]] || [[ $FUZZER == "all" ]]
then
    profuzzbench_exec_common.sh lightftp $NUM_CONTAINERS results-lightftp chatafl-enhanced out-lightftp-chatafl-enhanced "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
fi
```

### 修改位置

对每个目标添加对应的Enhanced分支：

```bash
# 在lightftp部分
if [[ $TARGET == "lightftp" ]] || [[ $TARGET == "all" ]]
then
    # ... aflnet分支
    # ... chatafl分支
    # ... chatafl-cl1分支
    # ... chatafl-cl2分支
    
    # 添加这里：
    if [[ $FUZZER == "chatafl-enhanced" ]] || [[ $FUZZER == "all" ]]
    then
        profuzzbench_exec_common.sh lightftp $NUM_CONTAINERS results-lightftp chatafl-enhanced out-lightftp-chatafl-enhanced "-P FTP -D 10000 -q 3 -s 3 -E -K -m none -t ${TEST_TIMEOUT}+" $TIMEOUT $SKIPCOUNT &
    fi
fi

# 对live555, dnsmasq等其他目标重复相同操作
```

---

## 📊 运行后查看结果

### 结果目录结构

```bash
benchmark/
└── results-lightftp/
    ├── out-lightftp-aflnet/
    ├── out-lightftp-chatafl/
    ├── out-lightftp-chatafl_cl1/
    ├── out-lightftp-chatafl_cl2/
    └── out-lightftp-chatafl-enhanced/  # Enhanced结果在这里
        ├── fuzzer_stats
        ├── plot_data
        ├── queue/
        ├── crashes/
        └── .stt_export/  # STT图文件
            ├── stt_cycle_100.dot
            ├── stt_cycle_200.dot
            └── ...
```

### 查看统计信息

```bash
# 查看fuzzer_stats
cat benchmark/results-lightftp/out-lightftp-chatafl-enhanced/fuzzer_stats

# 查看Enhanced特有日志
grep "Enhanced" benchmark/results-lightftp/out-lightftp-chatafl-enhanced/fuzzer_stats

# 示例输出:
# [*] Enhanced: Selected seed id:000042 (state rarity: 0.857)
# [+] STT exported to .stt_export/stt_cycle_100.dot
# [ENHANCED] ✓ Response ACCEPTED (status=200)
```

### 可视化STT

```bash
cd benchmark/results-lightftp/out-lightftp-chatafl-enhanced/.stt_export

# 生成PNG图像
for f in *.dot; do
    dot -Tpng "$f" -o "${f%.dot}.png"
done

# 查看图像
xdg-open stt_cycle_100.png
```

---

## 🛠️ 故障排除

### 问题1: "chatafl-enhanced: command not found"

**原因**: profuzzbench_exec_all.sh中未添加Enhanced分支

**解决方案**: 修改profuzzbench_exec_all.sh（见上文）

### 问题2: 没有看到Enhanced特有功能

**原因**: 未设置CHATAFL_ENHANCED环境变量

**解决方案**:
```bash
export CHATAFL_ENHANCED=1
export CEGAR_CACHE_DIR=$PWD/benchmark/results/.cegar_cache
./run.sh 2 1440 lightftp chatafl-enhanced
```

### 问题3: STT文件未生成

**原因**: 需要满足以下条件
- 运行超过100个fuzzing周期
- 启用state-aware模式 (`-K`参数)
- `CHATAFL_ENHANCED=1`已设置

**解决方案**: 确认AFL命令包含`-K`参数，等待运行超过100周期

---

## 📚 相关文档

- [BUILD_GUIDE.md](BUILD_GUIDE.md) - 构建指南
- [TASK_COMPLETION_SUMMARY.md](ChatAFL-Enhanced/TASK_COMPLETION_SUMMARY.md) - 功能完成总结
- [INTEGRATION_GUIDE.md](ChatAFL-Enhanced/INTEGRATION_GUIDE.md) - AFL集成详解

---

## ✅ 快速检查清单

运行前确认：

- [ ] 已构建ChatAFL-Enhanced (`./build_enhanced.sh`)
- [ ] 已修改profuzzbench_exec_all.sh添加Enhanced分支
- [ ] 已设置环境变量 (`CHATAFL_ENHANCED=1`)
- [ ] 目标程序已构建 (`cd benchmark/subjects/*/; ./build.sh`)
- [ ] 有足够磁盘空间（建议 >10GB）

运行命令：

```bash
export CHATAFL_ENHANCED=1
export CEGAR_CACHE_DIR=$PWD/benchmark/results/.cegar_cache
./run.sh <容器数> <分钟数> <目标> chatafl-enhanced
```

---

**文档版本**: v1.0  
**最后更新**: 2026-01-18  
**状态**: ✅ 需要修改profuzzbench_exec_all.sh
