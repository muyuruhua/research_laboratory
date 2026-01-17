# ChatAFL vs ChatAFL-Enhanced 对比测试快速指南

## 问题解决

### ❌ 错误1: "ChatAFL未构建"

**原因**: ChatAFL fuzzer未编译

**解决方案**:
```bash
cd ChatAFL
make clean && make -j$(nproc)
cd ..
```

### ❌ 错误2: "ChatAFL-Enhanced未构建"

**原因**: ChatAFL-Enhanced fuzzer未编译

**解决方案**:
```bash
cd ChatAFL-Enhanced
make standalone && make integrated
# 将ChatAFL的编译文件复制过来
cp ../ChatAFL/afl-* .
cp ../ChatAFL/*.o .
cd ..
```

### ❌ 错误3: "目标目录不存在"

**原因**: 目标名称大小写错误

**正确的目标名称**:
- ✅ `LightFTP` (不是 lightftp)
- ✅ `Live555` (不是 live555)
- ✅ `Exim` (不是 exim)

**查看所有可用目标**:
```bash
ls -d benchmark/subjects/*/*
```

### ❌ 错误4: "种子目录不存在"

**原因**: 目标程序未准备好

**解决方案**: 检查目标目录下的种子
```bash
ls benchmark/subjects/FTP/LightFTP/in-*
```

## ✅ 完整构建流程

```bash
# 1. 编译ChatAFL
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/ChatAFL
make clean && make -j$(nproc)
cd ..

# 2. 编译ChatAFL-Enhanced
cd ChatAFL-Enhanced
make standalone && make integrated
cp ../ChatAFL/afl-fuzz .
cd ..

# 3. 运行对比测试
./compare_fuzzers.sh LightFTP FTP 1   # 1分钟测试
./compare_fuzzers.sh LightFTP FTP 60  # 1小时测试
```

## 📝 使用方法

```bash
./compare_fuzzers.sh <TARGET> <PROTOCOL> <TIMEOUT_MINUTES>

# 示例
./compare_fuzzers.sh LightFTP FTP 60      # LightFTP，1小时
./compare_fuzzers.sh Live555 RTSP 1440    # Live555，24小时
./compare_fuzzers.sh Exim SMTP 120        # Exim，2小时
```

## �� 查看结果

测试完成后，结果保存在 `comparison_results/` 目录：

```bash
comparison_results/
└── LightFTP_20260118_012100/
    ├── report.txt              # 对比报告
    ├── chatafl.log             # ChatAFL日志
    ├── enhanced.log            # Enhanced日志
    ├── chatafl/                # ChatAFL输出
    │   └── fuzzer_stats
    └── chatafl-enhanced/       # Enhanced输出
        ├── fuzzer_stats
        ├── .stt_export/        # STT文件
        └── .cegar_cache/       # CEGAR补丁
```

查看报告:
```bash
cat comparison_results/LightFTP_*/report.txt
```

## 🎯 对比内容

脚本会自动对比:

**ChatAFL (基础版)**:
- execs_done (执行次数)
- execs_per_sec (执行速度)
- paths_total (路径总数)
- unique_crashes (崩溃数量)
- bitmap_cvg (覆盖率)

**ChatAFL-Enhanced (增强版)**:
- 上述所有指标
- **+ STT导出数量** (状态转移树)
- **+ CEGAR补丁数量** (反例引导抽象精化)
- **+ Verifier验证** (语法正确性验证)

## 🚀 快速测试

```bash
# 1分钟快速测试
./compare_fuzzers.sh LightFTP FTP 1

# 查看结果
cat comparison_results/LightFTP_*/report.txt
```
