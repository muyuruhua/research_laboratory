# ChatAFL-Enhanced 使用指南

## 概述

ChatAFL-Enhanced 是 ChatAFL 的学术研究增强版本，引入了以下高级功能：

- ✅ **四维验证框架**：语法可解析性、协议可接受性、状态可达性、覆盖率增益
- ✅ **CEGAR精化循环**：反例引导的抽象精化
- ✅ **状态感知调度**：基于状态稀有度的智能调度
- ✅ **CFG语法解析**：上下文无关文法支持
- ✅ **模块化架构**：解耦的观察者模式设计

## 编译选项

ChatAFL-Enhanced 支持**条件编译**，遵循开闭原则：

### 1. 基础模式（与 ChatAFL 兼容）

```bash
cd ChatAFL-Enhanced
make clean all
# 此时行为与 ChatAFL 完全相同，不包含增强模块
```

### 2. 增强模式（启用所有高级功能）

```bash
cd ChatAFL-Enhanced
make clean all CHATAFL_ENHANCED=1
# 编译包含 verifier, CEGAR, state-scheduler 等模块
```

## 使用 run.sh 脚本执行

### 语法

```bash
./run.sh <容器数量> <超时时间(分钟)> <目标> <模糊器>
```

### 示例

```bash
# 使用 ChatAFL-Enhanced 测试 kamailio (5个容器，10分钟)
./run.sh 5 10 kamailio chatafl-enhanced

# 使用 ChatAFL-Enhanced 测试 lightftp (3个容器，30分钟)
./run.sh 3 30 lightftp chatafl-enhanced

# 使用 ChatAFL-Enhanced 测试 live555 (5个容器，60分钟)
./run.sh 5 60 live555 chatafl-enhanced
```

### 支持的目标

- **FTP**: `lightftp`, `bftpd`, `proftpd`, `pure-ftpd`
- **SMTP**: `exim`
- **RTSP**: `live555`
- **SIP**: `kamailio`
- **DAAP**: `forked-daapd`
- **HTTP**: `lighttpd1`

## 直接使用二进制

```bash
# 启用增强功能编译
cd ChatAFL-Enhanced
make clean all CHATAFL_ENHANCED=1

# 运行模糊测试
./afl-fuzz -i input_dir -o output_dir -P <PROTOCOL> -N <NETINFO> -- target_binary

# 示例：测试 FTP 服务器
./afl-fuzz -i in-ftp -o out-ftp -P FTP -D 10000 -q 3 -s 3 -E -K -- ./lightftpd
```

## 验证编译状态

### 检查是否启用了增强功能

```bash
# 查看编译输出
make clean all CHATAFL_ENHANCED=1 2>&1 | grep -i enhanced

# 检查二进制文件中的符号
strings afl-fuzz | grep -i "verifier\|cegar\|scheduler"

# 查看链接的对象文件
nm afl-fuzz | grep -i "verifier_\|cegar_\|scheduler_"
```

### 预期输出

启用 `CHATAFL_ENHANCED=1` 时，编译输出应包含：
```
[+] ENHANCED BUILD - All modules included.
```

不启用时，输出应为：
```
[!] BASIC BUILD - Enhanced modules not included. Set CHATAFL_ENHANCED=1 to enable.
```

## 架构差异

### 编译依赖

| 组件 | ChatAFL | ChatAFL-Enhanced (基础) | ChatAFL-Enhanced (增强) |
|------|---------|------------------------|------------------------|
| AFL 核心 | ✅ | ✅ | ✅ |
| chat-llm | ✅ | ✅ | ✅ |
| verifier | ❌ | ❌ | ✅ |
| CEGAR | ❌ | ❌ | ✅ |
| state-scheduler | ❌ | ❌ | ✅ |
| state-graph | ❌ | ❌ | ✅ |

### 代码量对比

- **ChatAFL**: ~26,000 行
- **ChatAFL-Enhanced (基础)**: ~26,000 行
- **ChatAFL-Enhanced (增强)**: ~50,926 行 (+97%)

## 性能考虑

增强模式会引入额外开销：

1. **验证开销**: 每个生成的测试用例需要经过四维验证
2. **CEGAR开销**: 失败用例需要精化迭代
3. **状态追踪开销**: 维护状态转换图

**建议**：
- 对于快速原型测试，使用基础模式
- 对于深度协议分析，使用增强模式
- 对于性能基准测试，先用基础模式建立基线

## Docker 支持

所有 Dockerfile 已配置为同时构建基础和增强版本：

```dockerfile
COPY --chown=ubuntu:ubuntu chatafl-enhanced chatafl-enhanced
RUN cd chatafl-enhanced && \
    make clean all CHATAFL_ENHANCED=1 $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT
```

## 故障排除

### 编译错误

**问题**: `verifier.h: No such file or directory`

**解决**:
```bash
# 确保未设置 CHATAFL_ENHANCED 标志
make clean all  # 不要加 CHATAFL_ENHANCED=1
```

### 链接错误

**问题**: `undefined reference to verifier_xxx`

**原因**: 设置了 `CHATAFL_ENHANCED=1` 但缺少源文件

**解决**:
```bash
# 检查是否有所有必需的源文件
ls -la verifier.c cegar-*.c state-*.c cfg-parser.c module-interface.c
```

### 运行时错误

**问题**: Docker 容器找不到 `chatafl-enhanced`

**解决**:
```bash
# 检查 Dockerfile 是否包含 COPY 和 RUN 指令
grep -A2 "chatafl-enhanced" benchmark/subjects/*/*/Dockerfile

# 重新构建 Docker 镜像
cd benchmark
docker build -t <target>-fuzzing subjects/<protocol>/<target>/
```

## 开发者信息

### 遵循的设计原则

1. **开闭原则**: 对扩展开放，对修改关闭
   - 通过条件编译实现功能扩展
   - 不修改 ChatAFL 原有代码路径

2. **单一职责原则**: 每个模块专注单一功能
   - `verifier.*`: 仅负责验证
   - `cegar-*.*`: 仅负责精化
   - `state-*.*`: 仅负责状态管理

3. **依赖倒置原则**: 通过接口解耦
   - `module-interface.*`: 定义模块间通信接口

## 引用

如果您在研究中使用 ChatAFL-Enhanced，请引用：

```bibtex
@inproceedings{chatafl2024,
  title={ChatAFL: LLM-Powered Fuzzing for Stateful Network Protocols},
  author={...},
  booktitle={...},
  year={2024}
}
```

## 许可证

继承自 AFL，遵循 Apache License 2.0。增强模块同样采用 Apache License 2.0。
