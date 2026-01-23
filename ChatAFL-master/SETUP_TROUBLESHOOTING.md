# setup.sh 故障排除指南

## 问题 1: "sudo ./setup.sh" 失败（退出码 2）

### 现象
```bash
$ sudo ./setup.sh
NO OPENAI API KEY PROVIDED! Please set the KEY environment variable
$ echo $?
2
```

### 根本原因

**使用 `sudo` 运行脚本会导致环境变量丢失**：

```bash
# 普通用户环境
$ export KEY="sk-xxxxx"
$ echo $KEY
sk-xxxxx

# sudo 环境（新的 shell）
$ sudo echo $KEY
(空输出！环境变量丢失)
```

### 解决方案（3 种方式）

#### ✅ 方式 1：不使用 sudo（推荐）

```bash
# 1. 设置环境变量
export KEY="sk-your-openai-api-key-here"

# 2. 直接运行（不加 sudo）
./setup.sh
```

**为什么不需要 sudo？**
- setup.sh 只修改**当前用户的文件**
- 不需要系统级权限
- Docker 操作会在脚本调用 Docker 时自动处理权限

#### ✅ 方式 2：内联传递环境变量

```bash
# 一行命令完成
KEY="sk-your-openai-api-key-here" ./setup.sh
```

#### ⚠️ 方式 3：sudo 保留环境变量（不推荐）

```bash
# 如果必须使用 sudo
sudo KEY="$KEY" ./setup.sh

# 或者
sudo -E ./setup.sh  # -E 保留所有环境变量（有安全风险）
```

## 问题 2: 改进的 setup.sh 变更点

### 变更 1：更严格的错误检查

**之前**（有 bug）：
```bash
if [ -z $KEY ]; then  # ❌ 缺少引号，可能误判
    echo "NO OPENAI API KEY PROVIDED!"
    exit 0  # ❌ 应该是 exit 2 表示错误
fi
```

**现在**（已修复）：
```bash
if [ -z "$KEY" ]; then  # ✅ 正确的引号
    echo "❌ ERROR: NO OPENAI API KEY PROVIDED!"
    echo "详细的使用说明..."
    exit 2  # ✅ 错误退出码
fi

echo "✅ OpenAI API Key detected: ${KEY:0:10}..."  # ✅ 确认密钥已读取
```

### 变更 2：增强的用户反馈

**之前**：
```bash
for x in ChatAFL ChatAFL-CL1 ChatAFL-CL2 ChatAFL-Enhanced; do
  sed -i "s/..." $x/chat-llm.h  # 静默执行
done
```

**现在**：
```bash
echo "📝 Updating OpenAI API key in source files..."
for x in ChatAFL ChatAFL-CL1 ChatAFL-CL2 ChatAFL-Enhanced; do
  if [ -f "$x/chat-llm.h" ]; then
    sed -i "s/..." $x/chat-llm.h
    echo "  ✅ Updated $x/chat-llm.h"  # ✅ 进度反馈
  else
    echo "  ⚠️  Warning: $x/chat-llm.h not found"  # ✅ 错误提示
  fi
done
```

### 变更 3：更安全的路径处理

**之前**：
```bash
rm -r $subject/chatafl 2>&1 >/dev/null  # ❌ 路径未加引号
cp -r ChatAFL $subject/chatafl
```

**现在**：
```bash
rm -rf "$subject/chatafl" 2>/dev/null  # ✅ 引号保护，避免空格问题
cp -r ChatAFL "$subject/chatafl"       # ✅ -f 强制，避免确认提示
```

### 变更 4：完整性检查

**新增**：
```bash
target_count=0
for subject in ./benchmark/subjects/*/*; do
  if [ -d "$subject" ]; then  # ✅ 确认是目录
    target_count=$((target_count + 1))
    # ... 复制操作 ...
    echo "  ✅ Configured $(basename "$subject")"
  fi
done
echo "📊 Total targets configured: $target_count"  # ✅ 统计信息
```

### 变更 5：明确的成功提示

**新增**：
```bash
echo "✅ Setup completed successfully!"
echo ""
echo "Next steps:"
echo "  1. Run fuzzing: ./run.sh <containers> <timeout_min> <target> <fuzzer>"
echo "  2. Example: ./run.sh 5 10 kamailio chatafl"
```

## 遵循开闭原则的设计

### ✅ 对扩展开放

```bash
# 添加新版本只需在循环中添加
for x in ChatAFL ChatAFL-CL1 ChatAFL-CL2 ChatAFL-Enhanced NEW_VERSION;
#                                                      ^^^^^^^^^^^
# 不需要修改其他代码
```

### ✅ 对修改关闭

```bash
# 核心逻辑保持不变
# 只增强：
# - 错误提示（扩展功能）
# - 进度反馈（扩展功能）
# - 安全检查（扩展功能）
```

## 完整的正确工作流程

```bash
# 步骤 1: 克隆项目（如果还没有）
cd ~/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master

# 步骤 2: 设置 OpenAI API 密钥
export KEY="sk-your-actual-openai-api-key-here"

# 步骤 3: 验证环境变量
echo $KEY
# 应该输出: sk-your-actual-openai-api-key-here

# 步骤 4: 运行 setup.sh（不要用 sudo）
./setup.sh

# 预期输出:
# ✅ OpenAI API Key detected: sk-your-ac...
# 📝 Updating OpenAI API key in source files...
#   ✅ Updated ChatAFL/chat-llm.h
#   ✅ Updated ChatAFL-CL1/chat-llm.h
#   ✅ Updated ChatAFL-CL2/chat-llm.h
#   ✅ Updated ChatAFL-Enhanced/chat-llm.h
# 📦 Copying fuzzer sources to benchmark directories...
#   ✅ Configured BFTPD
#   ✅ Configured LightFTP
#   ... (更多目标)
#   📊 Total targets configured: 9
# 🐳 Building Docker images...
#   (This may take 10-30 minutes for the first time)
# ... (Docker 构建日志)
# ✅ Setup completed successfully!

# 步骤 5: 运行模糊测试
./run.sh 5 10 kamailio chatafl
```

## 常见错误与解决

### 错误 1: "Permission denied"

```bash
$ ./setup.sh
bash: ./setup.sh: Permission denied
```

**解决**：
```bash
chmod +x setup.sh
./setup.sh
```

### 错误 2: "Docker daemon not running"

```bash
Cannot connect to the Docker daemon at unix:///var/run/docker.sock
```

**解决**：
```bash
# 启动 Docker 服务
sudo systemctl start docker

# 或者（macOS）
open -a Docker

# 验证
docker info
```

### 错误 3: "sed: can't read ChatAFL/chat-llm.h"

**原因**：源代码目录不存在

**解决**：
```bash
# 确认在正确目录
pwd
# 应该输出: .../ChatAFL-master

# 检查目录结构
ls -la
# 应该看到: ChatAFL/ ChatAFL-CL1/ ChatAFL-CL2/ ChatAFL-Enhanced/
```

## 验证 setup 成功

```bash
# 检查 1: API 密钥已更新
grep "OPENAI_TOKEN" ChatAFL/chat-llm.h
# 应该看到: #define OPENAI_TOKEN "sk-your-key..."

# 检查 2: 源码已复制
ls benchmark/subjects/SIP/Kamailio/
# 应该看到: chatafl/ chatafl-cl1/ chatafl-cl2/ chatafl-enhanced/

# 检查 3: Docker 镜像已构建
docker images | grep kamailio
# 应该看到: kamailio  latest  ...

# 检查 4: afl-fuzz 可执行
ls -la benchmark/subjects/SIP/Kamailio/chatafl/afl-fuzz
# 应该看到: -rwxr-xr-x ... afl-fuzz
```

## 调试技巧

### 开启详细日志

```bash
# 方式 1: 使用 bash -x
bash -x ./setup.sh

# 方式 2: 在脚本开头添加
#!/bin/bash
set -x  # 开启调试
set -e  # 遇到错误立即退出
```

### 分步执行

```bash
# 只更新 API 密钥
export KEY="sk-xxx"
for x in ChatAFL ChatAFL-CL1 ChatAFL-CL2 ChatAFL-Enhanced; do
  sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$KEY\"/" $x/chat-llm.h
done

# 只复制源码（跳过 Docker 构建）
# 注释掉 setup.sh 最后的 profuzzbench_build_all.sh 调用
```

## 相关文档

- 📖 [问题诊断与解决方案.md](问题诊断与解决方案.md) - 为何容器运行 58 分钟无结果
- 📖 [SETUP_SH_EXPLANATION.md](SETUP_SH_EXPLANATION.md) - setup.sh 详细说明
- 📖 [COMPREHENSIVE_COMPARISON.md](COMPREHENSIVE_COMPARISON.md) - ChatAFL vs ChatAFL-Enhanced
- 🔧 [verify_chatafl_enhanced.sh](verify_chatafl_enhanced.sh) - 自动验证脚本

---

**总结**：setup.sh 失败的主要原因是使用了 `sudo` 导致环境变量丢失。改进后的脚本提供了更清晰的错误提示、进度反馈和使用指导，同时遵循开闭原则，保持了可扩展性。
