# 🧪 本地运行模糊测试指南（以 LightFTP 为例）

## 📋 前提条件检查

### 1. 确认环境已更新
```bash
# 检查 benchmark 中的 chatafl-opt 是否包含新扩展
test -f benchmark/subjects/FTP/LightFTP/chatafl-opt/fuzzer_extension.h && \
  echo "✅ 已包含扩展" || \
  echo "❌ 需要先运行 setup.sh"
```

### 2. 如果需要，先运行 setup.sh
```bash
# 回到项目根目录
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master

# 设置 OpenAI API Key
export KEY="sk-your-openai-api-key-here"

# 运行 setup.sh（会将所有 fuzzer 版本复制到 benchmark）
./setup.sh

# 等待完成...这会复制代码到所有 subjects 并开始构建 Docker 镜像
```

---

## 🎯 方式 1: 使用 Docker 容器（推荐）

### 为什么推荐 Docker？
- ✅ 环境隔离，不污染主机
- ✅ 自动配置所有依赖
- ✅ 与论文/benchmark 环境一致

### 步骤 1: 构建 Docker 镜像
```bash
cd benchmark/subjects/FTP/LightFTP

# 构建 LightFTP 镜像（包含所有 fuzzer 版本）
docker build -t lightftp-image .
```

### 步骤 2: 启动容器并进入
```bash
# 启动容器（交互式）
docker run -it --name lightftp-test lightftp-image /bin/bash

# 现在你在容器内，用户是 ubuntu，工作目录是 /home/ubuntu
```

### 步骤 3: 在容器内运行 fuzzing

#### 3a. 测试原版 AFLNet（基线）
```bash
# 在容器内执行
cd /home/ubuntu/experiments/LightFTP/Source/Release

# 运行 AFLNet（60秒测试）
timeout -k 2s 60s /home/ubuntu/aflnet/afl-fuzz \
  -d -i /home/ubuntu/experiments/in-ftp \
  -x /home/ubuntu/experiments/ftp.dict \
  -o out-aflnet \
  -N tcp://127.0.0.1/2200 \
  -c /home/ubuntu/experiments/ftpclean \
  ./fftp fftp.conf 2200
```

#### 3b. 测试 ChatAFL-Opt（扩展禁用模式）
```bash
# 在容器内执行
cd /home/ubuntu/experiments/LightFTP/Source/Release

# 清理之前的输出
rm -rf out-chatafl-opt

# 运行 ChatAFL-Opt（扩展默认禁用，行为类似 ChatAFL）
timeout -k 2s 60s /home/ubuntu/chatafl-opt/afl-fuzz \
  -d -i /home/ubuntu/experiments/in-ftp \
  -x /home/ubuntu/experiments/ftp.dict \
  -o out-chatafl-opt \
  -N tcp://127.0.0.1/2200 \
  -c /home/ubuntu/experiments/ftpclean \
  ./fftp fftp.conf 2200
```

#### 3c. 测试 ChatAFL-Opt（扩展启用模式）⭐
```bash
# 在容器内执行
cd /home/ubuntu/experiments/LightFTP/Source/Release

# 启用 ChatAFL-Opt 扩展
export AFL_ENABLE_CHATAFL_OPT=1
export KEY="sk-your-openai-api-key-here"

# 清理之前的输出
rm -rf out-chatafl-opt-enabled

# 运行 ChatAFL-Opt（5 个模块全部启用）
timeout -k 2s 300s /home/ubuntu/chatafl-opt/afl-fuzz \
  -d -i /home/ubuntu/experiments/in-ftp \
  -x /home/ubuntu/experiments/ftp.dict \
  -o out-chatafl-opt-enabled \
  -N tcp://127.0.0.1/2200 \
  -c /home/ubuntu/experiments/ftpclean \
  ./fftp fftp.conf 2200

# 注意：需要运行至少 5 分钟才能触发平台期检测和 Hypothesis 生成
```

### 步骤 4: 查看结果

#### 检查扩展是否启用
```bash
# 应该看到类似输出：
# [ChatAFL-Opt] Extension initialized successfully
# [ChatAFL-Opt] Hypothesis context: enabled
# [ChatAFL-Opt] Verifier context: enabled
# [ChatAFL-Opt] CEGAR context: enabled
# [ChatAFL-Opt] Scheduler context: enabled
```

#### 查看 fuzzer 统计
```bash
# 在容器内
cat /home/ubuntu/experiments/LightFTP/Source/Release/out-chatafl-opt-enabled/fuzzer_stats

# 重点关注：
# - execs_done: 执行次数
# - paths_total: 发现路径数
# - unique_crashes: 崩溃数
# - coverage: 代码覆盖率
```

#### 查看扩展统计（退出时输出）
```bash
# fuzzer 退出时会输出：
# [ChatAFL-Opt] Statistics:
# - Hypotheses Generated: XX
# - Verifications: XX
# - Refinements: XX
# - State Transitions: XX
```

### 步骤 5: 退出容器并提取结果
```bash
# 在容器内按 Ctrl+C 停止 fuzzing，然后退出
exit

# 在主机上复制结果
docker cp lightftp-test:/home/ubuntu/experiments/LightFTP/Source/Release/out-chatafl-opt-enabled ./results-local-test

# 查看结果
ls -la results-local-test/
cat results-local-test/fuzzer_stats
```

---

## 🔧 方式 2: 本地直接运行（不使用 Docker）

### ⚠️ 注意事项
- 需要手动配置环境
- 需要手动编译 LightFTP
- 可能与系统环境冲突

### 步骤 1: 准备环境

```bash
# 安装依赖
sudo apt-get update
sudo apt-get install -y \
  build-essential clang llvm \
  libgnutls28-dev libssl-dev \
  libcap-dev libpcre2-dev \
  libcurl4-openssl-dev libjson-c-dev \
  graphviz-dev

# 确认已编译 ChatAFL-Opt
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/ChatAFL-Opt
test -f afl-fuzz && echo "✅ afl-fuzz 已编译" || (echo "❌ 需要编译" && make clean all)
```

### 步骤 2: 下载并编译 LightFTP

```bash
# 创建工作目录
mkdir -p ~/lightftp-fuzzing-test
cd ~/lightftp-fuzzing-test

# 下载 LightFTP
git clone https://github.com/hfiref0x/LightFTP.git
cd LightFTP
git checkout 139af7c

# 应用 fuzzing patch
cp /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/benchmark/subjects/FTP/LightFTP/fuzzing.patch ./
patch -p1 < fuzzing.patch

# 使用 ChatAFL-Opt 的 afl-clang-fast 编译
cd Source/Release
export AFL_PATH=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/ChatAFL-Opt
export PATH=$AFL_PATH:$PATH

# 编译（使用 ASAN）
AFL_USE_ASAN=1 CC=afl-clang-fast make clean all
```

### 步骤 3: 准备配置和种子

```bash
# 复制配置文件
cd ~/lightftp-fuzzing-test/LightFTP/Source/Release
cp /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/benchmark/subjects/FTP/LightFTP/in-ftp ~/lightftp-fuzzing-test/seeds
cp /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/benchmark/subjects/FTP/LightFTP/ftp.dict ~/lightftp-fuzzing-test/
cp /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/benchmark/subjects/FTP/LightFTP/clean.sh ~/lightftp-fuzzing-test/ftpclean.sh
chmod +x ~/lightftp-fuzzing-test/ftpclean.sh

# 准备证书和共享目录（LightFTP 需要）
mkdir -p ~/certificate
mkdir -p ~/ftpshare

# 复制配置
cp /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/ChatAFL-Opt/tutorials/lightftp/fftp.conf ./
```

### 步骤 4: 运行 Fuzzing

```bash
# 设置环境变量
export AFL_PATH=/home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/ChatAFL-Opt
export PATH=$AFL_PATH:$PATH
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
export AFL_SKIP_CPUFREQ=1
export AFL_NO_AFFINITY=1

# 启用 ChatAFL-Opt 扩展
export AFL_ENABLE_CHATAFL_OPT=1
export KEY="sk-your-openai-api-key-here"

# 运行 fuzzing（5分钟测试）
cd ~/lightftp-fuzzing-test/LightFTP/Source/Release

timeout -k 2s 300s $AFL_PATH/afl-fuzz \
  -d -i ~/lightftp-fuzzing-test/seeds \
  -x ~/lightftp-fuzzing-test/ftp.dict \
  -o out-local-test \
  -N tcp://127.0.0.1/2200 \
  -c ~/lightftp-fuzzing-test/ftpclean.sh \
  ./fftp fftp.conf 2200
```

### 步骤 5: 查看结果

```bash
# 查看统计
cat ~/lightftp-fuzzing-test/LightFTP/Source/Release/out-local-test/fuzzer_stats

# 查看发现的队列
ls ~/lightftp-fuzzing-test/LightFTP/Source/Release/out-local-test/queue/

# 查看崩溃（如果有）
ls ~/lightftp-fuzzing-test/LightFTP/Source/Release/out-local-test/crashes/
```

---

## 🎯 方式 3: 使用 run.sh 脚本（批量测试）

这是 ProFuzzBench 的标准方式，适合多目标、多 fuzzer 对比测试。

### 步骤 1: 确保已运行 setup.sh
```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
export KEY="sk-your-key"
./setup.sh  # 会复制代码并构建镜像
```

### 步骤 2: 运行单个测试
```bash
# 语法：./run.sh 容器数 超时(分钟) 目标 fuzzer列表
# 测试 LightFTP，使用 chatafl-opt，2个容器，60分钟
./run.sh 2 60 lightftp chatafl-opt
```

### 步骤 3: 运行对比测试
```bash
# 对比 aflnet, chatafl, chatafl-opt
./run.sh 2 60 lightftp aflnet,chatafl,chatafl-opt

# 这会启动 2×3=6 个容器，每个运行 60 分钟
```

### 步骤 4: 查看结果
```bash
# 结果会保存在 benchmark/results-lightftp_日期_时间/
ls benchmark/results-*/

# 查看 CSV 统计
cat benchmark/results-*/results.csv
```

---

## 📊 验证扩展是否实际运行

### 检查点 1: 初始化消息
```bash
# 在 fuzzer 启动时应该看到：
[ChatAFL-Opt] Extension initialized successfully
[ChatAFL-Opt] Hypothesis context: enabled
[ChatAFL-Opt] Verifier context: enabled
[ChatAFL-Opt] CEGAR context: enabled
[ChatAFL-Opt] Scheduler context: enabled
```

### 检查点 2: 运行时日志
```bash
# 如果设置了 AFL_DEBUG=1，会看到更多日志
export AFL_DEBUG=1

# 应该看到：
[ChatAFL-Opt] Plateau detected at execution XXX
[ChatAFL-Opt] Generating hypotheses...
[ChatAFL-Opt] Verifying message...
[ChatAFL-Opt] Refinement triggered...
```

### 检查点 3: 退出统计
```bash
# fuzzer 退出时应该输出：
[ChatAFL-Opt] Statistics:
  Hypotheses Generated: XX
  Verifications Performed: XX
  Refinements: XX
  State Transitions: XX
```

### 检查点 4: 输出目录
```bash
# 检查是否有扩展生成的文件
ls out-chatafl-opt-enabled/protocol-grammars/  # Hypothesis 生成的语法
ls out-chatafl-opt-enabled/regions/            # IPSM 状态信息
```

---

## 🔍 常见问题排查

### Q1: "扩展文件不存在"
```bash
# 解决：运行 setup.sh
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
export KEY="your-key"
./setup.sh
```

### Q2: 没有看到 [ChatAFL-Opt] 初始化消息
```bash
# 检查环境变量
echo $AFL_ENABLE_CHATAFL_OPT  # 应该是 1
echo $KEY  # 应该显示你的 API key

# 重新设置
export AFL_ENABLE_CHATAFL_OPT=1
export KEY="sk-xxx"
```

### Q3: LightFTP 启动失败
```bash
# 检查端口占用
netstat -tuln | grep 2200

# 杀死占用进程
fuser -k 2200/tcp

# 或使用不同端口
./fftp fftp.conf 2201  # 使用 2201 端口
```

### Q4: Docker 镜像构建失败
```bash
# 清理并重建
docker system prune -a
cd benchmark/subjects/FTP/LightFTP
docker build --no-cache -t lightftp-image .
```

### Q5: 性能太慢
```bash
# 禁用 ASAN（更快但失去崩溃检测）
# 修改 Dockerfile 中的编译命令，去掉 AFL_USE_ASAN=1

# 或者调整 CPU 核心绑定
export AFL_NO_AFFINITY=0  # 启用 CPU 亲和性
```

---

## 📝 快速参考

### 推荐的测试命令（Docker 容器内）

```bash
# 1. 短时间测试（1分钟）- 验证扩展加载
export AFL_ENABLE_CHATAFL_OPT=1
export KEY="sk-xxx"
timeout 60s /home/ubuntu/chatafl-opt/afl-fuzz -d \
  -i /home/ubuntu/experiments/in-ftp \
  -x /home/ubuntu/experiments/ftp.dict \
  -o out-test \
  -N tcp://127.0.0.1/2200 \
  -c /home/ubuntu/experiments/ftpclean \
  ./fftp fftp.conf 2200

# 2. 中等时间测试（5分钟）- 触发平台期
timeout 300s /home/ubuntu/chatafl-opt/afl-fuzz -d \
  -i /home/ubuntu/experiments/in-ftp \
  -x /home/ubuntu/experiments/ftp.dict \
  -o out-test-5min \
  -N tcp://127.0.0.1/2200 \
  -c /home/ubuntu/experiments/ftpclean \
  ./fftp fftp.conf 2200

# 3. 长时间测试（60分钟）- 完整评估
timeout 3600s /home/ubuntu/chatafl-opt/afl-fuzz -d \
  -i /home/ubuntu/experiments/in-ftp \
  -x /home/ubuntu/experiments/ftp.dict \
  -o out-test-60min \
  -N tcp://127.0.0.1/2200 \
  -c /home/ubuntu/experiments/ftpclean \
  ./fftp fftp.conf 2200
```

---

## 🎓 总结

| 方式 | 优点 | 缺点 | 推荐场景 |
|------|------|------|----------|
| **Docker 容器** | 环境一致，易复现 | 需要构建镜像 | ⭐ 首选 |
| **本地直接运行** | 快速测试 | 环境配置复杂 | 快速验证 |
| **run.sh 批量** | 自动化对比 | 耗时长 | 论文实验 |

**最佳实践**:
1. 首次测试：使用 Docker 容器（方式 1）
2. 快速迭代：本地直接运行（方式 2）
3. 正式评估：run.sh 批量测试（方式 3）

---

**创建日期**: 2026-02-04  
**适用版本**: ChatAFL-Opt 2.0 Plugin Architecture  
