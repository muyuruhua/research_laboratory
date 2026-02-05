# 🚀 完整设置与运行指南

## ✅ 已完成的优化

### 1. 代码层面
- ✅ ChatAFL-Opt 插件化架构实现（fuzzer_extension + chatafl_opt_extension）
- ✅ 5 个模块通过钩子实际运行（Hypothesis, Verifier, CEGAR, Scheduler, Integration）
- ✅ 完全符合开闭原则（afl-fuzz.c 仅 30 行插入）

### 2. 脚本层面（刚刚完成）
- ✅ 修改 `profuzzbench_exec_common.sh`
- ✅ **自动为 chatafl-opt 启用扩展**
- ✅ 其他 fuzzer 不受影响

---

## 📋 现在的工作流程

### 步骤 1: 设置 API Key
```bash
# 在主机上设置（setup.sh 和 run.sh 会使用）
export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"
```

### 步骤 2: 运行 setup.sh（复制代码 + 构建镜像）
```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master

# 会做三件事：
# 1. 更新所有版本的 chat-llm.h 中的 OPENAI_TOKEN
# 2. 复制所有 fuzzer 到 benchmark/subjects/*/*
# 3. 构建所有 Docker 镜像
./setup.sh
```

### 步骤 3: 运行实验
```bash
# 测试单个 fuzzer（chatafl-opt）
./run.sh 2 60 lightftp chatafl-opt

# 对比多个 fuzzer
./run.sh 2 60 lightftp aflnet,chatafl,chatafl-opt

# 运行所有 fuzzer
./run.sh 2 60 lightftp all
```

---

## 🔍 现在的环境变量传递机制

### profuzzbench_exec_common.sh 的逻辑（已修改）

```bash
# 第 19-27 行（新逻辑）
for i in $(seq 1 $RUNS); do
  # 为 chatafl-opt 启用扩展
  if [[ $FUZZER == "chatafl-opt" ]]; then
    id=$(docker run --cpus=1 \
      -e KEY="$KEY" \                      # ← 传递 API Key
      -e AFL_ENABLE_CHATAFL_OPT=1 \        # ← 启用扩展
      -d -it $DOCIMAGE /bin/bash -c "cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
  else
    id=$(docker run --cpus=1 \
      -e KEY="$KEY" \                      # ← 只传递 API Key
      -d -it $DOCIMAGE /bin/bash -c "cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
  fi
  cids+=(${id::12})
done
```

### 环境变量流向

```
主机环境
  export KEY="sk-xxx"
       ↓
  run.sh 读取 $KEY
       ↓
  profuzzbench_exec_all.sh 继承 $KEY
       ↓
  profuzzbench_exec_common.sh
       ↓
  docker run -e KEY="$KEY"          ← 传递给容器
  docker run -e AFL_ENABLE_CHATAFL_OPT=1  ← 只给 chatafl-opt
       ↓
  容器内环境变量
    - $KEY 可用
    - $AFL_ENABLE_CHATAFL_OPT 仅 chatafl-opt 可用
       ↓
  afl-fuzz 读取环境变量
    if (getenv("AFL_ENABLE_CHATAFL_OPT")) {
        // 初始化扩展
    }
```

---

## 🎯 验证扩展是否启用

### 方法 1: 检查容器日志

```bash
# 运行测试
./run.sh 2 60 lightftp chatafl-opt

# 查看容器日志（在运行中）
docker ps  # 找到容器 ID
docker logs <container_id> | grep ChatAFL-Opt

# 应该看到：
# [ChatAFL-Opt] Extension initialized successfully
# [ChatAFL-Opt] Hypothesis context: enabled
# [ChatAFL-Opt] Verifier context: enabled
```

### 方法 2: 进入容器检查环境变量

```bash
# 手动启动一个测试容器
docker run -it \
  -e KEY="$KEY" \
  -e AFL_ENABLE_CHATAFL_OPT=1 \
  lightftp /bin/bash

# 在容器内检查
echo $KEY
echo $AFL_ENABLE_CHATAFL_OPT

# 运行 fuzzer
cd /home/ubuntu/experiments/LightFTP/Source/Release
/home/ubuntu/chatafl-opt/afl-fuzz -d \
  -i /home/ubuntu/experiments/in-ftp \
  -o test-output \
  -N tcp://127.0.0.1/2200 \
  ./fftp fftp.conf 2200

# 看到初始化消息就说明成功了
```

### 方法 3: 检查输出文件

```bash
# 提取结果后
tar -xzf benchmark/results-*/out-lightftp-chatafl_opt_1.tar.gz

# 检查扩展生成的文件
ls out-lightftp-chatafl_opt/protocol-grammars/  # Hypothesis 生成的语法
ls out-lightftp-chatafl_opt/regions/            # IPSM 状态
```

---

## 📊 对比实验示例

### 实验 1: AFL 变体对比（不含扩展）

```bash
export KEY="sk-xxx"

# 对比 aflnet, chatafl, chatafl-cl1, chatafl-cl2
./run.sh 5 60 lightftp aflnet,chatafl,chatafl-cl1,chatafl-cl2

# 结果：
# - aflnet: 基线
# - chatafl: ChatAFL 原版
# - chatafl-cl1: Chain-Learning 1
# - chatafl-cl2: Chain-Learning 2
```

### 实验 2: ChatAFL-Opt 扩展影响

```bash
export KEY="sk-xxx"

# 对比 chatafl vs chatafl-opt
./run.sh 5 120 lightftp chatafl,chatafl-opt

# chatafl-opt 会自动启用扩展
# 结果对比：
# - 路径覆盖
# - 崩溃数量
# - 执行速度
# - LLM 调用次数
```

### 实验 3: 多目标对比

```bash
export KEY="sk-xxx"

# 测试 LightFTP 和 BFTPD
./run.sh 3 90 lightftp,bftpd chatafl-opt

# 会启动 3×2=6 个容器
```

---

## 🔧 故障排查

### Q1: 没有看到 [ChatAFL-Opt] 初始化消息

**检查环境变量传递**:
```bash
# 确认主机上设置了 KEY
echo $KEY

# 检查容器内
docker exec <container_id> env | grep KEY
docker exec <container_id> env | grep AFL_ENABLE_CHATAFL_OPT

# 应该都有输出
```

### Q2: 其他 fuzzer 被意外启用扩展

**检查 profuzzbench_exec_common.sh**:
```bash
grep -A5 "if.*chatafl-opt" benchmark/scripts/execution/profuzzbench_exec_common.sh

# 应该看到条件判断：
# if [[ $FUZZER == "chatafl-opt" ]]; then
#   ... -e AFL_ENABLE_CHATAFL_OPT=1 ...
```

### Q3: API Key 无效

**检查 setup.sh 是否更新了 chat-llm.h**:
```bash
# 查看 ChatAFL-Opt 中的 API Key
grep "OPENAI_TOKEN" ChatAFL-Opt/chat-llm.h

# 应该显示：
# #define OPENAI_TOKEN "sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"
```

**如果不一致**:
```bash
# 重新运行 setup.sh
export KEY="sk-xxx"
./setup.sh
```

### Q4: 容器启动失败

**检查镜像是否存在**:
```bash
docker images | grep lightftp

# 如果没有镜像
cd benchmark/subjects/FTP/LightFTP
docker build -t lightftp .
```

---

## 📝 完整示例：从零到运行

```bash
# 1. 进入项目目录
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master

# 2. 设置 API Key
export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"

# 3. 运行 setup（复制代码 + 更新 Key + 构建镜像）
./setup.sh
# 等待... 会显示每个镜像的构建进度

# 4. 验证镜像构建成功
docker images | grep -E "lightftp|bftpd|proftpd"

# 5. 运行快速测试（2容器 × 5分钟）
./run.sh 2 5 lightftp chatafl-opt

# 6. 等待完成后查看结果
ls benchmark/results-lightftp_*/
cat benchmark/results-lightftp_*/results.csv

# 7. 运行完整对比实验（5容器 × 60分钟）
./run.sh 5 60 lightftp aflnet,chatafl,chatafl-opt

# 8. 分析结果
cd benchmark
./analyze.sh lightftp 60
```

---

## 🎓 关键要点

### ✅ 环境变量传递路径

```
主机 export KEY
    ↓
setup.sh 读取并写入 chat-llm.h
    ↓
run.sh 继承 $KEY
    ↓
profuzzbench_exec_common.sh
    ↓
docker run -e KEY="$KEY" -e AFL_ENABLE_CHATAFL_OPT=1
    ↓
容器内 afl-fuzz 读取环境变量
```

### ✅ 自动化决策

- **chatafl-opt**: 自动启用 `AFL_ENABLE_CHATAFL_OPT=1`
- **其他 fuzzer**: 不设置该变量

### ✅ 灵活性

- 可单独测试任何 fuzzer
- 可对比多个 fuzzer
- 扩展启用/禁用完全自动化

---

## 🏆 总结

现在的架构实现了：

1. ✅ **代码层**: 插件化，符合 OCP
2. ✅ **脚本层**: 自动化，无需手动配置
3. ✅ **环境层**: 有条件传递，互不干扰

**你只需要**:
1. `export KEY="sk-xxx"`
2. `./setup.sh`
3. `./run.sh 2 60 lightftp chatafl-opt`

其他全部自动完成！🎉

---

**文档日期**: 2026-02-04  
**版本**: ChatAFL-Opt 2.0 Plugin Architecture + Auto-Enable  
**状态**: ✅ Production Ready  
