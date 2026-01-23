# setup.sh 脚本与 ChatAFL-Enhanced

## 问题

**Q: 执行 setup.sh 脚本会编译 ChatAFL-Enhanced 吗？**

**A: 会！现在已经支持。**

## 修改说明

### 修改前

原始的 `setup.sh` **不会**处理 ChatAFL-Enhanced：

```bash
# 只处理这三个版本
for x in ChatAFL ChatAFL-CL1 ChatAFL-CL2;
do
  sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$KEY\"/" $x/chat-llm.h
done

# 只复制这三个版本到 benchmark 目录
for subject in ./benchmark/subjects/*/*; do
  cp -r ChatAFL $subject/chatafl
  cp -r ChatAFL-CL1 $subject/chatafl-cl1
  cp -r ChatAFL-CL2 $subject/chatafl-cl2
done
```

### 修改后

现在 `setup.sh` **已支持** ChatAFL-Enhanced：

```bash
# 处理四个版本（包括 ChatAFL-Enhanced）
for x in ChatAFL ChatAFL-CL1 ChatAFL-CL2 ChatAFL-Enhanced;
do
  sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$KEY\"/" $x/chat-llm.h
done

# 复制四个版本到 benchmark 目录
for subject in ./benchmark/subjects/*/*; do
  cp -r ChatAFL $subject/chatafl
  cp -r ChatAFL-CL1 $subject/chatafl-cl1
  cp -r ChatAFL-CL2 $subject/chatafl-cl2
  cp -r ChatAFL-Enhanced $subject/chatafl-enhanced
done
```

## setup.sh 的作用

`setup.sh` 脚本执行以下操作：

1. **更新 OpenAI API 密钥**
   - 在所有 ChatAFL 版本的 `chat-llm.h` 中设置 API 密钥
   - 现在包括：ChatAFL, ChatAFL-CL1, ChatAFL-CL2, **ChatAFL-Enhanced**

2. **复制源代码到 benchmark 目录**
   - 将各个版本复制到每个测试目标的目录中
   - Docker 构建时会使用这些复制的代码

3. **触发 Docker 镜像构建**（如果脚本完整的话）
   - 注：当前脚本似乎未完成，只有 `cd $PFBENCH`

## ChatAFL-Enhanced 的编译时机

### 方式 1: 通过 setup.sh（推荐）

```bash
# 设置 API 密钥并运行 setup.sh
export KEY="your-openai-api-key"
./setup.sh
```

**效果**：
- ✅ 更新所有版本的 API 密钥（包括 ChatAFL-Enhanced）
- ✅ 复制 ChatAFL-Enhanced 到所有 benchmark 目录
- ✅ Dockerfile 构建时会编译 ChatAFL-Enhanced

**编译发生在**：Docker 镜像构建时

**Dockerfile 中的编译命令**：
```dockerfile
COPY --chown=ubuntu:ubuntu chatafl-enhanced chatafl-enhanced
RUN cd chatafl-enhanced && \
    make clean all CHATAFL_ENHANCED=1 $MAKE_OPT && \
    cd llvm_mode && make $MAKE_OPT
```

### 方式 2: 直接手动编译

```bash
# 不通过 setup.sh，直接编译
cd ChatAFL-Enhanced
make clean all CHATAFL_ENHANCED=1
```

**效果**：
- ✅ 直接在 ChatAFL-Enhanced 目录中编译
- ✅ 可以立即使用 `./afl-fuzz`
- ❌ 不会复制到 benchmark 目录
- ❌ Docker 镜像不会包含最新代码

## 编译选项

### 基础模式（兼容 ChatAFL）

```bash
cd ChatAFL-Enhanced
make clean all  # 不设置 CHATAFL_ENHANCED
```

- 不包含增强模块
- 与 ChatAFL 行为完全相同

### 增强模式（完整功能）

```bash
cd ChatAFL-Enhanced
make clean all CHATAFL_ENHANCED=1
```

- 包含所有增强模块
- 启用验证器、CEGAR、状态调度器等

## 完整工作流

### 推荐流程

```bash
# 1. 设置 API 密钥
export KEY="sk-your-openai-api-key"

# 2. 运行 setup.sh（会更新密钥并复制代码）
./setup.sh

# 3. 构建 Docker 镜像（会自动编译 ChatAFL-Enhanced）
cd benchmark
./scripts/execution/profuzzbench_build_all.sh

# 4. 运行测试
cd ..
./run.sh 5 10 kamailio chatafl-enhanced
```

### 快速测试流程（不使用 Docker）

```bash
# 1. 直接编译
cd ChatAFL-Enhanced
make clean all CHATAFL_ENHANCED=1

# 2. 直接运行
./afl-fuzz -i in -o out -P SIP -- target_binary
```

## 条件编译说明

### 是否需要添加条件？

**答：不需要额外添加条件**

原因：
1. **Dockerfile 已有条件**
   ```dockerfile
   RUN cd chatafl-enhanced && \
       make clean all CHATAFL_ENHANCED=1 $MAKE_OPT
   ```
   - `CHATAFL_ENHANCED=1` 标志已经是条件
   - 启用增强功能

2. **Makefile 内部有条件**
   ```makefile
   ifdef CHATAFL_ENHANCED
     ENHANCED_OBJS = verifier.o cegar-refinement.o ...
   else
     ENHANCED_OBJS =
   endif
   ```
   - 根据标志决定是否编译增强模块

3. **setup.sh 无需条件**
   - 只是复制代码，不执行编译
   - 编译由 Docker 或手动执行

### 如果想要可选的 ChatAFL-Enhanced 支持

如果希望 setup.sh 可以选择性地包含/排除 ChatAFL-Enhanced，可以这样修改：

```bash
#!/bin/bash

# 默认不包含 ChatAFL-Enhanced，除非设置环境变量
INCLUDE_ENHANCED="${INCLUDE_ENHANCED:-0}"

if [ -z $KEY ]; then
    echo "NO OPENAI API KEY PROVIDED! Please set the KEY environment variable"
    exit 0
fi

# 确定要处理的版本
if [ "$INCLUDE_ENHANCED" = "1" ]; then
    VERSIONS="ChatAFL ChatAFL-CL1 ChatAFL-CL2 ChatAFL-Enhanced"
    echo "✓ 包含 ChatAFL-Enhanced"
else
    VERSIONS="ChatAFL ChatAFL-CL1 ChatAFL-CL2"
    echo "✗ 不包含 ChatAFL-Enhanced (设置 INCLUDE_ENHANCED=1 以启用)"
fi

# Update the openAI key
for x in $VERSIONS;
do
  sed -i "s/#define OPENAI_TOKEN \".*\"/#define OPENAI_TOKEN \"$KEY\"/" $x/chat-llm.h
done

# Copy the different versions of ChatAFL to the benchmark directories
for subject in ./benchmark/subjects/*/*; do
  # ... 复制逻辑 ...
  
  if [ "$INCLUDE_ENHANCED" = "1" ]; then
    rm -r $subject/chatafl-enhanced 2>&1 >/dev/null
    cp -r ChatAFL-Enhanced $subject/chatafl-enhanced
  fi
done
```

**使用方式**：
```bash
# 不包含 ChatAFL-Enhanced（默认）
./setup.sh

# 包含 ChatAFL-Enhanced
INCLUDE_ENHANCED=1 ./setup.sh
```

## 当前实现

**当前 setup.sh 的实现**：**始终包含** ChatAFL-Enhanced

这符合"对扩展开放"的原则：
- ✅ 默认支持所有版本
- ✅ 用户可以选择性地使用 `chatafl-enhanced`
- ✅ 不影响现有版本的使用

## 总结

| 问题 | 答案 |
|------|------|
| setup.sh 会编译 ChatAFL-Enhanced 吗？ | 会，通过 Docker 构建 |
| 需要添加条件吗？ | 不需要，已有条件编译机制 |
| 直接运行 setup.sh 后能用吗？ | 需要先构建 Docker 镜像 |
| 可以手动编译吗？ | 可以，`make CHATAFL_ENHANCED=1` |
| 增强功能默认启用吗？ | 在 Docker 中启用，手动编译需指定 |

## 相关文档

- [ChatAFL-Enhanced/README-ENHANCED.md](ChatAFL-Enhanced/README-ENHANCED.md) - 详细使用文档
- [QUICKSTART-ENHANCED.md](QUICKSTART-ENHANCED.md) - 快速开始
- [CHATAFL_ENHANCED_ADAPTATION_REPORT.md](CHATAFL_ENHANCED_ADAPTATION_REPORT.md) - 适配报告
