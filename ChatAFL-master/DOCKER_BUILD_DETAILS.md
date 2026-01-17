# Docker构建实时细节说明

## 构建流程架构

### 正确的构建顺序：

```
1. 编译ChatAFL-Enhanced本地版本（使用-O3）
   └→ make -f Makefile.enhanced integrated
   └→ make clean all
   
2. 运行setup.sh复制所有fuzzers到benchmark
   └→ 复制到每个subject目录：
      - aflnet/  (从aflnet-master)
      - chatafl/ (从ChatAFL)
      - chatafl-cl1/ (从ChatAFL-CL1)
      - chatafl-cl2/ (从ChatAFL-CL2)
      - chatafl-enhanced/ (从ChatAFL-Enhanced)
   
3. Docker构建从benchmark目录执行
   └→ cd benchmark
   └→ PFBENCH=$PWD scripts/execution/profuzzbench_build_all.sh
      └→ 遍历subjects/*/*
      └→ docker build -t <target> <subject_dir>
```

## 关键理解

### 为什么之前构建失败？

**错误尝试1：**
```bash
# 从项目根目录构建，期望COPY直接找到大写目录
docker build -f benchmark/subjects/FTP/LightFTP/Dockerfile -t lightftp .
# ✗ 失败：Dockerfile期望小写目录名（chatafl, chatafl-enhanced）
```

**错误尝试2：**
```bash
# 从Dockerfile所在目录构建
cd benchmark/subjects/FTP/LightFTP
docker build -t lightftp .
# ✗ 失败：build context无法找到上层的fuzzer源码
```

**正确方式：**
```bash
# 1. 先复制fuzzers到subject目录（小写名）
cp -r ChatAFL benchmark/subjects/FTP/LightFTP/chatafl
cp -r ChatAFL-Enhanced benchmark/subjects/FTP/LightFTP/chatafl-enhanced
# ...

# 2. 从subject目录构建（fuzzer代码已在build context内）
cd benchmark/subjects/FTP/LightFTP
docker build -t lightftp .
# ✓ 成功：COPY命令能找到本地的chatafl/等目录
```

## Docker构建步骤详解（40步）

### 阶段1: 基础环境 (Steps 1-8) - ~1分钟
```dockerfile
Step 1/40 : FROM ubuntu:20.04              # 使用缓存
Step 2/40 : ENV DEBIAN_FRONTEND=...        # 使用缓存
Step 3/40 : RUN apt-get install...         # 使用缓存（~30秒）
Step 4/40 : RUN groupadd ubuntu...         # 使用缓存
Step 5/40 : RUN chmod 777 /tmp             # 使用缓存
Step 6/40 : RUN pip3 install gcovr         # 使用缓存
Step 7/40 : USER ubuntu                    # 使用缓存
Step 8/40 : WORKDIR /home/ubuntu           # 使用缓存
```

### 阶段2: AFLNet (Steps 9-11) - ~1-2分钟
```dockerfile
Step 9/40  : ARG MAKE_OPT
Step 10/40 : COPY aflnet aflnet
Step 11/40 : RUN cd aflnet && \
               make clean all $MAKE_OPT && \    # 编译aflnet（~1分钟）
               cd llvm_mode && make $MAKE_OPT   # 编译LLVM模式（~30秒）
```

### 阶段3: ChatAFL基础版 (Steps 12-14) - ~1-2分钟
```dockerfile
Step 12/40 : COPY chatafl chatafl
Step 13/40 : RUN cd chatafl && \
               make clean all $MAKE_OPT && \
               cd llvm_mode && make $MAKE_OPT
```

### 阶段4: ChatAFL-CL1 (Steps 15-17) - ~1-2分钟
```dockerfile
Step 15/40 : COPY chatafl-cl1 chatafl-cl1
Step 16/40 : RUN cd chatafl-cl1 && \
               make clean all $MAKE_OPT && \
               cd llvm_mode && make $MAKE_OPT
```

### 阶段5: ChatAFL-CL2 (Steps 18-20) - ~1-2分钟
```dockerfile
Step 18/40 : COPY chatafl-cl2 chatafl-cl2
Step 19/40 : RUN cd chatafl-cl2 && \
               make clean all $MAKE_OPT && \
               cd llvm_mode && make $MAKE_OPT
```

### 阶段6: ChatAFL-Enhanced ⭐ (Steps 21-23) - ~1-2分钟
```dockerfile
Step 21/40 : COPY chatafl-enhanced chatafl-enhanced
Step 22/40 : RUN cd chatafl-enhanced && \
               make clean all $MAKE_OPT && \       # ← 这里会使用修复后的Makefile(-O3)
               cd llvm_mode && make $MAKE_OPT
```

**关键：** 这一步编译的chatafl-enhanced使用镜像内的Makefile，必须确保复制到benchmark目录的版本已包含-O3修复！

### 阶段7: LightFTP目标程序 (Steps 24-40) - ~2-3分钟
```dockerfile
Step 24/40 : COPY Source Source
Step 25/40 : RUN cd Source/Release && make clean
Step 26/40 : WORKDIR Source/Release
...
Step 38/40 : RUN make -j$(nproc)           # 用不同fuzzer编译多个版本
Step 39/40 : RUN ... 
Step 40/40 : ENV ...
```

## 实时监控命令

### 监控构建进度：
```bash
# 终端1：启动构建
cd /path/to/ChatAFL-master
bash setup.sh   # 或手动运行构建命令

# 终端2：实时监控
watch -n 2 'docker images | head -5'                           # 查看镜像
tail -f /tmp/docker_build.log | grep "^Step"                   # 跟踪步骤
docker ps -a | grep -v CONTAINER                                # 查看容器
```

### 查看当前步骤详情：
```bash
# 显示最近10步
tail -100 /tmp/docker_build.log | grep -E "^Step|^COPY|^RUN" | tail -10

# 显示进度百分比
CURRENT=$(grep "Step [0-9]*/40" /tmp/docker_build.log | tail -1 | cut -d'/' -f1 | awk '{print $2}')
echo "Progress: $CURRENT/40 ($((CURRENT * 100 / 40))%)"

# 实时显示编译输出
tail -f /tmp/docker_build.log | grep --line-buffered -v "Using cache"
```

### 检查特定fuzzer编译：
```bash
# 查看Enhanced编译步骤
grep -A50 "COPY chatafl-enhanced" /tmp/docker_build.log | head -50

# 查看是否使用-O3
docker run --rm lightftp grep "CFLAGS" /home/ubuntu/chatafl-enhanced/Makefile

# 验证二进制时间戳
docker run --rm lightftp stat -c "%y %s" /home/ubuntu/chatafl-enhanced/afl-fuzz
```

## 构建时间估算

| 阶段 | 步骤 | 耗时 | 说明 |
|------|------|------|------|
| 基础环境 | 1-8 | ~1分钟 | 全部使用缓存 |
| AFLNet | 9-11 | ~1-2分钟 | 编译+LLVM |
| ChatAFL | 12-14 | ~1-2分钟 | 编译+LLVM |
| ChatAFL-CL1 | 15-17 | ~1-2分钟 | 编译+LLVM |
| ChatAFL-CL2 | 18-20 | ~1-2分钟 | 编译+LLVM |
| **ChatAFL-Enhanced** | 21-23 | ~1-2分钟 | **编译+LLVM** |
| LightFTP | 24-40 | ~2-3分钟 | 多fuzzer版本 |
| **总计** | **40步** | **8-12分钟** | 使用-j4并行编译 |

## 常见构建输出

### 成功的Enhanced编译输出：
```
Step 22/40 : RUN cd chatafl-enhanced && make clean all $MAKE_OPT && cd llvm_mode && make $MAKE_OPT
 ---> Running in abc123def456
[*] Checking for the ability to compile x86 code...
[+] All right, the instrumentation seems to be working!
cc -O3 -funroll-loops -Wall ...    ← 确认使用-O3
...
[+] All done! Be sure to review README
 ---> 17eb7d612b17
Step 23/40 : ...
```

### 检查编译优化级别：
```bash
# 在构建日志中查找
grep "^cc -O" /tmp/docker_build.log | head -5
# 应该看到: cc -O3 -funroll-loops ...

# 不应该看到: cc -O2 ...
```

## 调试技巧

### 如果构建卡住：
```bash
# 检查Docker进程
docker ps -a | grep lightftp

# 检查构建进程
ps aux | grep "docker build"

# 杀死卡死的构建
docker ps -a | grep lightftp | awk '{print $1}' | xargs docker rm -f
```

### 如果构建失败：
```bash
# 查看完整错误
cat /tmp/docker_build.log | grep -A10 "ERROR"

# 检查最后一步
tail -50 /tmp/docker_build.log

# 重新从失败步骤构建（手动）
docker run -it lightftp:old /bin/bash
# 手动执行失败的命令
```

### 验证最终镜像：
```bash
# 检查镜像大小和时间
docker images lightftp

# 运行容器查看
docker run --rm lightftp ls -lh /home/ubuntu/chatafl-enhanced/afl-fuzz

# 检查Makefile内容
docker run --rm lightftp cat /home/ubuntu/chatafl-enhanced/Makefile | grep CFLAGS

# 验证二进制是今天编译
docker run --rm lightftp stat -c "%y" /home/ubuntu/chatafl-enhanced/afl-fuzz | grep "2026-01-18"
```

## 性能验证

构建完成后立即验证性能：

```bash
# 快速2分钟测试
./verify_fix.sh

# 预期结果（修复后）：
# ChatAFL:  ~27 paths
# Enhanced: ~26-28 paths (95-105%)
# 性能差距应在±5%内
```

---

**关键要点：**
1. 必须先运行setup.sh复制fuzzers到benchmark目录
2. Docker build从subject目录执行，不是从项目根目录
3. 复制到benchmark的Enhanced版本必须已经修复为-O3
4. 构建时间8-12分钟，Enhanced编译在Steps 21-23
5. 监控日志确认看到`cc -O3 -funroll-loops`而不是`-O2`
