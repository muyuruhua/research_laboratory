# ChatAFL-Enhanced 开发模式快速指南

## 🚀 快速开始（开发模式）

### 方法一：Volume 挂载模式（推荐 ⭐）

**优点**: 修改代码立即同步，无需复制文件，编译速度快（~10秒）

#### 1. 启动开发容器（首次）
```bash
./dev-sync.sh start
```
这将：
- 创建一个长期运行的容器 `chatafl-enhanced-dev`
- 将当前目录挂载到容器的 `/opt/aflnet`
- 宿主机修改的代码**立即**反映到容器中

#### 2. 修改代码后重新编译
```bash
# 在宿主机修改 afl-fuzz.c、chat-llm.c 等文件后
./dev-sync.sh sync
```
编译完成后，容器内的 `afl-fuzz` 会更新。

#### 3. 快速重编译（无清理）
```bash
# 适合小改动，跳过 make clean
./dev-sync.sh rebuild
```

#### 4. 进入容器调试
```bash
./dev-sync.sh shell
# 现在你在容器内，可以直接运行
./afl-fuzz -h
./aflnet-replay ...
```

#### 5. 自动监控模式（高级）
```bash
# 安装依赖（仅首次）
sudo apt-get install inotify-tools

# 启动文件监控（保存 .c/.h 文件时自动编译）
WATCH_MODE=1 ./dev-sync.sh watch
```

#### 6. 停止容器（保留数据）
```bash
./dev-sync.sh stop
# 下次运行 ./dev-sync.sh start 会恢复
```

---

### 方法二：手动 docker cp（适合临时测试）

#### 1. 查找运行中的容器
```bash
docker ps
# 找到容器名，例如 aflnet-http-1
```

#### 2. 复制修改的文件到容器
```bash
# 复制单个文件
docker cp afl-fuzz.c aflnet-http-1:/opt/aflnet/

# 复制整个目录
docker cp ./ aflnet-http-1:/opt/aflnet/
```

#### 3. 进入容器重新编译
```bash
docker exec -it aflnet-http-1 bash
cd /opt/aflnet
make clean && make -j$(nproc)
exit
```

---

### 方法三：修改 Dockerfile（适合发布版本）

在 `Dockerfile` 中添加挂载点：

```dockerfile
# 在 Dockerfile 末尾添加
VOLUME ["/opt/aflnet"]
```

然后构建并运行：
```bash
docker build -t chatafl-enhanced:dev .
docker run -it --rm \
    -v $(pwd):/opt/aflnet \
    chatafl-enhanced:dev \
    bash
```

---

## 📊 对比表格

| 方法 | 同步速度 | 编译速度 | 适用场景 | 复杂度 |
|------|---------|---------|---------|--------|
| **dev-sync.sh** | 即时 | ~10秒 | 频繁开发 | 低 ⭐ |
| docker cp | 手动 | ~15秒 | 临时测试 | 中 |
| 重建镜像 | 慢（5-10分钟） | 完整编译 | 发布版本 | 高 |
| 自动监控 | 自动 | ~10秒 | 持续开发 | 中 |

---

## 🔧 常见问题

### Q1: 容器内修改的文件会保留吗？
**A**: 使用 Volume 挂载时，容器和宿主机共享同一份文件，修改会双向同步。

### Q2: 如何验证代码是否已同步？
```bash
./dev-sync.sh shell
# 在容器内
cat afl-fuzz.c | head -20  # 检查文件内容
./afl-fuzz -h              # 测试二进制
```

### Q3: 如何同时运行多个开发容器？
```bash
CONTAINER_NAME=chatafl-dev-1 ./dev-sync.sh start
CONTAINER_NAME=chatafl-dev-2 ./dev-sync.sh start
```

### Q4: 编译失败怎么办？
```bash
# 查看完整编译日志
./dev-sync.sh shell
make clean && make 2>&1 | tee compile.log
```

### Q5: 如何重置到干净状态？
```bash
# 停止并删除容器
docker stop chatafl-enhanced-dev
docker rm chatafl-enhanced-dev

# 清理宿主机编译产物
make clean

# 重新开始
./dev-sync.sh start
```

---

## 🎯 推荐工作流程

### 日常开发循环：
```bash
# 1. 启动容器（每天首次）
./dev-sync.sh start

# 2. 修改代码（在 VS Code / Vim 中编辑）
vim afl-fuzz.c

# 3. 重新编译
./dev-sync.sh sync

# 4. 测试（在容器内或宿主机运行）
./dev-sync.sh shell
./afl-fuzz -i testcases/ftp -o output -N tcp://127.0.0.1/21 ./lightftp

# 5. 调试（如有问题）
gdb ./afl-fuzz
```

### 提交前完整验证：
```bash
# 完整重新编译
./dev-sync.sh sync

# 检查符号表
./dev-sync.sh shell
nm afl-fuzz | grep -E "(llm_cost|plateau|cegar)"

# 运行集成测试
./run_comparison.sh 1 1 HTTP chatafl_enhanced
```

---

## 🚨 注意事项

1. **首次使用**：确保已运行过 `make` 构建基础镜像
2. **权限问题**：容器内文件所有者可能是 root，需要在宿主机修改
3. **缓存问题**：如果看到旧版本，运行 `docker exec chatafl-enhanced-dev make clean`
4. **网络配置**：如需访问宿主机服务，使用 `--network host`

---

## 💡 高级技巧

### 调试时挂载 GDB
```bash
docker run -it --rm \
    --cap-add=SYS_PTRACE \
    --security-opt seccomp=unconfined \
    -v $(pwd):/opt/aflnet \
    chatafl-enhanced:dev \
    gdb ./afl-fuzz
```

### 多阶段构建优化
将编译依赖和运行时分离：
```dockerfile
# Stage 1: 构建
FROM ubuntu:18.04 AS builder
COPY . /opt/aflnet
RUN make

# Stage 2: 运行时
FROM ubuntu:18.04
COPY --from=builder /opt/aflnet/afl-fuzz /usr/local/bin/
```

### 使用 docker-compose 管理
```yaml
version: '3'
services:
  aflnet-dev:
    image: chatafl-enhanced:dev
    volumes:
      - .:/opt/aflnet
    working_dir: /opt/aflnet
    command: tail -f /dev/null
```

---

**总结**：优先使用 `./dev-sync.sh start` + `./dev-sync.sh sync` 的工作流程，可以获得接近原生开发的体验，编译速度提升 90%。
