# ChatAFL-Opt 容器化模糊测试指南

本指南详细介绍如何使用 Docker 容器进行 ChatAFL-Opt 模糊测试，确保测试环境的隔离性、可移植性和可复现性。

---

## 目录
1. [快速开始](#快速开始)
2. [Dockerfile 详解](#dockerfile-详解)
3. [构建镜像](#构建镜像)
4. [运行容器](#运行容器)
5. [实战示例：测试 LightFTP](#实战示例测试-lightftp)
6. [高级用法](#高级用法)
7. [监控与调试](#监控与调试)
8. [最佳实践](#最佳实践)
9. [故障排查](#故障排查)

---

## 快速开始

### 前置要求
- 已安装 Docker (版本 >= 20.10)
- 至少 4GB 可用内存
- 有效的 OpenAI API Key

### 三步快速启动
```bash
# 1. 构建镜像
cd ChatAFL-Opt
docker build -t chatafl-opt:latest .

# 2. 启动容器
docker run -it --rm \
  -e KEY="your-openai-api-key" \
  -v $(pwd)/in:/opt/in \
  -v $(pwd)/out:/opt/out \
  chatafl-opt:latest

# 3. 运行模糊测试（容器内）
./afl-fuzz -i /opt/in -o /opt/out -N tcp://127.0.0.1/21 -P FTP -- /path/to/target
```

---

## Dockerfile 详解

### 当前 Dockerfile 结构
```dockerfile
FROM ubuntu:18.04

# 安装系统依赖
RUN apt-get -y update && \
    apt-get -y install sudo apt-utils build-essential \
    openssl clang \
    libcurl-openssl1.0-dev libjson-c-dev libpcre2-dev \
    graphviz-dev git libcap-dev libcurl3

# 复制并编译 ChatAFL-Opt
COPY . /opt/aflnet
WORKDIR /opt/aflnet
RUN make clean all && cd llvm_mode && make

# 设置环境变量
ENV AFLNET="/opt/aflnet"
ENV PATH="${PATH}:${AFLNET}"
ENV AFL_PATH="${AFLNET}"
ENV AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    AFL_SKIP_CPUFREQ=1
```

### 关键依赖说明
| 依赖 | 用途 |
|------|------|
| `libjson-c-dev` | 解析 LLM 返回的 JSON 假设 |
| `libpcre2-dev` | 正则表达式验证（可解析性检查） |
| `libcurl-openssl1.0-dev` | 调用 OpenAI API |
| `graphviz-dev` | 生成状态转移树可视化 |
| `clang` | LLVM 模式编译目标程序 |

---

## 构建镜像

### 基础构建
```bash
cd /path/to/ChatAFL-Opt
docker build -t chatafl-opt:latest .
```

### 自定义构建参数
```bash
# 指定基础镜像版本
docker build --build-arg BASE_IMAGE=ubuntu:20.04 -t chatafl-opt:ubuntu20 .

# 使用缓存加速构建
docker build --cache-from chatafl-opt:latest -t chatafl-opt:v2 .

# 多阶段构建（优化镜像大小）
docker build -f Dockerfile.optimized -t chatafl-opt:slim .
```

### 验证镜像
```bash
# 查看镜像信息
docker images | grep chatafl-opt

# 测试镜像是否可用
docker run --rm chatafl-opt:latest ./afl-fuzz -h
```

---

## 运行容器

### 基本运行模式

#### 1. 交互式模式（推荐用于开发调试）
```bash
docker run -it --rm \
  --name chatafl-fuzzing \
  -e KEY="sk-xxxxx" \
  -v $(pwd)/seeds:/opt/in \
  -v $(pwd)/results:/opt/out \
  chatafl-opt:latest \
  bash
```

#### 2. 后台运行模式（推荐用于长时间测试）
```bash
docker run -d \
  --name chatafl-fuzzing \
  -e KEY="sk-xxxxx" \
  -v $(pwd)/seeds:/opt/in \
  -v $(pwd)/results:/opt/out \
  chatafl-opt:latest \
  ./afl-fuzz -i /opt/in -o /opt/out -N tcp://127.0.0.1/21 -P FTP -- /target
```

#### 3. 一次性运行模式（测试完自动销毁）
```bash
docker run --rm \
  -e KEY="sk-xxxxx" \
  -v $(pwd)/seeds:/opt/in \
  -v $(pwd)/results:/opt/out \
  chatafl-opt:latest \
  timeout 3600 ./afl-fuzz -i /opt/in -o /opt/out -N tcp://127.0.0.1/21 -P FTP -- /target
```

### 参数说明
| 参数 | 说明 |
|------|------|
| `-it` | 交互式终端 |
| `--rm` | 容器退出后自动删除 |
| `-d` | 后台运行 |
| `-e KEY="xxx"` | 设置 OpenAI API Key |
| `-v host:container` | 挂载目录 |
| `--name` | 指定容器名称 |
| `--cpus` | 限制 CPU 使用（如 `--cpus="2.0"`） |
| `--memory` | 限制内存使用（如 `--memory="4g"`） |

---

## 实战示例：测试 LightFTP

### 完整工作流程

#### Step 1: 准备种子文件
```bash
mkdir -p seeds
echo -e "USER anonymous\r\nPASS test@example.com\r\n" > seeds/ftp_login.txt
echo -e "USER admin\r\nPASS 12345\r\nLIST\r\n" > seeds/ftp_list.txt
```

#### Step 2: 构建目标程序
```bash
# 使用容器内的 afl-clang-fast 编译
docker run -it --rm \
  -v $(pwd)/LightFTP:/src \
  chatafl-opt:latest \
  bash -c "cd /src && CC=afl-clang-fast make"
```

#### Step 3: 启动 LightFTP 服务（在容器内）
```bash
docker run -d \
  --name lightftp-server \
  --network host \
  -v $(pwd)/LightFTP:/app \
  chatafl-opt:latest \
  /app/fftp /app/ftpconfig.txt 21
```

#### Step 4: 运行 ChatAFL-Opt 模糊测试
```bash
docker run -it --rm \
  --name chatafl-fuzzer \
  --network host \
  -e KEY="sk-xxxxx" \
  -v $(pwd)/seeds:/opt/in \
  -v $(pwd)/results:/opt/out \
  chatafl-opt:latest \
  ./afl-fuzz \
    -i /opt/in \
    -o /opt/out \
    -N tcp://127.0.0.1/21 \
    -P FTP \
    -t 5000 \
    -m none \
    -- /app/fftp /app/ftpconfig.txt 2121
```

#### Step 5: 实时监控
```bash
# 查看容器日志
docker logs -f chatafl-fuzzer

# 查看状态树
docker exec chatafl-fuzzer cat /opt/out/hypotheses.json

# 生成可视化图
docker exec chatafl-fuzzer dot -Tpng /opt/out/state_tree.dot -o /opt/out/tree.png
```

---

## 高级用法

### 1. Docker Compose 编排

创建 `docker-compose.yml`:
```yaml
version: '3.8'

services:
  # LightFTP 目标服务
  lightftp:
    image: chatafl-opt:latest
    container_name: lightftp-target
    command: /app/fftp /app/ftpconfig.txt 21
    volumes:
      - ./LightFTP:/app
    networks:
      - fuzzing-net
    ports:
      - "21:21"

  # ChatAFL-Opt 模糊测试器
  fuzzer:
    image: chatafl-opt:latest
    container_name: chatafl-fuzzer
    depends_on:
      - lightftp
    environment:
      - KEY=${OPENAI_API_KEY}
    volumes:
      - ./seeds:/opt/in
      - ./results:/opt/out
    networks:
      - fuzzing-net
    command: >
      ./afl-fuzz
      -i /opt/in
      -o /opt/out
      -N tcp://lightftp:21
      -P FTP
      -- /bin/true

networks:
  fuzzing-net:
    driver: bridge
```

运行：
```bash
export OPENAI_API_KEY="sk-xxxxx"
docker-compose up -d
docker-compose logs -f fuzzer
```

### 2. 多实例并行模糊测试
```bash
# 主节点
docker run -d --name fuzzer-master \
  -e KEY="sk-xxxxx" \
  -v $(pwd)/shared:/opt/shared \
  chatafl-opt:latest \
  ./afl-fuzz -i /opt/in -o /opt/shared -M fuzzer01 -N tcp://target:21 -P FTP -- /target

# 从节点 1
docker run -d --name fuzzer-slave1 \
  -v $(pwd)/shared:/opt/shared \
  chatafl-opt:latest \
  ./afl-fuzz -i /opt/in -o /opt/shared -S fuzzer02 -N tcp://target:21 -P FTP -- /target

# 从节点 2
docker run -d --name fuzzer-slave2 \
  -v $(pwd)/shared:/opt/shared \
  chatafl-opt:latest \
  ./afl-fuzz -i /opt/in -o /opt/shared -S fuzzer03 -N tcp://target:21 -P FTP -- /target
```

### 3. 使用网络命名空间隔离
```bash
# 创建自定义网络
docker network create --subnet=172.18.0.0/16 fuzzing-net

# 在隔离网络中运行
docker run -d \
  --network fuzzing-net \
  --ip 172.18.0.10 \
  --name target \
  target-image

docker run -it \
  --network fuzzing-net \
  --ip 172.18.0.20 \
  -e KEY="sk-xxxxx" \
  chatafl-opt:latest \
  ./afl-fuzz -i /opt/in -o /opt/out -N tcp://172.18.0.10/21 -P FTP -- /bin/true
```

---

## 监控与调试

### 实时监控容器状态
```bash
# CPU、内存使用情况
docker stats chatafl-fuzzer

# 进入运行中的容器
docker exec -it chatafl-fuzzer bash

# 查看实时日志
docker logs -f --tail 100 chatafl-fuzzer
```

### 导出测试结果
```bash
# 复制文件到本地
docker cp chatafl-fuzzer:/opt/out/hypotheses.json ./results/

# 打包整个输出目录
docker exec chatafl-fuzzer tar czf /tmp/results.tar.gz /opt/out
docker cp chatafl-fuzzer:/tmp/results.tar.gz ./
```

### 调试技巧
```bash
# 在容器内运行 GDB
docker run -it --cap-add=SYS_PTRACE \
  chatafl-opt:latest \
  gdb --args ./afl-fuzz -i /opt/in -o /opt/out -N tcp://127.0.0.1/21 -P FTP -- /target

# 查看系统调用
docker run -it --cap-add=SYS_PTRACE \
  chatafl-opt:latest \
  strace -f ./afl-fuzz -i /opt/in -o /opt/out -N tcp://127.0.0.1/21 -P FTP -- /target
```

---

## 最佳实践

### 1. 资源限制
```bash
# 限制 CPU 和内存，防止资源耗尽
docker run -d \
  --cpus="2.0" \
  --memory="4g" \
  --memory-swap="4g" \
  --pids-limit 200 \
  chatafl-opt:latest \
  ./afl-fuzz -i /opt/in -o /opt/out -N tcp://target:21 -P FTP -- /target
```

### 2. 数据持久化
```bash
# 使用命名卷（推荐）
docker volume create fuzzing-results
docker run -d \
  -v fuzzing-results:/opt/out \
  chatafl-opt:latest \
  ./afl-fuzz -i /opt/in -o /opt/out -N tcp://target:21 -P FTP -- /target
```

### 3. 日志管理
```bash
# 限制日志大小
docker run -d \
  --log-driver json-file \
  --log-opt max-size=10m \
  --log-opt max-file=3 \
  chatafl-opt:latest \
  ./afl-fuzz -i /opt/in -o /opt/out -N tcp://target:21 -P FTP -- /target
```

### 4. 自动重启
```bash
# 容器退出后自动重启
docker run -d \
  --restart unless-stopped \
  chatafl-opt:latest \
  ./afl-fuzz -i /opt/in -o /opt/out -N tcp://target:21 -P FTP -- /target
```

### 5. 安全隔离
```bash
# 以非 root 用户运行
docker run -d \
  --user 1000:1000 \
  --read-only \
  --tmpfs /tmp \
  chatafl-opt:latest \
  ./afl-fuzz -i /opt/in -o /opt/out -N tcp://target:21 -P FTP -- /target
```

---

## 故障排查

### 常见问题与解决方案

#### 1. 容器无法启动
```bash
# 检查镜像是否存在
docker images | grep chatafl-opt

# 查看容器日志
docker logs chatafl-fuzzer

# 检查端口占用
netstat -tuln | grep 21
```

#### 2. 无法连接到目标服务
```bash
# 检查网络连通性
docker exec chatafl-fuzzer ping target-container

# 检查端口映射
docker port chatafl-fuzzer

# 使用 host 网络模式
docker run --network host chatafl-opt:latest
```

#### 3. API Key 无效
```bash
# 验证环境变量
docker exec chatafl-fuzzer env | grep KEY

# 重新设置
docker exec -it chatafl-fuzzer bash -c 'export KEY="new-key" && ./afl-fuzz ...'
```

#### 4. 磁盘空间不足
```bash
# 清理未使用的镜像
docker system prune -a

# 查看磁盘使用
docker system df

# 限制输出大小（在容器内）
find /opt/out -type f -size +100M -delete
```

#### 5. 性能问题
```bash
# 禁用 CPU 频率检查（已在 Dockerfile 中设置）
export AFL_SKIP_CPUFREQ=1

# 增加共享内存
docker run --shm-size=2g chatafl-opt:latest

# 使用更高效的存储驱动
docker run --storage-opt size=50G chatafl-opt:latest
```

---

## 与 ChatAFL-Opt 特性集成

### 1. 查看 LLM 生成的假设
```bash
docker exec chatafl-fuzzer cat /opt/out/hypotheses.json | jq '.hypotheses[] | {message_type, revision}'
```

### 2. 可视化状态转移树
```bash
docker exec chatafl-fuzzer dot -Tsvg /opt/out/state_tree.dot > state_tree.svg
open state_tree.svg
```

### 3. 查看 CEGAR 精化记录
```bash
docker exec chatafl-fuzzer cat /opt/out/statistics.txt
```

### 4. 验证数据流连通性
```bash
docker exec chatafl-fuzzer ./verify_completion.sh
```

---

## 性能优化建议

### 1. 使用 tmpfs 加速 I/O
```bash
docker run -d \
  --tmpfs /tmp:rw,noexec,nosuid,size=2g \
  chatafl-opt:latest
```

### 2. 使用专用网络驱动
```bash
docker network create --driver macvlan \
  --subnet=192.168.1.0/24 \
  --gateway=192.168.1.1 \
  fuzzing-macvlan
```

### 3. 预热缓存
```bash
# 提前生成初始假设
docker exec chatafl-fuzzer ./afl-fuzz -i /opt/in -o /opt/out -N tcp://target:21 -P FTP -G -- /bin/true
```

---

## 总结

通过 Docker 容器化，ChatAFL-Opt 模糊测试获得以下优势：

✅ **隔离性**: 测试环境与主机隔离，避免相互干扰  
✅ **可移植性**: 一次构建，到处运行  
✅ **可复现性**: 确保测试环境一致  
✅ **易管理**: 通过 Docker Compose 编排复杂场景  
✅ **易扩展**: 快速启动多个并行实例  

**快速命令参考**:
```bash
# 构建
docker build -t chatafl-opt .

# 运行
docker run -it --rm -e KEY="xxx" -v $(pwd)/in:/opt/in -v $(pwd)/out:/opt/out chatafl-opt

# 监控
docker stats chatafl-fuzzer

# 清理
docker stop chatafl-fuzzer && docker rm chatafl-fuzzer
```

更多问题请参考 [README_CHATAFL_OPT.md](README_CHATAFL_OPT.md)。
