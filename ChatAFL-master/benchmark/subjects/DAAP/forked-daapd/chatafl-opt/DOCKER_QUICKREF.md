# ChatAFL-Opt Docker 快速参考

## 一键运行

```bash
# 最快启动方式
./docker-run.sh interactive
```

## 常用命令

### 构建与运行
```bash
# 构建镜像
docker build -t chatafl-opt .

# 交互式运行
docker run -it --rm -e KEY="sk-xxx" -v $(pwd)/in:/opt/in -v $(pwd)/out:/opt/out chatafl-opt

# 后台运行
docker run -d --name fuzzer -e KEY="sk-xxx" -v $(pwd)/in:/opt/in -v $(pwd)/out:/opt/out chatafl-opt ./afl-fuzz -i /opt/in -o /opt/out -N tcp://target:21 -P FTP -- /bin/true
```

### Docker Compose
```bash
# 启动所有服务
docker-compose up -d

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

### 监控与调试
```bash
# 查看容器状态
docker ps
docker stats fuzzer

# 查看日志
docker logs -f fuzzer

# 进入容器
docker exec -it fuzzer bash

# 查看结果
docker exec fuzzer cat /opt/out/statistics.txt
docker exec fuzzer cat /opt/out/hypotheses.json
```

### 结果导出
```bash
# 复制文件
docker cp fuzzer:/opt/out/hypotheses.json ./

# 生成状态树图
docker exec fuzzer dot -Tpng /opt/out/state_tree.dot -o /opt/out/tree.png
docker cp fuzzer:/opt/out/tree.png ./
```

### 清理
```bash
# 停止并删除容器
docker stop fuzzer && docker rm fuzzer

# 使用 Compose 清理
docker-compose down -v

# 清理所有未使用资源
docker system prune -a
```

## 环境变量

| 变量 | 说明 | 示例 |
|------|------|------|
| `KEY` | OpenAI API Key | `sk-xxxxx` |
| `AFL_SKIP_CPUFREQ` | 跳过 CPU 频率检查 | `1` |
| `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES` | 忽略崩溃缺失警告 | `1` |

## 目录映射

| 主机目录 | 容器目录 | 用途 |
|----------|----------|------|
| `./seeds` | `/opt/in` | 输入种子文件 |
| `./results` | `/opt/out` | 测试结果输出 |
| `./targets` | `/opt/targets` | 目标程序 |

## 完整示例

### LightFTP 测试
```bash
# 1. 准备种子
mkdir -p seeds
echo -e "USER anonymous\r\nPASS test\r\n" > seeds/login.txt

# 2. 启动目标服务
docker run -d --name lightftp --network host target-image

# 3. 运行模糊测试
export OPENAI_API_KEY="sk-xxxxx"
./docker-run.sh daemon FTP tcp://127.0.0.1/21

# 4. 查看结果
./docker-run.sh results

# 5. 清理
./docker-run.sh cleanup
```

## 故障排查

### 问题：容器无法启动
```bash
docker logs fuzzer
docker inspect fuzzer
```

### 问题：无法连接目标
```bash
docker exec fuzzer ping target
docker exec fuzzer netstat -tuln
```

### 问题：API Key 无效
```bash
docker exec fuzzer env | grep KEY
docker exec -it fuzzer bash -c 'export KEY="new-key" && ./afl-fuzz ...'
```

### 问题：磁盘空间不足
```bash
docker system df
docker system prune -a
find results -type f -size +100M -delete
```

## 性能优化

### 限制资源
```bash
docker run --cpus="2.0" --memory="4g" chatafl-opt
```

### 使用 tmpfs
```bash
docker run --tmpfs /tmp:rw,size=2g chatafl-opt
```

### 并行测试
```bash
# 主节点
docker run -d --name fuzzer-master -v shared:/opt/out chatafl-opt \
  ./afl-fuzz -i /opt/in -o /opt/out -M fuzzer01 -N tcp://target:21 -P FTP -- /bin/true

# 从节点
docker run -d --name fuzzer-slave1 -v shared:/opt/out chatafl-opt \
  ./afl-fuzz -i /opt/in -o /opt/out -S fuzzer02 -N tcp://target:21 -P FTP -- /bin/true
```

## 更多信息

- 完整指南: [DOCKER_GUIDE.md](DOCKER_GUIDE.md)
- 系统架构: [README_CHATAFL_OPT.md](README_CHATAFL_OPT.md)
- 示例脚本: `example-lightftp.sh`
