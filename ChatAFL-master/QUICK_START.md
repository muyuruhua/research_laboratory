# 快速测试使用指南

## 当前场景：修复崩溃后快速验证

你当前已经修改了 `ChatAFL-Opt/grammar-hypothesis.c`，需要快速验证修复是否有效。

---

## 方案 A：重新构建镜像 + 测试（完整验证）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master

# 设置API Key
export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"

# 一键构建+测试（推荐）
./rebuild_and_test.sh lightftp chatafl-opt 5

# 或者分步执行：
# 1. 构建镜像
cd benchmark/subjects/FTP/LightFTP
sudo docker build --no-cache -t lightftp .

# 2. 测试
cd ../../../../
./quick_test.sh lightftp chatafl-opt 5
```

**优点**：完整验证，确保镜像内代码是最新的
**缺点**：需要30分钟构建时间

---

## 方案 B：Volume挂载开发模式（无需重新构建）⭐ 推荐

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master

# 设置API Key
export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"

# 方式1: 使用quick_test.sh（自动挂载本地代码）
./quick_test.sh lightftp chatafl-opt 5

# 方式2: 手动进入容器调试
docker run -it --rm \
  -e KEY="${KEY}" \
  -e CHATAFL_HYPOTHESIS=1 \
  -v "$PWD/ChatAFL-Opt:/home/ubuntu/chatafl-opt" \
  lightftp /bin/bash

# 在容器内：
cd /home/ubuntu/chatafl-opt
make clean all
cd /home/ubuntu/experiments
timeout 300 run chatafl-opt results-test '' 300 1
```

**优点**：本地修改立即生效，无需重新构建
**缺点**：需要镜像已经构建过一次

---

## 方案 C：进入运行中的容器修复（临时方案）

如果你有一个正在运行的容器：

```bash
# 1. 查看运行中的容器
docker ps

# 2. 复制修复后的文件到容器
docker cp ChatAFL-Opt/grammar-hypothesis.c <container_id>:/home/ubuntu/chatafl-opt/

# 3. 进入容器重新编译
docker exec -it <container_id> bash
cd /home/ubuntu/chatafl-opt
make clean all
exit

# 4. 重启fuzzing
docker restart <container_id>
```

**优点**：最快速
**缺点**：容器重启后修改丢失

---

## 推荐流程（当前最佳实践）

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"

# 如果镜像已存在（docker images | grep lightftp）
./quick_test.sh lightftp chatafl-opt 5

# 如果镜像不存在或想完整验证
./rebuild_and_test.sh lightftp chatafl-opt 5
```

---

## 查看测试结果

```bash
# 实时查看日志
tail -f quick_test_results/chatafl-opt_*/results-chatafl-opt/fuzzer-0/fuzz.log

# 检查是否还有崩溃
grep -i "segmentation\|dumped core\|crash" quick_test_results/chatafl-opt_*/results-chatafl-opt/fuzzer-0/fuzz.log

# 查看Grammar Hypothesis初始化
grep -i "grammar\|hypothesis\|llm" quick_test_results/chatafl-opt_*/results-chatafl-opt/fuzzer-0/fuzz.log | head -50
```

---

## 常见问题

### Q: 镜像是否存在？
```bash
docker images | grep lightftp
```

### Q: 清理所有容器重新开始
```bash
docker ps -q | xargs -r docker stop
docker ps -a -q | xargs -r docker rm
```

### Q: 查看构建日志
```bash
tail -100 /tmp/lightftp-rebuild.log
```
