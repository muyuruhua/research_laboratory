# 环境变量传递问题修复说明

## 问题现象
执行 `sudo -E ./run.sh` 时已设置 `export KEY="sk-..."`，但 Docker 容器内部仍然报错：
```
KEY environment variable not set
```

---

## 根本原因

### 环境变量传递路径

```
宿主机 shell
   ↓ (export KEY=...)
run.sh 脚本
   ↓ (KEY="$KEY")
profuzzbench_exec_all.sh
   ↓ (继承 KEY)
profuzzbench_exec_common.sh
   ↓ (docker run ...)
Docker 容器 ❌ 断层！
```

**关键问题**：
- `sudo -E` 只能保证环境变量传递给 `./run.sh` 脚本
- `run.sh` 和 `profuzzbench_exec_all.sh` 正确传递了 `KEY` 变量
- **但是 `docker run` 命令没有使用 `-e` 参数，环境变量无法进入容器**

### Docker 环境变量隔离机制

Docker 容器有独立的环境变量空间，**宿主机的环境变量不会自动继承到容器内部**。

必须显式使用以下方式传递：
```bash
docker run -e KEY="value" ...        # 方式1：直接赋值
docker run -e KEY="${KEY}" ...       # 方式2：继承宿主机变量
docker run --env-file .env ...       # 方式3：从文件读取
```

---

## 修复方案

### 修改文件：`benchmark/scripts/execution/profuzzbench_exec_common.sh`

**修改位置**：第22行

**修改前**：
```bash
id=$(docker run --cpus=1 -d -it $DOCIMAGE /bin/bash -c "cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
```

**修改后**：
```bash
id=$(docker run --cpus=1 -e KEY="${KEY}" -d -it $DOCIMAGE /bin/bash -c "cd ${WORKDIR} && run ${FUZZER} ${OUTDIR} '${OPTIONS}' ${TIMEOUT} ${SKIPCOUNT}")
```

**关键变化**：添加 `-e KEY="${KEY}"` 参数

---

## 验证修复

### 1. 手动测试环境变量传递

```bash
export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"

# 测试容器能否接收到 KEY
docker run --rm -e KEY="${KEY}" lightftp:latest bash -c \
  'if [ -z "$KEY" ]; then echo "FAIL"; else echo "SUCCESS: KEY length=${#KEY}"; fi'
```

**期望输出**：
```
SUCCESS: KEY length=51
```

### 2. 运行完整 fuzzing 流程

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"
sudo -E ./run.sh 1 20 lightftp chatafl-opt
```

### 3. 检查容器日志

```bash
# 获取容器ID
docker ps -a | grep lightftp

# 查看日志（应该不再有 KEY not set 错误）
docker logs <container_id> | grep -E "KEY|RFC"
```

**期望输出**：
```
[*] RFC text not provided, attempting auto-fetch for FTP...
[RFC] Fetching RFC for FTP from https://www.rfc-editor.org/rfc/rfc959.txt...
[+] Fetched RFC for FTP (121845 bytes)
[+] Injected 18456 chars of RFC content into LLM prompt
...
```

**不应该再出现**：
```
KEY environment variable not set
```

---

## 为什么需要重新构建镜像？

**答案：不需要！**

这个问题**与镜像构建无关**，是运行时环境变量传递问题。

### 镜像层次：
- **构建时**（`docker build`）：
  - 代码、依赖、编译结果打包进镜像
  - 不涉及运行时环境变量
  
- **运行时**（`docker run`）：
  - 环境变量通过 `-e` 参数传入
  - 代码已存在镜像中，直接执行

### 因此：
- ✅ 修改 `profuzzbench_exec_common.sh` 后，**直接运行即可**
- ❌ 不需要重新执行 `docker build`（除非修改了容器内的代码）

---

## 环境变量传递最佳实践

### 1. 使用 `docker-compose`（推荐）

创建 `docker-compose.yml`：
```yaml
version: '3.8'
services:
  fuzzer:
    image: lightftp:latest
    environment:
      - KEY=${KEY}
    command: /bin/bash -c "cd /home/ubuntu/experiments && run chatafl-opt ..."
```

运行：
```bash
export KEY="sk-..."
docker-compose up
```

### 2. 使用 `.env` 文件

创建 `.env`：
```bash
KEY=sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS
```

运行：
```bash
docker run --env-file .env lightftp:latest ...
```

### 3. 批量传递多个环境变量

```bash
docker run \
  -e KEY="${KEY}" \
  -e MODEL="gpt-4o-mini" \
  -e DEBUG="1" \
  lightftp:latest ...
```

---

## 故障排查清单

如果仍然遇到 "KEY environment variable not set" 错误：

1. **检查宿主机环境变量**：
   ```bash
   echo "KEY length: ${#KEY}"  # 应该显示 51
   ```

2. **检查 sudo -E 是否生效**：
   ```bash
   sudo -E env | grep KEY  # 应该显示 KEY=sk-...
   ```

3. **检查 run.sh 是否传递 KEY**：
   ```bash
   # 在 run.sh 的第20行后添加调试输出
   echo "DEBUG: KEY in run.sh = ${KEY}"
   ```

4. **检查 docker run 命令**：
   ```bash
   # 在容器启动前打印 docker run 命令
   echo "docker run --cpus=1 -e KEY=\"${KEY}\" ..."
   ```

5. **检查容器内部**：
   ```bash
   docker exec <container_id> bash -c 'echo "KEY in container: $KEY"'
   ```

---

## 相关文件清单

| 文件 | 作用 | 修改内容 |
|------|------|---------|
| `run.sh` | 入口脚本 | 已正确传递 `KEY="$KEY"` ✅ |
| `benchmark/scripts/execution/profuzzbench_exec_all.sh` | 调度脚本 | 继承 KEY 变量 ✅ |
| `benchmark/scripts/execution/profuzzbench_exec_common.sh` | 容器启动脚本 | **添加 `-e KEY="${KEY}"`** 🔧 |

---

## 总结

**问题**：环境变量在宿主机和 Docker 容器之间断层  
**原因**：`docker run` 命令缺少 `-e KEY="${KEY}"` 参数  
**修复**：在 `profuzzbench_exec_common.sh` 第22行添加环境变量传递  
**验证**：手动测试 + 运行 fuzzing 检查日志  
**注意**：无需重新构建镜像，修改脚本后直接运行即可  

现在环境变量已正确传递到容器内部，ChatAFL-Opt 的 LLM 功能可以正常工作！🚀
