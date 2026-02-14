# 开发模式使用说明

## 问题
Docker镜像构建时间过长（每次修改代码都要重新构建30分钟+），严重影响开发效率。

## 解决方案：Volume挂载开发模式

### 核心原理
将本地fuzzer代码目录挂载到Docker容器中，修改本地文件后：
- ✅ **无需重新构建镜像**
- ✅ **修改立即生效**（容器重启即可）
- ✅ **保持版本控制**
- ✅ **镜像只需构建一次**

---

## 方案1：使用run_dev.sh（推荐用于完整测试）

### 使用步骤

1. **首次构建镜像**（只需一次）
```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
export KEY="your-api-key"

# 构建目标镜像（只需执行一次）
cd benchmark
docker build -t lightftp subjects/FTP/LightFTP/
cd ..
```

2. **开发迭代**（后续开发使用）
```bash
# 修改本地代码
vim ChatAFL-Opt/grammar-hypothesis.c
vim ChatAFL-Opt/afl-fuzz.c

# 直接运行测试（volume自动挂载）
sudo -E ./run_dev.sh 1 5 lightftp chatafl-opt

# 再次修改代码后，直接重新运行即可，无需重新构建镜像！
```

### 工作原理
- `run_dev.sh` 会自动将 `ChatAFL-Opt/` 挂载到容器的 `/home/ubuntu/chatafl-opt/`
- 容器启动时使用挂载的代码，而非镜像中编译的旧代码
- 修改本地文件 = 修改容器内文件

---

## 方案2：使用quick_test.sh（推荐用于快速验证）

### 特点
- 更简单直接
- 实时查看结果
- 适合快速验证修改

### 使用方法

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master

# 快速测试5分钟
./quick_test.sh lightftp chatafl-opt 5

# 测试其他fuzzer
./quick_test.sh lightftp chatafl 10
./quick_test.sh lightftp aflnet 5
```

### 输出位置
结果自动保存到：`quick_test_results/chatafl-opt_YYYYMMDD_HHMMSS/`

---

## 典型开发流程

```bash
# 1. 修改代码
vim ChatAFL-Opt/grammar-hypothesis.c

# 2. 快速验证（5分钟测试）
./quick_test.sh lightftp chatafl-opt 5

# 3. 查看日志
tail -f quick_test_results/chatafl-opt_*/results-chatafl-opt/fuzzer-0/fuzz.log

# 4. 如果有问题，继续修改代码并重复步骤2-3

# 5. 验证通过后，运行完整测试
sudo -E ./run_dev.sh 1 30 lightftp chatafl-opt
```

---

## 为什么不推荐手动复制到容器

❌ **不推荐的方法：**
```bash
docker cp file.c container_id:/path/  # 容器重启后丢失
docker commit container_id new_image   # 无法追溯、难维护
```

**问题：**
1. 镜像是只读的，无法直接修改
2. 只能复制到运行中的容器，容器重启后修改丢失
3. 即使用commit保存，也失去了可复现性和版本控制

---

## 对比总结

| 方法 | 首次构建 | 修改代码后 | 版本控制 | 推荐度 |
|------|---------|-----------|---------|--------|
| **Volume挂载** | 30分钟（一次） | 0分钟（重启容器） | ✅ 完美 | ⭐⭐⭐⭐⭐ |
| 重新构建镜像 | 30分钟 | 30分钟 | ✅ 完美 | ⭐⭐ (仅用于发布) |
| docker cp | 30分钟 | 1分钟 | ❌ 丢失 | ⭐ (不推荐) |
| docker commit | 30分钟 | 5分钟 | ❌ 混乱 | ⭐ (不推荐) |

---

## 常见问题

### Q1: 挂载后代码修改为何不生效？
A: 如果fuzzer已编译成二进制，需要在容器内重新编译：
```bash
docker exec -it <container_id> bash
cd /home/ubuntu/chatafl-opt
make clean all
```

### Q2: 能否同时挂载多个fuzzer？
A: 可以，修改 `profuzzbench_exec_common_dev.sh` 添加更多volume：
```bash
-v "${PROJECT_ROOT}/ChatAFL-Opt:/home/ubuntu/chatafl-opt" \
-v "${PROJECT_ROOT}/ChatAFL:/home/ubuntu/chatafl"
```

### Q3: 如何在容器内调试？
A: 启动交互式容器：
```bash
docker run -it --rm \
  -v "$PWD/ChatAFL-Opt:/home/ubuntu/chatafl-opt" \
  lightftp /bin/bash
  
# 然后在容器内
cd /home/ubuntu/chatafl-opt
ls -la
make clean all
./afl-fuzz --help
```

---

## 注意事项

1. **权限问题**：容器内用户是ubuntu(uid=1000)，确保本地文件权限正确
2. **编译产物**：挂载后，本地目录的 `.o` 文件会被容器编译产物覆盖
3. **API Key**：记得设置 `export KEY="your-api-key"`
4. **SELinux**：如果使用SELinux，volume路径添加 `:z` 后缀

---

## 生产环境部署

开发验证完成后，更新setup.sh确保生产环境使用最新代码：

```bash
# 提交代码
git add ChatAFL-Opt/
git commit -m "Fix grammar hypothesis"

# 运行完整构建（用于正式实验）
export KEY="your-api-key"
./setup.sh
./run.sh 5 1440 lightftp chatafl-opt  # 5个容器，24小时
```
