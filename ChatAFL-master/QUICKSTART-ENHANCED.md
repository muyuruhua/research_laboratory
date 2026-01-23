# ChatAFL-Enhanced 快速参考

## 一键使用

```bash
# 1. 验证配置
chmod +x verify_chatafl_enhanced.sh
./verify_chatafl_enhanced.sh

# 2. 运行模糊测试
./run.sh 5 10 kamailio chatafl-enhanced
```

## 命令对比

| 任务 | ChatAFL | ChatAFL-Enhanced |
|------|---------|------------------|
| 编译 | `cd ChatAFL && make` | `cd ChatAFL-Enhanced && make CHATAFL_ENHANCED=1` |
| 运行 | `./run.sh 5 10 kamailio chatafl` | `./run.sh 5 10 kamailio chatafl-enhanced` |
| 清理 | `make clean` | `make clean` |

## 支持的 FUZZER 选项

- `aflnet` - 原始 AFLNet
- `chatafl` - ChatAFL 基础版
- `chatafl-cl1` - ChatAFL CL1 变体
- `chatafl-cl2` - ChatAFL CL2 变体
- `chatafl-enhanced` - **ChatAFL 增强版（新）**

## 支持的 TARGET 选项

### FTP 协议
- `lightftp` - LightFTP 服务器
- `bftpd` - BFTPD 服务器
- `proftpd` - ProFTPD 服务器
- `pure-ftpd` - Pure-FTPd 服务器

### 其他协议
- `exim` - SMTP 服务器
- `live555` - RTSP 媒体服务器
- `kamailio` - SIP 服务器
- `forked-daapd` - DAAP 音乐服务器
- `lighttpd1` - HTTP 服务器

## 典型工作流

### 1. 快速测试（10分钟）
```bash
./run.sh 1 10 lightftp chatafl-enhanced
```

### 2. 标准测试（1小时）
```bash
./run.sh 3 60 kamailio chatafl-enhanced
```

### 3. 长期测试（24小时）
```bash
./run.sh 5 1440 live555 chatafl-enhanced
```

### 4. 比较测试
```bash
# 同时运行 ChatAFL 和 ChatAFL-Enhanced 对比
./run.sh 5 60 kamailio chatafl &
./run.sh 5 60 kamailio chatafl-enhanced &
wait
```

## 结果查看

```bash
# 查看结果目录
ls -la benchmark/results-*/

# 解压结果
cd benchmark/results-kamailio/
tar -xzf out-kamailio-chatafl_enhanced_1.tar.gz

# 查看覆盖率
cat out-kamailio-chatafl_enhanced/cov_over_time.csv

# 查看 crash
ls out-kamailio-chatafl_enhanced/crashes/
```

## 环境变量

```bash
# 设置容器数量
export NUM_CONTAINERS=5

# 设置超时时间（分钟）
export TIMEOUT=60

# 设置跳过计数（用于覆盖率采样）
export SKIPCOUNT=1

# 设置测试超时（毫秒）
export TEST_TIMEOUT=5000
```

## 故障排除速查

### 编译失败
```bash
# 清理并重新编译
cd ChatAFL-Enhanced
make clean
make CHATAFL_ENHANCED=1 2>&1 | tee build.log
```

### Docker 构建失败
```bash
# 检查 Docker 镜像
docker images | grep -E "kamailio|lightftp"

# 重新构建
cd benchmark/subjects/SIP/Kamailio
docker build -t kamailio-fuzzing .
```

### 权限问题
```bash
# 添加执行权限
chmod +x run.sh verify_chatafl_enhanced.sh
chmod +x benchmark/scripts/execution/*.sh
```

## 开闭原则体现

✅ **对扩展开放**: 
- 通过 `CHATAFL_ENHANCED=1` 启用新功能
- 通过新增 `if [[ $FUZZER == "chatafl-enhanced" ]]` 支持新模糊器

✅ **对修改关闭**:
- 不修改 ChatAFL 原有代码
- 不修改现有的 aflnet/chatafl/chatafl-cl1/chatafl-cl2 逻辑
- 保持向后兼容

## 更多信息

详细文档请参阅：`ChatAFL-Enhanced/README-ENHANCED.md`
