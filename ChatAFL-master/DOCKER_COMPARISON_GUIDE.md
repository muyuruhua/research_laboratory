# Docker版本对比脚本使用指南

## 问题解决

### 为什么需要Docker版本？

之前的本地版本脚本遇到关键问题：
- ❌ 从容器复制的二进制文件**没有AFL插桩**
- ❌ AFLNet无法检测服务器状态（"No server states have been detected"）
- ❌ 路径和依赖配置复杂

### Docker版本优势

✅ 使用容器内**AFL编译的插桩二进制文件**  
✅ 环境完全隔离和配置  
✅ 与ProFuzzBench官方方式一致  
✅ 支持所有目标程序  

## 使用方法

### 1. 确保Docker镜像已构建

```bash
cd benchmark/subjects/FTP/LightFTP
docker build -t lightftp .
```

### 2. 运行对比测试

```bash
./compare_fuzzers_docker.sh <TARGET> <PROTOCOL> <时长(分钟)>
```

### 示例

```bash
# FTP服务器测试（3分钟快速测试）
./compare_fuzzers_docker.sh LightFTP FTP 3

# RTSP服务器测试（60分钟完整测试）
./compare_fuzzers_docker.sh Live555 RTSP 60

# SMTP服务器测试
./compare_fuzzers_docker.sh Exim SMTP 60
```

## 支持的目标

| 目标 | 协议 | Docker镜像名 |
|------|------|-------------|
| LightFTP | FTP | lightftp |
| BFTPD | FTP | bftpd |
| ProFTPD | FTP | proftpd |
| PureFTPD | FTP | pure-ftpd |
| Live555 | RTSP | live555 |
| Exim | SMTP | exim |
| Kamailio | SIP | kamailio |
| forked-daapd | DAAP | forked-daapd |
| Lighttpd1 | HTTP | lighttpd1 |

## 实时监控

测试运行时，脚本会显示：
```
剩余时间: 02:50 | ChatAFL执行数: 813 | Enhanced执行数: 765
```

### 查看详细日志

在另一个终端中：
```bash
# 查看ChatAFL日志
docker logs -f chatafl_LightFTP_<TIMESTAMP>

# 查看Enhanced日志
docker logs -f enhanced_LightFTP_<TIMESTAMP>
```

## 结果分析

测试完成后，查看对比报告：
```bash
cat comparison_results/LightFTP_<TIMESTAMP>/report.txt
```

报告包含：
- **执行统计**: 执行次数、执行速度
- **路径发现**: 新路径数量、代码覆盖率
- **漏洞发现**: 崩溃、挂起数量
- **Enhanced特性**: STT状态树、CEGAR补丁

### 示例报告

```
===== ChatAFL vs ChatAFL-Enhanced 对比报告 =====
目标: LightFTP (FTP), 时长: 60分钟

========== ChatAFL 统计 ==========
execs_done        : 45623
execs_per_sec     : 12.67
paths_total       : 89
unique_crashes    : 2
bitmap_cvg        : 3.21%

========== ChatAFL-Enhanced 统计 ==========
execs_done        : 43890
execs_per_sec     : 12.19
paths_total       : 112
unique_crashes    : 3
bitmap_cvg        : 4.15%

========== Enhanced特有功能 ==========
STT导出文件数: 15
CEGAR缓存数: 8

========== 对比分析 ==========
路径数对比: ChatAFL=89, Enhanced=112
Enhanced路径发现提升: +25.84%
```

## 故障排查

### Docker镜像不存在

```bash
[✗] Docker镜像不存在: lightftp
```

**解决**: 构建镜像
```bash
cd benchmark/subjects/FTP/LightFTP
docker build -t lightftp .
```

### 容器启动失败

检查Docker状态：
```bash
docker ps -a | grep lightftp
docker logs <container_id>
```

### 清理旧容器

```bash
docker ps -a | grep -E "chatafl|enhanced"
docker rm $(docker ps -a -q -f name=chatafl)
docker rm $(docker ps -a -q -f name=enhanced)
```

## 对比：本地版 vs Docker版

| 特性 | 本地版 (compare_fuzzers.sh) | Docker版 (compare_fuzzers_docker.sh) |
|------|------------------------------|--------------------------------------|
| AFL插桩 | ❌ 缺失 | ✅ 完整 |
| 状态检测 | ❌ 失败 | ✅ 正常 |
| 环境配置 | ❌ 复杂 | ✅ 自动 |
| 路径发现 | ❌ 0个 | ✅ 正常 |
| 推荐使用 | ❌ | ✅ |

## 性能建议

### 短时测试（验证）
```bash
./compare_fuzzers_docker.sh LightFTP FTP 3
```
用于快速验证fuzzing是否正常工作。

### 标准测试（对比）
```bash
./compare_fuzzers_docker.sh LightFTP FTP 60
```
60分钟足以看出明显差异。

### 完整测试（论文级）
```bash
./compare_fuzzers_docker.sh LightFTP FTP 1440
```
24小时测试，用于论文实验。

## 下一步

1. **查看STT可视化**:
   ```bash
   ls comparison_results/*/chatafl-enhanced/.stt_export/*.dot
   dot -Tpng state_tree.dot -o state_tree.png
   ```

2. **分析崩溃样本**:
   ```bash
   ls comparison_results/*/chatafl*/crashes/
   ```

3. **覆盖率分析**:
   查看`bitmap_cvg`和`paths_total`指标

4. **对比多次运行**:
   多次运行取平均值，减少随机性影响
