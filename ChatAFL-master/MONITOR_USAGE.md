# monitor.sh 使用说明

实时监控运行中 Docker 容器的模糊测试覆盖率与状态空间探索数据。

## 基本用法

```bash
./monitor.sh [协议名] [选项]
```

## 示例

```bash
# 监控所有协议（持续刷新，默认 30s）
./monitor.sh

# 只监控 exim
./monitor.sh exim

# 监控 exim 和 mosquitto
./monitor.sh exim,mosquitto

# 看一次就退出
./monitor.sh exim -1

# 每 60 秒刷新，同时输出 CSV
./monitor.sh exim -i 60 --csv

# 指定 CSV 输出目录
./monitor.sh -o ./monitor_data

# 组合使用
./monitor.sh exim,pure-ftpd -i 120 -o ./data
```

## 参数说明

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `协议名` | 第一个位置参数，多个用逗号分隔，不填则监控全部 | 全部 |
| `-i SEC` | 采集间隔（秒） | 30 |
| `-1` | 单次采集后退出 | 持续运行 |
| `--csv` | 同时生成 CSV 时间序列文件 | 关闭 |
| `-o DIR` | CSV 输出目录（自动启用 CSV 模式） | `/tmp` |
| `-h` | 显示帮助 | - |

## 支持的协议名

与 `run_dev.sh` 一致：`exim`、`mosquitto`、`pure-ftpd`、`bftpd`、`proftpd`、`lightftp`、`live555`、`kamailio`、`forked-daapd`、`lighttpd1`

## 输出内容

### 终端表格

- **基本指标**：Bitmap 覆盖率、Paths、Execs、Crashes、Hangs、IPSM Nodes/Edges
- **LLM 指标**（仅 ChatAFL/Opt）：LLM 调用次数、Prompt/Completion Tokens、Plateau 触发次数与阈值、假设数量与适应度
- **汇总统计**：按 fuzzer 分组的均值对比

### 活跃状态指示

- `●` — 最近 2 分钟内有数据更新（正常）
- `○` — 超过 2 分钟无更新（可能卡住或执行速度慢）

### CSV 文件

启用 `--csv` 或 `-o` 后，每次采集追加一行到 `monitor_YYYYMMDD.csv`，包含 25 个字段，可直接用于绘图或 pandas 分析。

## 工作原理

通过 `docker exec` 只读读取容器内文件：

| 文件 | 数据 |
|------|------|
| `fuzzer_stats` | 覆盖率、路径数、执行数、crashes/hangs 等 |
| `ipsm.dot` | 状态机节点数和边数 |
| `plot_data` | 最后更新时间（判断活跃状态） |

仅使用 `cat`、`grep`、`tail`、`wc` 等轻量只读命令，**不写入容器任何文件、不启动新进程、不影响 fuzzer 运行**。

## 退出

按 `Ctrl+C` 随时退出，不影响容器内模糊测试。
