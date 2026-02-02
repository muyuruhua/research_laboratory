# 结果目录时间戳功能

## 功能说明

为所有 `results-` 目录添加时间戳后缀，格式为：`results-<target>_<timestamp>`

例如：
- `results-lightftp_Feb-02_14-30-25`
- `results-bftpd_Feb-02_15-45-10`

## 修改说明

### 1. 符合开闭原则 (Open-Closed Principle)

**开闭原则**：软件实体应该对扩展开放，对修改封闭。

我们的修改完全符合开闭原则：

#### ✅ 扩展性（Open for Extension）
- 在 `profuzzbench_exec_all.sh` 开头添加时间戳生成：`RESULTS_TIMESTAMP=$(date "+%b-%d_%H-%M-%S")`
- 为每个目标创建带时间戳的变量：`RESULTS_DIR="results-lightftp_${RESULTS_TIMESTAMP}"`
- 通过环境变量传递信息，无需修改核心逻辑

#### ✅ 向后兼容（Closed for Modification）
- `analyze.sh` 自动检测新旧两种格式：
  ```bash
  # 优先查找新格式：results-lightftp_Feb-02_12-34-56
  RESULTS_DIR=$(find . -maxdepth 1 -type d -name "results-${SUBJECT}_*" | sort -r | head -n 1)
  
  # 回退到旧格式：results-lightftp
  if [ -z "$RESULTS_DIR" ]; then
      RESULTS_DIR="results-${SUBJECT}"
  fi
  ```

- `profuzzbench_generate_all.sh` 使用正则表达式匹配：
  ```bash
  # 旧格式: results-lightftp -> lightftp
  # 新格式: results-lightftp_Feb-02_12-34-56 -> lightftp
  TARGET=$(echo $RESULTDIR | perl -n -l -e '/results-([^_]+)/; print $1;')
  ```

### 2. 修改的文件

1. **benchmark/scripts/execution/profuzzbench_exec_all.sh**
   - 添加时间戳生成
   - 为所有9个目标（lightftp, bftpd, proftpd, pure-ftpd, exim, live555, kamailio, forked-daapd, lighttpd1）使用带时间戳的目录名

2. **analyze.sh**
   - 添加自动发现带时间戳目录的逻辑
   - 保持向后兼容旧格式

3. **benchmark/scripts/analysis/profuzzbench_generate_all.sh**
   - 支持 RESULTS_DIR 环境变量
   - 正则表达式提取目标名称（去除时间戳后缀）

### 3. 使用示例

#### 运行模糊测试（生成带时间戳的结果目录）
```bash
sudo ./run.sh 1 30 lightftp chatafl,chatafl-opt
# 创建: benchmark/results-lightftp_Feb-02_14-30-25/
```

#### 分析结果（自动检测目录）
```bash
./analyze.sh lightftp 30
# 自动查找最新的 results-lightftp_* 目录
# 如果找不到，回退到 results-lightftp（向后兼容）
```

### 4. 时间戳格式

- **执行脚本时间戳**：`%b-%d_%H-%M-%S` （例如：`Feb-02_14-30-25`）
  - 月份简写-日期_小时-分钟-秒
  - 在脚本开始时生成一次，所有目标共享同一时间戳

- **分析结果时间戳**：`%b-%d_%H-%M-%S` （例如：`Feb-02_15-45-10`）
  - 格式相同，但在分析时重新生成
  - 用于最终结果文件夹：`res_lightftp_Feb-02_15-45-10/`

### 5. 优势

1. **易于区分**：不同时间运行的实验结果不会相互覆盖
2. **自动排序**：`find ... | sort -r` 自动获取最新结果
3. **向后兼容**：旧脚本生成的 `results-lightftp` 仍可正常分析
4. **零侵入**：不需要修改 Docker 容器内部逻辑或 profuzzbench_exec_common.sh
5. **开闭原则**：扩展了功能，但保持了对旧代码的兼容性

### 6. 测试验证

```bash
# 1. 运行模糊测试
sudo ./run.sh 1 30 lightftp chatafl

# 2. 检查生成的目录
ls benchmark/ | grep results-lightftp
# 应该看到: results-lightftp_Feb-02_14-30-25

# 3. 运行分析
cd benchmark && ../analyze.sh lightftp 30

# 4. 检查分析结果
ls .. | grep res_lightftp
# 应该看到: res_lightftp_Feb-02_15-45-10
```

## 开闭原则验证

### ✅ 对扩展开放
- 添加了新功能：时间戳目录命名
- 通过配置和参数化实现，无需改变核心算法
- 使用环境变量传递状态，符合依赖注入原则

### ✅ 对修改封闭
- 所有旧代码仍然可用
- 向后兼容旧的目录命名格式
- 不破坏现有的调用接口
- profuzzbench_exec_common.sh 完全不需要修改
- **多 fuzzer 共享目录**：使用 `mkdir -p` 确保多个 fuzzer 可以共享同一个带时间戳的结果目录

### 设计模式应用
- **策略模式**：目录命名策略可以通过时间戳变量控制
- **模板方法模式**：核心流程不变，扩展点清晰
- **单一职责原则**：时间戳生成、目录创建、结果分析各司其职
- **幂等性原则**：`mkdir -p` 确保重复调用不会失败

## 常见问题与解决

### Q1: 为什么会出现 "mkdir: cannot create directory: File exists" 错误？

**原因**：当使用多个 fuzzer（如 `chatafl,chatafl-opt`）时，所有 fuzzer 应该共享同一个 results 目录。

**解决**：已使用 `mkdir -p` 替代 `mkdir`，确保：
- 第一个 fuzzer 创建目录成功
- 后续 fuzzer 发现目录存在时不会报错
- 所有 fuzzer 的结果保存在同一个带时间戳的目录中

**目录结构**：
```
results-lightftp_Feb-02_19-15-06/
├── out-lightftp-chatafl_1.tar.gz      # 第一个 fuzzer 的结果
└── out-lightftp-chatafl_opt_1.tar.gz  # 第二个 fuzzer 的结果
```
