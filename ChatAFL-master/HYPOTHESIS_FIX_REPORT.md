# ChatAFL-Opt Segmentation Fault 修复报告

## 问题诊断

### 容器日志分析 (4375dba69654)
```
[+] Grammar Hypothesis Mode enabled (CHATAFL_HYPOTHESIS env var set)
[*] Initializing Grammar Hypothesis System...
[*] RFC text not provided, attempting auto-fetch for FTP...
[RFC] Fetching RFC for FTP from https://www.rfc-editor.org/rfc/rfc959.txt...
[RFC] ✓ Fetched RFC for FTP (147316 bytes)
[*] Saved RFC for FTP to cache (147316 bytes)
[+] Successfully fetched RFC for FTP (147316 bytes)
timeout: the monitored command dumped core
/home/ubuntu/experiments/run: line 56:     8 Segmentation fault
```

### 根本原因

**缓冲区溢出导致段错误**

1. **触发条件**: RFC 文本过大（147KB）导致 LLM prompt 构建时超出 `MAX_HYPOTHESIS_PROMPT` (64KB) 限制
2. **问题代码**: `construct_hypothesis_generation_prompt()` 中多次使用 `snprintf()` 但未检查返回值
3. **后果**: `offset` 变量持续累加超出缓冲区边界，导致内存访问违规（Segmentation Fault）

## 修复内容

### 文件: `ChatAFL-Opt/grammar-hypothesis.c`

#### 1. 添加严格的 snprintf 返回值检查

**修复前** (示例):
```c
offset += snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset, ...);
```

**修复后**:
```c
written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset, ...);
if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
    fprintf(stderr, "[!] Prompt buffer overflow\n");
    ck_free(prompt);
    return NULL;
}
offset += written;
```

#### 2. 修改位置统计

- **行 178-191**: system message 和 protocol name - 添加溢出检查和错误返回
- **行 206-221**: RFC content injection - 添加溢出检查，优雅降级（跳过 RFC 而非崩溃）
- **行 227-262**: PCAP samples - 添加溢出检查和 `goto finalize_prompt` 跳转
- **行 267-284**: Request format - 添加最终溢出检查
- **行 351**: `generate_grammar_hypotheses()` - 添加 prompt NULL 指针检查

#### 3. 新增 goto label 用于错误恢复

```c
finalize_prompt:
    // Request format
    written = snprintf(prompt + offset, MAX_HYPOTHESIS_PROMPT - offset, ...);
    if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset) {
        fprintf(stderr, "[!] Prompt buffer overflow at final request format\n");
        ck_free(prompt);
        return NULL;
    }
    offset += written;
    
    printf("[+] Constructed LLM prompt (%d bytes total)\n", offset);
    return prompt;
```

#### 4. 增强日志输出

- 详细的溢出位置信息（system message / RFC / PCAP / final format）
- 显示尝试写入的字节数和剩余空间
- 成功构建后输出 prompt 总大小

## 修复效果

### 预期行为

1. **正常场景**: RFC 小于 20KB → 完整注入 → 生成 hypothesis
2. **RFC 过大**: 智能截取 → 部分注入 → 生成 hypothesis
3. **极端溢出**: 检测到溢出 → 返回 NULL → 优雅降级为标准模式

### 错误日志示例（修复后）

```
[!] Prompt buffer overflow at RFC content (tried to write 65000 bytes, 10000 available)
[!] Continuing without full RFC content
[+] Constructed LLM prompt (55234 bytes total)
```

或

```
[!] Prompt buffer overflow at final request format
[!] Failed to construct hypothesis generation prompt (buffer overflow)
[!] Failed to generate hypotheses from LLM
[-] No grammar hypotheses generated, continuing in standard mode
```

## 部署步骤

1. ✅ 修复源文件: `ChatAFL-Opt/grammar-hypothesis.c`
2. ✅ 复制到构建目录:
   - `benchmark/subjects/FTP/LightFTP/chatafl-opt/grammar-hypothesis.c`
   - `benchmark/subjects/FTP/BFTPD/chatafl-opt/grammar-hypothesis.c`
3. 🔄 重新构建 Docker 镜像:
   ```bash
   cd benchmark
   docker build --no-cache -t lightftp subjects/FTP/LightFTP
   docker build --no-cache -t bftpd subjects/FTP/BFTPD
   ```
4. ⏳ 验证修复:
   ```bash
   ./verify_hypothesis_fix.sh
   ```

## 验证方法

### 运行测试

```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
sudo -E ./run.sh 1 10 lightftp chatafl-opt
```

### 监控日志

```bash
docker ps  # 获取容器 ID
docker logs -f <container_id> | grep -E 'hypothesis|buffer overflow|Segmentation|Generated'
```

### 预期输出（成功）

```
[+] Grammar Hypothesis Mode enabled (CHATAFL_HYPOTHESIS env var set)
[*] Initializing Grammar Hypothesis System...
[RFC] ✓ Fetched RFC for FTP (147316 bytes)
[+] Injected 19998 chars of RFC content into LLM prompt
[+] Constructed LLM prompt (54321 bytes total)
[+] Generated 5 grammar hypotheses
[+] Grammar Hypothesis System initialized.
```

### 回退方案

如果修复后仍有问题，可以禁用 hypothesis:

```bash
# 编辑 profuzzbench_exec_common.sh
# 注释掉 CHATAFL_HYPOTHESIS=1 环境变量
```

## 技术细节

### snprintf 返回值规范

- **返回值**: 实际需要写入的字符数（不包括 null 终止符）
- **成功**: `0 <= 返回值 < size`
- **截断**: `返回值 >= size` （表示缓冲区不足）
- **错误**: `返回值 < 0`

### 边界条件检查公式

```c
if (written < 0 || written >= MAX_HYPOTHESIS_PROMPT - offset)
```

- `written < 0`: 编码错误
- `written >= remaining`: 缓冲区不足，数据被截断

## 后续优化建议

1. **动态分配**: 考虑根据 RFC 大小动态分配 prompt buffer
2. **RFC 压缩**: 实现更智能的 RFC 内容提取算法
3. **分段生成**: 对于超大 RFC，分多次 LLM 调用
4. **监控指标**: 添加 prometheus metrics 跟踪缓冲区使用率

---

**修复时间**: 2026-02-13  
**影响范围**: ChatAFL-Opt 的 Grammar Hypothesis 模块  
**严重程度**: Critical（导致 fuzzer 崩溃）  
**测试状态**: 待验证
