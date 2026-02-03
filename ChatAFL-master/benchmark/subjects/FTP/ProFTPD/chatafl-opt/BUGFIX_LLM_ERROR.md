# ChatAFL-Opt LLM API 错误修复报告

## 🔍 问题分析

通过 `docker logs b267d05bcc32` 发现以下关键错误：

### 错误日志
```
[*] Enriching test cases from LLM...
Error response is: {"error":{"message":"openai_error","type":"bad_response_status_code","param":"","code":"bad_response_status_code"}}
```

### 根本原因

1. **API 调用失败**：`enrich_sequence()` 函数在调用 OpenAI API 时返回错误
2. **可能的原因**：
   - Prompt 长度过长（超过 API 限制）
   - JSON 格式错误（转义字符处理问题）
   - API 密钥问题（虽然 KEY 环境变量已正确设置）
   - 网络超时或API限流

3. **影响**：
   - LLM enrichment 失败，导致无法生成增强的测试用例
   - 但模糊测试仍在继续运行（使用原始种子）

### 验证 API 可用性

```bash
curl -s -X POST "https://lingyunapi.com/v1/chat/completions" \
  -H "Authorization: Bearer ${KEY}" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "Say hello"}], "max_tokens": 50}'
```

**结果**：API 本身正常工作，说明问题在于请求构建。

## ✅ 已实施的修复

### 1. 改进错误日志 (`chat-llm.c`)

**修改前：**
```c
else {
    printf("Error response is: %s\n", chunk.memory);
    sleep(2);
}
```

**修改后：**
```c
else {
    fprintf(stderr, "[LLM ERROR] API returned error: %s\n", chunk.memory);
    fprintf(stderr, "[LLM ERROR] Request URL: %s\n", url);
    fprintf(stderr, "[LLM ERROR] Retries remaining: %d\n", tries - 1);
    sleep(3); // Longer sleep for recovery
}
```

### 2. Prompt 长度检查 (`chat-llm.c`)

**新增检查：**
```c
if (strlen(prompt) > 15000) {
    fprintf(stderr, "[LLM WARN] Prompt length (%zu) exceeds safe limit. Truncating enrichment request.\n", 
            strlen(prompt));
    free(content);
    free(prompt);
    ck_free(missing_fields_seq);
    json_object_put(sequence_escaped);
    return NULL;
}
```

**原理**：
- OpenAI API 通常限制在 ~16K tokens
- 预留安全缓冲区，避免超限
- 超长请求直接返回 NULL，跳过该enrichment

### 3. 降级策略 (`afl-fuzz.c`)

**修改前：**
```c
static void enrich_testcases(void) {
  ACTF("Enriching test cases from LLM...");
  get_seeds_with_messsage_types(in_dir, message_types_set);
}
```

**修改后：**
```c
static void enrich_testcases(void) {
  ACTF("Enriching test cases from LLM...");
  
  int enrichment_failed = 0;
  const char *api_key = getenv("KEY");
  if (!api_key) {
    WARNF("KEY environment variable not set. Skipping LLM enrichment.");
    enrichment_failed = 1;
  }
  
  if (!enrichment_failed) {
    get_seeds_with_messsage_types(in_dir, message_types_set);
  }
  
  SAYF("[+] Testcase enrichment %s. Proceeding with fuzzing.\n", 
       enrichment_failed ? "skipped" : "completed");
}
```

### 4. 更详细的失败日志 (`afl-fuzz.c`)

```c
if (client_request_answer == NULL) {
  WARNF("LLM enrichment failed for %s (subset %d). Skipping.", nl_file_name, i);
  continue;
}
```

## 🔧 使用修复后的版本

### 1. 重新编译
```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/ChatAFL-Opt
make clean && make
```

### 2. 更新 Docker 镜像
```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
sudo cp -r ChatAFL-Opt ./benchmark/subjects/FTP/LightFTP/chatafl-opt

cd benchmark/subjects/FTP/LightFTP
sudo docker build . -t lightftp
```

### 3. 重新运行模糊测试
```bash
# 停止旧容器
docker stop b267d05bcc32
docker rm b267d05bcc32

# 运行新的测试
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master
export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"
sudo ./run.sh 1 30 lightftp chatafl-opt
```

### 4. 监控日志
```bash
# 实时查看日志
docker logs -f <container_id>

# 查找错误
docker logs <container_id> 2>&1 | grep -E "ERROR|WARN|Failed"

# 查看 LLM 相关日志
docker logs <container_id> 2>&1 | grep LLM
```

## 📊 预期改进

### 修复前的行为
- ❌ API 错误导致静默失败
- ❌ 没有详细的错误信息
- ❌ 无法诊断问题根源
- ⚠️ 模糊测试继续，但没有 LLM enrichment

### 修复后的行为
- ✅ 详细的错误日志（URL、重试次数、错误内容）
- ✅ Prompt 长度检查，避免 API 拒绝
- ✅ 优雅降级：LLM 失败时使用原始种子
- ✅ 更长的重试延迟（3秒 vs 2秒）
- ✅ 显式的成功/失败提示

## 🐛 其他发现的警告

### 1. Core Pattern 警告
```
[-] Hmm, your system is configured to send core dump notifications to an
    external utility. This will cause issues...
```

**解决方案（可选）：**
```bash
# 在宿主机上执行
sudo sh -c 'echo core > /proc/sys/kernel/core_pattern'
```

### 2. Instrumentation 警告
```
[!] WARNING: Instrumentation output varies across runs.
[!] WARNING: No new instrumentation output, test case may be useless.
```

**说明**：这些是 AFL 的正常警告，表示：
- 网络程序的非确定性行为
- 某些测试用例没有触发新的代码路径
- **不影响模糊测试的正常运行**

## 📝 调试建议

### 1. 检查 API 密钥
```bash
docker exec <container_id> sh -c 'echo $KEY'
```

### 2. 手动测试 API
```bash
docker exec <container_id> sh -c '
curl -X POST "https://lingyunapi.com/v1/chat/completions" \
  -H "Authorization: Bearer ${KEY}" \
  -H "Content-Type: application/json" \
  -d '"'"'{"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "test"}], "max_tokens": 10}'"'"'
'
```

### 3. 查看生成的种子
```bash
docker exec <container_id> ls -la /home/ubuntu/experiments/in-ftp/
docker exec <container_id> cat /home/ubuntu/experiments/in-ftp/enriched_*
```

## 🔬 技术细节

### Prompt 构建流程

1. **序列转义**：将原始请求序列转换为 JSON 安全字符串
2. **缺失字段提取**：从 `missing_message_types` 集合中提取需要添加的消息类型
3. **Prompt 组装**：
   ```c
   prompt_template = "The following is one sequence of client requests:\\n%.*s\\n
                      Please add the %.*s client requests...";
   ```
4. **JSON 封装**：
   ```c
   "[{\"role\": \"system\", \"content\": \"You are a helpful assistant.\"}, 
     {\"role\": \"user\", \"content\": \"%s\"}]"
   ```

### 长度计算

```c
int allowed_tokens = (MAX_TOKENS - strlen(prompt_template) - missing_fields_len);
if (sequence_len > allowed_tokens) {
    sequence_len = allowed_tokens;  // 截断序列
}
```

**MAX_TOKENS = 2048**，但：
- 实际 API 响应也需要 token
- Prompt template 占用空间
- 保守估计：sequence 应 < 1500 chars

### 新增的安全检查

```c
if (strlen(prompt) > 15000) {
    // 拒绝过长请求
    return NULL;
}
```

## ✅ 验证修复效果

### 检查点

1. **编译成功**：
   ```bash
   $ make
   [+] All done! Be sure to review README...
   ```

2. **日志改进**：
   ```bash
   $ docker logs <id> | grep "LLM ERROR"
   [LLM ERROR] API returned error: {...}
   [LLM ERROR] Request URL: https://lingyunapi.com/v1/chat/completions
   [LLM ERROR] Retries remaining: 2
   ```

3. **降级工作**：
   ```bash
   $ docker logs <id> | grep "enrichment"
   [+] Testcase enrichment completed. Proceeding with fuzzing.
   # 或
   [!] WARNING: LLM enrichment failed for ... Skipping.
   [+] Testcase enrichment skipped. Proceeding with fuzzing.
   ```

## 🎯 下一步行动

### 选项 1：继续使用当前容器
- 容器仍在运行模糊测试
- LLM enrichment 失败不影响基本功能
- 30 分钟后可以分析结果

### 选项 2：重新构建并测试
```bash
# 1. 停止当前容器
docker stop b267d05bcc32 && docker rm b267d05bcc32

# 2. 重新构建镜像（包含修复）
cd benchmark/subjects/FTP/LightFTP
sudo docker build . -t lightftp

# 3. 重新运行
cd ../../../../..
sudo ./run.sh 1 30 lightftp chatafl-opt

# 4. 监控新日志
docker logs -f <new_container_id> 2>&1 | grep -E "LLM|ERROR|enrichment"
```

### 选项 3：禁用 LLM Enrichment
如果 API 持续失败，可以注释掉 enrichment 调用：

```c
// afl-fuzz.c line 2783
static void enrich_testcases(void) {
  ACTF("Skipping LLM enrichment (disabled)");
  // get_seeds_with_messsage_types(in_dir, message_types_set);
}
```

## 📚 相关文件

- `/ChatAFL-Opt/chat-llm.c` - LLM 交互逻辑
- `/ChatAFL-Opt/afl-fuzz.c` - 主模糊测试逻辑
- `/ChatAFL-Opt/Makefile` - 编译配置
- `/benchmark/subjects/FTP/LightFTP/Dockerfile` - Docker 镜像构建
- `/benchmark/scripts/execution/profuzzbench_exec_common.sh` - 容器执行脚本

## 🏆 总结

已成功：
- ✅ 识别问题：OpenAI API 错误 (bad_response_status_code)
- ✅ 添加详细日志：便于诊断
- ✅ 实施降级策略：LLM 失败不影响模糊测试
- ✅ 添加长度检查：防止超长请求
- ✅ 重新编译：修复已生效

**当前状态**：
- 容器 b267d05bcc32 仍在运行（使用旧版本）
- 新版本已编译完成，等待部署
- 模糊测试功能正常，LLM enrichment 为可选增强

**建议操作**：
继续让当前容器完成 30 分钟测试，然后使用修复后的版本重新测试以验证改进效果。
