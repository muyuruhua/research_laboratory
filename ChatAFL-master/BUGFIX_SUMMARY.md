# ChatAFL LLM API 调用问题修复总结

## 问题分析

### 症状
1. `testLLM1.c` 独立程序能够正常调用大模型 API
2. `afl-fuzz` 运行时出现两类错误：
   - 第一阶段："无效的令牌" (Invalid token)  
   - 第二阶段："无效的请求, invalid character 'T' looking for beginning of value"

### 根本原因

#### 问题 1: API Key 未从环境变量读取
**位置**: `chat-llm.c` 第 59 行

**原始代码**:
```c
char *auth_header = "Authorization: Bearer " OPENAI_TOKEN;
```

**问题**: 
- 使用了编译时定义的宏 `OPENAI_TOKEN`（在 `chat-llm.h` 中定义为 `"1"`）
- 没有读取环境变量 `KEY`
- 导致发送无效的 API token

**修复**:
```c
const char *api_key = getenv("KEY");
if (!api_key) {
    fprintf(stderr, "KEY environment variable not set\n");
    return NULL;
}
char auth_header[256];
snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", api_key);
```

#### 问题 2: Prompt 格式不正确

**位置**: 
- `construct_prompt_for_requests_to_states()` (第 369-378 行)
- `enrich_sequence()` (第 962-975 行)

**问题**:
这两个函数返回的是纯文本字符串，但 `chat_with_llm()` 函数期望接收 JSON 格式的 messages 数组：

```c
asprintf(&data, "{\"model\": \"gpt-4o-mini\",\"messages\": %s, ...}", prompt);
```

如果 `prompt` 是纯文本（如 "This is a test"），生成的 JSON 会是：
```json
{"model": "gpt-4o-mini","messages": This is a test, ...}
```
这会导致 JSON 解析错误："invalid character 'T' looking for beginning of value"

**修复 1 - construct_prompt_for_requests_to_states()**:
```c
char *content = NULL;
asprintf(&content,
         "In the %s protocol, if the server just starts, to reach the INIT state, the sequence of client requests can be:\\n"
         "%.*s\\nSimilarly, in the %s protocol, if the server just starts, to reach the %.*s state, the sequence of client requests can be:\\n",
         protocol_name,
         example_request_len,
         example_requests_json_str + 1,
         protocol_name,
         (int)strlen(protocol_state_json_str) - 2,
         protocol_state_json_str + 1);

asprintf(&prompt, "[{\"role\": \"system\", \"content\": \"You are a helpful assistant.\"}, {\"role\": \"user\", \"content\": \"%s\"}]", content);

free(content);
```

**修复 2 - enrich_sequence()**:
```c
char *content = NULL;
asprintf(&content, prompt_template, sequence_len, sequence_escaped_str, missing_fields_len, missing_fields_seq);
asprintf(&prompt, "[{\"role\": \"system\", \"content\": \"You are a helpful assistant.\"}, {\"role\": \"user\", \"content\": \"%s\"}]", content);

free(content);
```

## 代码对比

### testLLM1.c (工作正常)
```c
const char *api_key = getenv("KEY");  // ✅ 从环境变量读取
snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", api_key);

char* messages = "[{\"role\": \"user\", \"content\": \"...\"}]";  // ✅ 正确的 JSON 格式
```

### chat-llm.c (修复前)
```c
char *auth_header = "Authorization: Bearer " OPENAI_TOKEN;  // ❌ 使用硬编码的 "1"

// construct_prompt_for_requests_to_states 返回:
asprintf(&prompt, "In the %s protocol...", ...);  // ❌ 纯文本
```

### chat-llm.c (修复后)
```c
const char *api_key = getenv("KEY");  // ✅ 从环境变量读取
snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", api_key);

// construct_prompt_for_requests_to_states 返回:
asprintf(&prompt, "[{\"role\": \"system\", \"content\": \"You are a helpful assistant.\"}, {\"role\": \"user\", \"content\": \"%s\"}]", content);  // ✅ 正确的 JSON
```

## 修改的文件

### /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/ChatAFL/chat-llm.c

**修改 1** (第 59-66 行): 从环境变量读取 API key
```c
- char *auth_header = "Authorization: Bearer " OPENAI_TOKEN;
+ const char *api_key = getenv("KEY");
+ if (!api_key) {
+     fprintf(stderr, "KEY environment variable not set\n");
+     return NULL;
+ }
+ char auth_header[256];
+ snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", api_key);
```

**修改 2** (第 369-383 行): 修复 construct_prompt_for_requests_to_states
```c
+ char *content = NULL;
+ asprintf(&content, ...);
+ asprintf(&prompt, "[{\"role\": \"system\", \"content\": \"You are a helpful assistant.\"}, {\"role\": \"user\", \"content\": \"%s\"}]", content);
+ free(content);
```

**修改 3** (第 962-978 行): 修复 enrich_sequence
```c
+ char *content = NULL;
+ asprintf(&content, prompt_template, ...);
+ asprintf(&prompt, "[{\"role\": \"system\", \"content\": \"You are a helpful assistant.\"}, {\"role\": \"user\", \"content\": \"%s\"}]", content);
+ free(content);
```

## 验证方法

### 重新编译
```bash
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/ChatAFL
make clean && make
```

### 测试命令
```bash
export KEY="sk-Ange3qwa3xwQnG9IqH8srU6tMZeXqIiDJxGjVpqPM7ahJgSS"
cd /home/ckt/Documents/000_2026_test_dev/research_laboratory/ChatAFL-master/ChatAFL
AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 timeout 10s ./afl-fuzz -i /tmp/afl_in_test -o /tmp/afl_out_test -N tcp://127.0.0.1/21 -P FTP -- /bin/true
```

### 预期结果
1. ✅ "Getting grammars from LLM..." 阶段成功（输出 Header pattern 信息）
2. ✅ "Enriching test cases from LLM..." 阶段不再报错 "invalid character 'T'"

## 总结

两个主要问题已修复：
1. **认证问题**: API key 现在从环境变量 `KEY` 读取，而不是使用硬编码的无效 token
2. **JSON 格式问题**: 所有 prompt 构造函数现在都返回正确的 JSON 消息格式

这些修改确保 ChatAFL 的 LLM 集成功能能够像 testLLM1.c 一样正常工作。
