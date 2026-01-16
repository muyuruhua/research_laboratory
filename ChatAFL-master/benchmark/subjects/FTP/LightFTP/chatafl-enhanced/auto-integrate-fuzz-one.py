#!/usr/bin/env python3
"""
文件: auto-integrate-fuzz-one.py
描述: 自动在fuzz_one()中集成验证器/CEGAR/状态追踪功能
"""

import re
import sys

def read_file(filepath):
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def write_file(filepath, content):
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)

def integrate_modules(source_code):
    """在关键位置插入集成代码"""
    
    # === 步骤1: 在fuzz_one开头添加验证器声明 ===
    pattern1 = r'(static u8 fuzz_one\(char \*\*argv\)\s*\{[\s\S]*?)(  s32 len, fd, temp_len)'
    
    verifier_decl = '''  /* ChatAFL-Enhanced: 验证器变量 */
  int verifier_enabled = 1;
  int state_tracking_enabled = 1;
  
'''
    
    if re.search(pattern1, source_code):
        source_code = re.sub(pattern1, r'\1' + verifier_decl + r'\2', source_code, count=1)
        print("[+] 步骤1: 添加验证器变量声明")
    else:
        print("[!] 警告: 未找到fuzz_one函数开头位置")
        return None
    
    # === 步骤2: 在所有common_fuzz_stuff调用前添加验证 ===
    # 查找模式: if (common_fuzz_stuff(argv, out_buf, len)) goto abandon_entry;
    pattern2 = r'(    if \(common_fuzz_stuff\(argv, out_buf, len\)\) goto abandon_entry;)'
    
    verifier_check = r'''    /* ChatAFL-Enhanced: 验证测试用例 */
    if (verifier_enabled && len > 0 && len < MAX_FILE) {
      if (!verify_json_grammar((char*)out_buf, &g_protocol_spec)) {
        g_verifier_rejects++;
        if (!(stage_cur % 100) && stage_cur > 0) {
          ACTF("Verifier rejected (total: %d)", g_verifier_rejects);
        }
        goto abandon_entry;
      }
    }

\1'''
    
    count = len(re.findall(pattern2, source_code))
    source_code = re.sub(pattern2, verifier_check, source_code)
    print(f"[+] 步骤2: 在 {count} 处common_fuzz_stuff调用前添加验证")
    
    # === 步骤3: 在每个stage结束后添加状态追踪 ===
    # 查找abandon_entry标签后面的位置
    pattern3 = r'(abandon_entry:[\s\S]{0,200}?)(  splicing_with:;)'
    
    state_tracking = '''
  /* ChatAFL-Enhanced: 状态追踪和CEGAR */
  if (state_tracking_enabled && ret_val == 0) {
    // TODO: 从AFLNet获取响应状态
    // 这需要AFLNet的响应信息，当前为占位符
    if (g_current_state[0] != '\\0') {
      increment_state_count(g_current_state);
    }
  }

'''
    
    if re.search(pattern3, source_code):
        source_code = re.sub(pattern3, r'\1' + state_tracking + r'\2', source_code, count=1)
        print("[+] 步骤3: 在abandon_entry后添加状态追踪")
    else:
        print("[!] 警告: 未找到abandon_entry位置")
    
    return source_code

def main():
    filepath = 'afl-fuzz.c'
    backup_filepath = 'afl-fuzz.c.pre-integration'
    
    print("[+] ChatAFL-Enhanced 自动集成工具")
    print(f"[+] 目标文件: {filepath}")
    print("")
    
    # 读取源文件
    try:
        source_code = read_file(filepath)
        print(f"[+] 读取源文件成功 ({len(source_code)} 字节)")
    except Exception as e:
        print(f"[!] 错误: 无法读取文件 - {e}")
        return 1
    
    # 检查是否已集成
    if 'verifier_enabled' in source_code:
        print("[!] 警告: 文件似乎已经集成过，请检查")
        response = input("    继续? (y/N): ")
        if response.lower() != 'y':
            return 0
    
    # 备份
    try:
        write_file(backup_filepath, source_code)
        print(f"[+] 备份原文件到: {backup_filepath}")
    except Exception as e:
        print(f"[!] 错误: 无法创建备份 - {e}")
        return 1
    
    # 执行集成
    print("[+] 开始集成...")
    integrated_code = integrate_modules(source_code)
    
    if integrated_code is None:
        print("[!] 集成失败")
        return 1
    
    # 写回文件
    try:
        write_file(filepath, integrated_code)
        print(f"[+] 集成完成，已写入文件")
    except Exception as e:
        print(f"[!] 错误: 无法写入文件 - {e}")
        return 1
    
    print("")
    print("[+] 集成成功! 下一步:")
    print("    1. make clean && make")
    print("    2. 测试运行: ./afl-fuzz -i in -o out -- target @@")
    print("    3. 重新运行实验对比")
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
