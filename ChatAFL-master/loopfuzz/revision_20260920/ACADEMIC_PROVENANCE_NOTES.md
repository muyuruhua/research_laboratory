# 作者用技术溯源记录

本文件不参与论文排版。这里只保留本轮从论文叙述中移出的操作细节，不能视为新增实验结果。

| 案例 | 原始版本或证据标识 |
|---|---|
| ProFTPD / CVE-2023-51713 | vulnerable 61e621e743346; reported patch 97bbe68363cc; command parser make_ftp_cmd |
| LIVE555 / CVE-2026-38998 | diagnostic offset 0x614b86; missing fuzzer reproducer trigger_loopfuzz.raw |
| Kamailio / CVE-2026-39863 | vulnerable a2209018fb; reported upstream patch 060b6c2530c8; local guard INT_MAX/10 |
| SMARTPL | reported revision 2ca10d9b; version 27.2 |

上述身份与补丁效力的限制保持不变；附带日志观察不等价于本轮独立重执行。完整源文件清单与哈希仍由既有漏洞证据文件保存。

原事件名称 run_config、candidate_event、admission_trial、provisional_event、state_selection_episode、bug_event、repair_event 及所需字段，保留在 academic_language_edits.json 的原文中；论文表 5 改用对应的观察类别。

实际实验根目录：/home/ckt/Documents/000_2026_test_dev/Key_Experiment。原始结果不作改写。

数值复核命令：

    python3 verify_data_update_20260929.py --source-root /home/ckt/Documents/000_2026_test_dev/Key_Experiment
    python3 verify_vulnerability_evidence_20260929.py --source-root /home/ckt/Documents/000_2026_test_dev/Key_Experiment
    python3 verify_academic_language.py
