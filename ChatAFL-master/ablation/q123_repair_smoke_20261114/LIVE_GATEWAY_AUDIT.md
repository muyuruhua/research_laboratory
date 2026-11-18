# Bftpd 原始 pvstop512 参数的真实网关审计

启动命令仍使用 `./run_ablation.sh bftpd 3 30 -g pvstop512`。网关地址应写为
`https://ai-apigateway.must.edu.mo/openhub/v1/chat/completions`，不包含反斜杠。
KEY 由用户在本地设置。

该入口在 fuzz 后自动执行 coverage 回放并归档。30 分钟是 fuzz 时限，回放、
统计、归档另需时间。等整条启动命令完成后，复制日志中
`[ABLATION:pvstop512] 启动 → ...` 打印的本次确切结果目录。

在项目根目录手动执行，替换下面的时间戳：

```bash
RESULT_DIR='ablation/results-bftpd_ablation_pvstop512_本次时间戳'
python3 ablation/q123_repair_smoke_20261114/audit_smoke.py \
  --gateway live --profile arm-default \
  --target bftpd --threshold 512 --arms pvstop512 \
  --timeout-min 30 "$RESULT_DIR"
```

这是对已归档回放的离线审计，正常完成的运行无需再次回放。审计命令不使用 KEY，
不请求网关。退出码 0 表示所列证据检查全部通过，1 表示存在失败，2 表示参数错误。
若启动或归档未完成，须先处理失败，不能用此命令补造缺失证据。

`--profile arm-default` 明确检查原始共享控制值：warmup=64、episode energy=512、
reward window=0；同时保留 pvstop 的 salvage、early-stop K=32 等已有臂语义检查。
该选项允许客户端记录无 LLM 调用上限的有效标记 `-1`；若配置了正上限，仍检查实际
出站次数。它继续要求每个重复有至少一次带原始响应、模型和用量证据的成功请求，
并保留配置、身份、执行/reset、回放逐帧及覆盖证据检查。截断回放不能通过该选项。

默认 `--profile smoke` 保持原有 8/32/16 控制值及真实网关正调用上限要求。
未改变 fuzz、回放或目标参数。此命令的验证范围仅为指定 Bftpd 单臂的三个重复；
没有对照臂时不能据此作效果比较。

实现验证：2026-11-17 离线 `test_audit_smoke` 80/80 通过，包含新增参数匹配、
无上限标记、正上限超额、配置不符、原始交换篡改/缺失等正反例。
本次未执行真实网关实验或请求。
