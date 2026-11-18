Pure-FTPd 原始3归档：server-exit-251/252 分别3、2、3输入，reset均成功，13份gcda均导入，但final_reply=null；正文已观察251对应421 Line too long。直接原因之一已确定：run脚本没有选择LoopFuzz重放器，PATH仍用镜像旧/home/ubuntu/aflnet/aflnet-replay（sha ed90d941，无ledger且FTP旧多行提取）。已编译的/home/ubuntu/loopfuzz/aflnet-replay sha012bd3eb并未被调用。不能只加PATH：LoopFuzz argv4是local_port，需要显式0后再传poll与socket timeout，coverage_v4当前按旧接口传1。
Live555 run3：前13个同SHA的OPTIONS单帧种子client-exit-1；无frame banner，耗时约1.13秒，server ready=true，符合客户端连接重试耗尽。还需固定语料隔离重放确认根因；不能宣称已修。
尚未改coverage_v4主文件，尚无诊断容器启动；下一步仅用失败语料跑run_one_replay，之后全归档固定语料回放。原始归档只读。
诊断已启动（无 fuzz）：partial-diag-pure-ftpd-20261116 与 partial-diag-live555-20261116，分别重放原8个异常输入及OPTIONS同SHA输入3次，对比旧PATH二进制与新编译显式LoopFuzz argv local_port=0/poll100/socket10000。输出 partial_replay_diagnosis_20261116/<target>/out/。coverage_v4主文件未改。
