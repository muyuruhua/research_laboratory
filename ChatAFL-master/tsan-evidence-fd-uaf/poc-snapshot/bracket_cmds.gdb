# bracket_cmds.gdb — 由 stdin 补充 "run"/"continue" 的命令模板
set pagination off
set confirm off

break listener_remove
commands
  silent
  printf "\n=== [POC-1] listener_remove entered ===\n"
  bt 5
  break listener.c:78
commands
  silent
  printf "\n=== [POC-2] STOPPED at free@78 victim(reg rdi)=%p ===\n", $rdi
  printf "=== [POC-2] driver takes over now ===\n"
end

echo [SETUP] breakpoints armed\n
