# bracket_py.gdb — Python 编排版：目标自己 free，主线程 hold，worker 踩读
set pagination off
set confirm off

python
import gdb, time, threading

class FreeStop(gdb.Breakpoint):
    def __init__(self):
        super().__init__("listener.c:78")
        self.silent = False
        self.victim = None
        self.done = False
    def stop(self):
        try:
            # listener.c:78 即 free(listener); 优化后取参：反汇编上一条 mov rdi
            # 更稳：asm 里 free 调用前必有 mov rdi,rbx/rdi 之类——用 gdb 当前
            # 行的函数参数已 optimized out，改从链表里找 pending removal 的节点：
            # 直接用入口断点记录的 listener 指针（AddStop 存下）。
            pass
        except Exception as e:
            print("POC err", e)
        return True

class RemoveStop(gdb.Breakpoint):
    def __init__(self):
        super().__init__("listener_remove")
        self.silent = True
        self.node = None
    def stop(self):
        fr = gdb.newest_frame()
        print("\n=== [POC-1] listener_remove from %s ===" % fr.older().name() if fr.older() else "=== [POC-1] ===")
        return True

# 断在 78 行时，用 selected thread 的 rdi 不可靠（非入口）。
# 更可靠：在 free 调用的实际目标处断 —— ASAN 构建下 free 调用 __interceptor_free。
# 直接断 malloc/free 的 interceptor 太宽。改用：FinishBreakpoint 不可用于无 debug 信息。
# 最实用：断 listener.c:78，读取反汇编中 free 的参数寄存器。
class FreeStop78(gdb.Breakpoint):
    def __init__(self):
        super().__init__("listener.c:78")
        self.fired = False
    def stop(self):
        if self.fired:
            return False
        self.fired = True
        vic = int(gdb.parse_and_eval("$rdi"))
        print("\n=== [POC-2] at free@78 victim=%#x; scheduling ===" % vic)
        state = {"phase": 0, "hold_until": 0.0}
        def work():
            try:
                if state["phase"] == 0:
                    gdb.execute("finish", to_string=True)
                    print("=== [POC-3] target free done ===")
                    try:
                        gdb.selected_inferior().read_memory(vic+16, 8)
                        print("=== [POC-3] probe read OK ===")
                    except gdb.MemoryError:
                        print("=== [POC-3] probe poisoned (expected) ===")
                    state["phase"] = 1
                    state["hold_until"] = time.time() + 10
                if state["phase"] == 1:
                    if time.time() < state["hold_until"]:
                        gdb.post_event(work)
                        return
                    print("=== [POC-3] hold done, releasing ===")
                    gdb.execute("continue")
                    return
            except Exception as e:
                print("POC-3 err:", e)
        gdb.post_event(work)
        return False

FreeStop78()
print("[SETUP] python breakpoints armed")
end

run
