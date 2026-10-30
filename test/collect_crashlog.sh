#!/system/bin/sh
# NBG-driver 死机/重启后日志收集脚本
# 用法：adb shell su -c 'sh /data/local/tmp/collect_crashlog.sh'
# 可选：adb shell su -c 'NBG_SYSRQ=1 sh /data/local/tmp/collect_crashlog.sh'
#       触发 SysRq w/t/l，把阻塞任务/任务栈/CPU 回溯打进 dmesg。
# 注意：不清空 pstore，不删除日志，只读取和打包。

set +e

TS="$(date +%Y%m%d_%H%M%S 2>/dev/null)"
[ -n "$TS" ] || TS="unknown_time"
BASE="/data/local/tmp"
[ -d "$BASE" ] || BASE="/sdcard/Download"
[ -d "$BASE" ] || BASE="/tmp"
OUT="$BASE/NBG_crashlog_$TS"
mkdir -p "$OUT" 2>/dev/null || exit 1
LOG="$OUT/收集过程.log"
NBG_SYSRQ="${NBG_SYSRQ:-0}"

log() {
    echo "[$(date '+%F %T' 2>/dev/null)] $*" | tee -a "$LOG"
}

save_shell() {
    name="$1"
    cmd="$2"
    log "执行命令：$name"
    {
        echo "===== 命令：$cmd ====="
        sh -c "$cmd" 2>&1
        echo "===== 结束：$name ====="
    } > "$OUT/$name.txt" 2>&1
}

save_file() {
    src="$1"
    dst="$2"
    if [ -e "$src" ]; then
        log "读取文件：$src"
        cat "$src" > "$OUT/$dst" 2>&1
    else
        echo "不存在：$src" > "$OUT/$dst"
    fi
}

copy_dir_files() {
    srcdir="$1"
    dstdir="$2"
    mkdir -p "$OUT/$dstdir" 2>/dev/null
    if [ -d "$srcdir" ]; then
        log "复制目录文件：$srcdir"
        for f in "$srcdir"/*; do
            [ -e "$f" ] || continue
            base="$(basename "$f")"
            cat "$f" > "$OUT/$dstdir/$base" 2>&1
        done
    else
        echo "不存在：$srcdir" > "$OUT/$dstdir/目录不存在.txt"
    fi
}

log "开始收集 NBG 死机日志"
log "输出目录：$OUT"

save_shell "00_身份信息" 'id; whoami 2>/dev/null; date; uptime 2>/dev/null; cat /proc/uptime 2>/dev/null'
save_shell "01_系统信息" 'uname -a; cat /proc/version 2>/dev/null; cat /proc/cmdline 2>/dev/null'
save_shell "02_安卓属性" 'getprop 2>/dev/null'
save_shell "03_内核配置_关键项" 'zcat /proc/config.gz 2>/dev/null | grep -E "PSTORE|RAMOOPS|PANIC|LOCKUP|KMSG|DEBUG|KALLSYMS|KPROBES" || true'

save_shell "10_pstore列表" 'ls -la /sys/fs/pstore 2>&1'
copy_dir_files "/sys/fs/pstore" "10_pstore原始文件"
save_shell "11_pstore合并" 'for f in /sys/fs/pstore/*; do [ -e "$f" ] || continue; echo "===== $f ====="; cat "$f" 2>&1; echo; done'
save_file "/proc/last_kmsg" "12_proc_last_kmsg.txt"
save_shell "13_pstore_NBG关键日志" 'cat /sys/fs/pstore/* 2>/dev/null | grep -E "NBG_STAGE|NBG_ERROR|NBG\[|NBG|panic|Oops|BUG|Unable to handle|Call trace|PC is at|LR is at" || true'

save_shell "20_dmesg完整" 'dmesg 2>&1'
save_shell "21_dmesg_NBG关键日志" 'dmesg 2>/dev/null | grep -E "NBG_STAGE|NBG_ERROR|NBG\[|NBG|panic|Oops|BUG|Unable to handle|Call trace|PC is at|LR is at" || true'

# /dev/kmsg 是实时流，直接 cat 会一直阻塞。这里不能再用 cat /dev/kmsg | tail，
# 否则脚本会卡在 22。优先用 dmesg 快照；有 timeout 时最多读 3 秒。
save_shell "22_kmsg最近" 'if command -v timeout >/dev/null 2>&1; then timeout 3 sh -c "cat /dev/kmsg 2>/dev/null" | tail -n 2000; else dmesg 2>/dev/null | tail -n 2000; fi || true'
save_shell "23_dmesg_卡顿关键日志" 'dmesg 2>/dev/null | grep -Ei "NBG|panic|Oops|BUG|Unable to handle|Call trace|PC is at|LR is at|hung|blocked|watchdog|lockup|rcu|stall|freezer|deadlock|workqueue|kworker|sched|rate limit" || true'

save_shell "30_logcat_all" 'logcat -d -b all -v threadtime 2>&1'
save_shell "31_logcat_NBG关键日志" 'logcat -d -b all -v threadtime 2>/dev/null | grep -Ei "NBG|kernel panic|watchdog|tombstone|reboot|shutdown|crash|fatal" || true'

save_shell "40_模块信息" 'cat /proc/modules 2>/dev/null; echo; lsmod 2>/dev/null; echo; ls -la /sys/module/NBG 2>/dev/null || true'
save_shell "41_进程列表" 'ps -A 2>/dev/null || ps 2>/dev/null'
save_file "$BASE/LS_test.log" "LS_test.log"
save_shell "42_挂载与磁盘" 'mount 2>/dev/null; echo; df -h 2>/dev/null'
save_shell "43_内存信息" 'cat /proc/meminfo 2>/dev/null; echo; free 2>/dev/null'
save_shell "44_中断信息" 'cat /proc/interrupts 2>/dev/null | head -300'
save_shell "45_CPU调度状态" 'uptime 2>/dev/null; echo; cat /proc/loadavg 2>/dev/null; echo; cat /proc/stat 2>/dev/null | head -80; echo; cat /proc/schedstat 2>/dev/null | head -200'
save_shell "46_候选进程线程栈" 'for name in LS_test shmem_test kworker/u8:3 kworker/u16:1; do echo "===== pidof $name ====="; pidof "$name" 2>/dev/null; done; echo; pids="$(pidof LS_test 2>/dev/null) $(pidof shmem_test 2>/dev/null)"; for d in /proc/[0-9]*; do [ -d "$d" ] || continue; p="${d#/proc/}"; comm="$(cat "$d/comm" 2>/dev/null)"; kt="$(awk "/^Kthread:/ {print \$2}" "$d/status" 2>/dev/null)"; case "$comm:$kt" in LS_test:*|shmem_test:*|kworker/u8:3:0|kworker/u16:1:0) pids="$pids $p";; esac; done; seen=" "; for p in $pids; do case "$seen" in *" $p "*) continue;; esac; seen="$seen$p "; echo "===== PID $p ====="; cat /proc/$p/status 2>/dev/null; cat /proc/$p/wchan 2>/dev/null; echo; cat /proc/$p/sched 2>/dev/null | head -120; for t in /proc/$p/task/*; do [ -d "$t" ] || continue; echo "----- $t -----"; cat "$t/comm" 2>/dev/null; cat "$t/status" 2>/dev/null | head -40; echo "wchan=$(cat "$t/wchan" 2>/dev/null)"; cat "$t/stack" 2>/dev/null | head -80; done; done'
save_shell "50_panic_lockup配置" 'for f in /proc/sys/kernel/panic /proc/sys/kernel/panic_on_oops /proc/sys/kernel/panic_on_warn /proc/sys/kernel/hung_task_panic /proc/sys/kernel/softlockup_panic /proc/sys/kernel/hardlockup_panic /proc/sys/kernel/watchdog /proc/sys/kernel/nmi_watchdog; do echo "===== $f ====="; cat "$f" 2>/dev/null; done'
save_shell "60_重启原因节点" 'for f in /proc/sys/kernel/boot_reason /sys/kernel/boot_reason /sys/kernel/reboot_reason /sys/class/bootinfo/bootreason /proc/bootreason; do echo "===== $f ====="; cat "$f" 2>/dev/null; done'

if [ "$NBG_SYSRQ" = "1" ]; then
    save_shell "47_sysrq_任务栈快照" 'if [ -w /proc/sysrq-trigger ]; then echo w > /proc/sysrq-trigger; sleep 1; echo t > /proc/sysrq-trigger; sleep 1; echo l > /proc/sysrq-trigger; sleep 1; dmesg 2>/dev/null | tail -n 2500; else echo "/proc/sysrq-trigger 不可写"; fi'
else
    echo "未启用：设置 NBG_SYSRQ=1 可采集 SysRq 任务栈" > "$OUT/47_sysrq_任务栈快照.txt"
fi

SUMMARY="$OUT/00_快速查看_摘要.txt"
{
    echo "NBG 死机日志收集摘要"
    echo "时间：$(date 2>/dev/null)"
    echo "输出目录：$OUT"
    echo
    echo "===== 内核 ====="
    uname -a 2>/dev/null
    cat /proc/version 2>/dev/null
    echo
    echo "===== pstore 文件 ====="
    ls -la /sys/fs/pstore 2>/dev/null
    echo
    echo "===== pstore 关键行 ====="
    cat /sys/fs/pstore/* 2>/dev/null | grep -E "NBG_STAGE|NBG_ERROR|NBG\[|NBG|panic|Oops|BUG|Unable to handle|Call trace|PC is at|LR is at" | tail -300
    echo
	    echo "===== 当前 dmesg 关键行 ====="
	    dmesg 2>/dev/null | grep -E "NBG_STAGE|NBG_ERROR|NBG\[|NBG|panic|Oops|BUG|Unable to handle|Call trace|PC is at|LR is at" | tail -300
	    echo
	    echo "===== 当前卡顿关键行 ====="
	    dmesg 2>/dev/null | grep -Ei "NBG|panic|Oops|BUG|Unable to handle|Call trace|PC is at|LR is at|hung|blocked|watchdog|lockup|rcu|stall|freezer|deadlock|workqueue|kworker|sched|rate limit" | tail -300
	} > "$SUMMARY" 2>&1

ARCHIVE="$OUT.tar.gz"
if command -v tar >/dev/null 2>&1; then
    log "开始打包：$ARCHIVE"
    cd "$BASE" 2>/dev/null && tar -czf "$ARCHIVE" "$(basename "$OUT")" 2>>"$LOG"
    [ -f "$ARCHIVE" ] && log "打包完成：$ARCHIVE" || log "打包失败，但目录已保留：$OUT"
else
    log "未找到 tar，跳过打包，目录已保留：$OUT"
fi

log "收集完成"
echo
echo "=============================="
echo "NBG 死机日志收集完成"
echo "目录：$OUT"
[ -f "$ARCHIVE" ] && echo "压缩包：$ARCHIVE"
echo "优先查看：$SUMMARY"
echo "=============================="
