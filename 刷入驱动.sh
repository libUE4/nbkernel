#!/system/bin/sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

MODULE_NAME="${MODULE_NAME:-NBG}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd)"
[ -n "$SCRIPT_DIR" ] || SCRIPT_DIR="."
SCRIPT_ARGS="$*"
LOG_FILE="${LOG_FILE:-$SCRIPT_DIR/${MODULE_NAME}_load_error.log}"
LOG_STARTED=0
ERROR_LOG_WRITTEN=0
DMESG_BEFORE_FILE="/data/local/tmp/${MODULE_NAME}_dmesg_before.log"
DMESG_LINES="${DMESG_LINES:-500}"

say() { printf "%b\n" "$*"; }

now_string() {
    date '+%Y-%m-%d %H:%M:%S %z' 2>/dev/null || date 2>/dev/null || echo unknown
}

print_env_plain() {
    echo "kernel : $(uname -r)"
    echo "android: $(getprop ro.build.version.release 2>/dev/null) sdk=$(android_api)"
    echo "arch   : $(uname -m)"
    echo "module : $MODULE_NAME"
}

ensure_log_file() {
    [ "$LOG_STARTED" = "1" ] && return 0

    : >"$LOG_FILE" 2>/dev/null || LOG_FILE="/data/local/tmp/${MODULE_NAME}_load_error.log"
    : >"$LOG_FILE" 2>/dev/null || LOG_FILE="/sdcard/${MODULE_NAME}_load_error.log"
    : >"$LOG_FILE" 2>/dev/null || {
        LOG_FILE=""
        return 1
    }

    LOG_STARTED=1
    ERROR_LOG_WRITTEN=1
    {
        echo "NBG driver error log"
        echo "created: $(now_string)"
        echo "script : $0"
        echo "args   : $SCRIPT_ARGS"
        echo
        echo "===== device ====="
        print_env_plain
    } >>"$LOG_FILE" 2>&1
    return 0
}

show_log_notice() {
    [ "$ERROR_LOG_WRITTEN" = "1" ] || return 0
    [ -n "$LOG_FILE" ] || return 0
    say "${YELLOW}日志已保存本地目录: \"$(basename "$LOG_FILE")\"${NC}"
    say "${YELLOW}请把这个日志发送给作者。${NC}"
}

need_root() {
    if [ "$(id -u)" != "0" ]; then
        say "${RED}错误: 请用 root 执行，例如 su -c sh $0${NC}"
        exit 1
    fi
}

find_control_helper() {
    for candidate in \
            "${NBG_UNHIDE_HELPER:-}" \
            /data/local/tmp/NBG-debug.sh \
            /data/local/tmp/NBG-release.sh \
            /data/local/tmp/NBG.sh \
            /data/lost+found/local_c4d \
            "$SCRIPT_DIR/NBG-debug.sh" \
            "$SCRIPT_DIR/NBG-release.sh" \
            "$SCRIPT_DIR/NBG.sh"; do
        [ -n "$candidate" ] || continue
        if [ -x "$candidate" ]; then
            printf "%s\n" "$candidate"
            return 0
        fi
    done
    return 1
}

prepare_hidden_module_unload() {
    helper="$(find_control_helper)" || return 127
    "$helper" --prepare-driver-unload
}

stop_overlay_process() {
    lock_file="/data/local/tmp/.rmcn_overlay.lock"
    helper="$(find_control_helper 2>/dev/null)" || helper=""
    if [ -n "$helper" ] && "$helper" --stop-hidden >/dev/null 2>&1; then
        sleep 5
        "$helper" --stop-hidden-force >/dev/null 2>&1 || true
        rm -f "$lock_file"
        return 0
    fi

    # Compatibility path for a previously deployed binary/driver pair.
    [ -f "$lock_file" ] || return 0
    overlay_pid="$(tr -cd '0-9' < "$lock_file")"
    if [ -n "$overlay_pid" ] && [ "$overlay_pid" -gt 1 ] 2>/dev/null; then
        kill -TERM "$overlay_pid" 2>/dev/null
        i=0
        while kill -0 "$overlay_pid" 2>/dev/null && [ "$i" -lt 30 ]; do
            sleep 0.1
            i=$((i + 1))
        done
        kill -KILL "$overlay_pid" 2>/dev/null
    fi
    rm -f "$lock_file"
}

ko_list() {
    {
        find "$SCRIPT_DIR" -maxdepth 1 -type f -name '*.ko'
        find "$SCRIPT_DIR/output_ddk" -maxdepth 1 -type f -name '*.ko'
    } 2>/dev/null | sort -u
}

android_api() {
    getprop ro.build.version.sdk 2>/dev/null
}

android_major() {
    api="$(android_api)"
    case "$api" in
        36) echo 16 ;;
        35) echo 15 ;;
        34) echo 14 ;;
        33) echo 13 ;;
        31|32) echo 12 ;;
        *) getprop ro.build.version.release 2>/dev/null | sed 's/\..*$//' ;;
    esac
}

kernel_short() {
    uname -r | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p'
}

kernel_release() {
    uname -r
}

kernel_android_major() {
    # A userspace OTA does not necessarily change the kernel's KMI branch.
    kernel_release | sed -n 's/.*-android\([0-9][0-9]*\)-.*/\1/p'
}

ko_vermagic() {
    f="$1"
    value=""
    if command -v modinfo >/dev/null 2>&1; then
        value="$(modinfo "$f" 2>/dev/null | sed -n 's/^vermagic:[[:space:]]*//p' | head -n 1)"
    fi
    if [ -z "$value" ] && command -v strings >/dev/null 2>&1; then
        value="$(strings "$f" 2>/dev/null | sed -n 's/^vermagic=//p' | head -n 1)"
    fi
    printf "%s\n" "$value"
}

ko_release() {
    ko_vermagic "$1" | awk '{print $1}'
}

candidate_abi_matches() {
    f="$1"
    [ "${NBG_ALLOW_UNMATCHED:-0}" = "1" ] && return 0
    [ "$(ko_release "$f")" = "$(kernel_release)" ]
}

emit_candidate() {
    f="$1"
    [ -n "$f" ] || return 0
    path="$SCRIPT_DIR/$f"
    [ -f "$path" ] || return 0
    candidate_abi_matches "$path" && echo "$path"
}

emit_candidate_path() {
    f="$1"
    [ -n "$f" ] || return 0
    case "$f" in
        /*) [ -f "$f" ] && candidate_abi_matches "$f" && echo "$f" ;;
        *) emit_candidate "$f" ;;
    esac
}

sanitize_ko_name() {
    printf "%s" "$1" | tr -c 'A-Za-z0-9._+-' '_'
}

kernel_ab_id() {
    kernel_release | sed -n 's/.*-\(ab[0-9][0-9]*\)\(-.*\)\{0,1\}$/\1/p'
}

candidate_order() {
    r="$(kernel_release)"
    k="$(kernel_short)"
    a="$(kernel_android_major)"
    [ -n "$a" ] || a="$(android_major)"
    ab="$(kernel_ab_id)"

    # A package-specific wrapper can pin one verified artifact.  Keeping the
    # pin in the common matcher preserves the same diagnostics, permissions,
    # and error-log path as ordinary automatic loading.
    if [ -n "${NBG_FORCE_KO:-}" ]; then
        emit_candidate_path "$NBG_FORCE_KO"
        return 0
    fi

    case "$k:$a:$r" in
        6.12:*:*android16-6*) preferred="6.12-a16-6.ko" ;;
        5.10:13:*) preferred="5.10-a13.ko" ;;
        5.15:14:*) preferred="5.15-a14.ko" ;;
        *) preferred="$k.ko" ;;
    esac

    {
        # 1) 精确小分支 ABI：如 ab15936633.ko，优先解决 vermagic/module_layout 差异。
        emit_candidate "$ab.ko"
        # 2) 完整 uname 文件名：用于手动补丁包或特殊分支。
        emit_candidate "$(sanitize_ko_name "$r").ko"
        # 3) Android 大版本 ABI 分组：如 6.12-a16-6.ko。
        emit_candidate "$preferred"
        # 4) 主内核线兜底：保留最初一个主线一个 ko 的简单逻辑。
        emit_candidate "$k.ko"
        # 5) 开发构建会把当前模块保留在 output_ddk；与脚本同级的
        # NBG.ko 则是单文件发布包。两者都必须参与自动匹配。
        emit_candidate "output_ddk/$ab.ko"
        emit_candidate "output_ddk/$(sanitize_ko_name "$r").ko"
        emit_candidate "output_ddk/$preferred"
        emit_candidate "output_ddk/$k.ko"
        emit_candidate "NBG.ko"
    } | awk '!seen[$0]++'
}

print_env() {
    say "${CYAN}设备信息:${NC}"
    print_env_plain | sed 's/^/  /'
}

show_ko_info() {
    f="$1"
    echo "  file   : $(basename "$f")"
    [ -r "$f" ] && ls -lh "$f" 2>/dev/null | awk '{print "  size   : "$5}'
    vermagic="$(ko_vermagic "$f")"
    [ -n "$vermagic" ] && echo "  vermagic: $vermagic"
}

snapshot_dmesg() {
    if command -v dmesg >/dev/null 2>&1; then
        dmesg 2>/dev/null | tail -n "$DMESG_LINES"
    fi
}

save_dmesg_before() {
    if command -v dmesg >/dev/null 2>&1; then
        dmesg 2>/dev/null | tail -n "$DMESG_LINES" >"$DMESG_BEFORE_FILE" 2>/dev/null || true
    fi
}

print_dmesg_before() {
    if [ -r "$DMESG_BEFORE_FILE" ]; then
        cat "$DMESG_BEFORE_FILE" 2>/dev/null
    else
        echo "(unavailable)"
    fi
}

diagnose_failure() {
    f="$1"
    err="$2"

    if ensure_log_file; then
        {
            echo
            echo "===== insmod failed: $(basename "$f") ====="
            echo "time   : $(now_string)"
            echo "path   : $f"
            show_ko_info "$f"
            echo
            echo "insmod stderr:"
            if [ -n "$err" ]; then
                printf "%s\n" "$err"
            else
                echo "(empty)"
            fi
            echo
            echo "lsmod:"
            lsmod 2>&1
            echo
            echo "SELinux:"
            getenforce 2>&1
            echo
            echo "all ko in script dir:"
            ko_list 2>&1
            echo
            echo "dmesg before insmod tail ${DMESG_LINES} lines:"
            print_dmesg_before
            echo
            echo "dmesg after insmod tail ${DMESG_LINES} lines:"
            snapshot_dmesg
            echo
            echo "dmesg after insmod filtered:"
            snapshot_dmesg | grep -Ei 'NBG|module|vermagic|version magic|invalid|unknown symbol|disagrees|taint|exec format|permission|denied|Required key|signature|insmod|kallsyms|kprobe|BTF|BPF'
        } >>"$LOG_FILE" 2>&1
    fi

    return 0
}

log_no_candidate() {
    if ensure_log_file; then
        {
            echo
            echo "===== no candidate ====="
            echo "time        : $(now_string)"
            echo "kernel      : $(kernel_release)"
            echo "kernel_short: $(kernel_short)"
            echo "script_dir  : $SCRIPT_DIR"
            echo "allow_unmatched: ${NBG_ALLOW_UNMATCHED:-0}"
            echo
            echo "all ko in script dir:"
            ko_list 2>&1
            echo
            echo "ko vermagic inventory:"
            while IFS= read -r item; do
                [ -n "$item" ] || continue
                printf "%s : %s\n" "$item" "$(ko_vermagic "$item")"
            done <<EOF
$(ko_list)
EOF
        } >>"$LOG_FILE" 2>&1
    fi
}

log_rmmod_failure() {
    err="$1"
    if ensure_log_file; then
        {
            echo
            echo "===== rmmod failed ====="
            echo "time  : $(now_string)"
            echo "module: $MODULE_NAME"
            echo
            echo "rmmod stderr:"
            if [ -n "$err" ]; then
                printf "%s\n" "$err"
            else
                echo "(empty)"
            fi
            echo
            echo "lsmod:"
            lsmod 2>&1
            echo
            echo "dmesg tail ${DMESG_LINES} lines:"
            snapshot_dmesg
        } >>"$LOG_FILE" 2>&1
    fi
}

is_loaded() {
    lsmod 2>/dev/null | awk '{print $1}' | grep -qx "$MODULE_NAME"
}

try_insmod() {
    f="$1"
    if ! candidate_abi_matches "$f"; then
        say "${RED}跳过 ABI 不匹配的模块: $(basename "$f")${NC}"
        say "${YELLOW}模块: $(ko_vermagic "$f")；内核: $(kernel_release)${NC}"
        if ensure_log_file; then
            {
                echo
                echo "===== ABI mismatch: $(basename "$f") ====="
                echo "module vermagic: $(ko_vermagic "$f")"
                echo "kernel release : $(kernel_release)"
                echo "action         : load skipped"
            } >>"$LOG_FILE" 2>&1
        fi
        return 1
    fi
    err_file="/data/local/tmp/${MODULE_NAME}_insmod.err"
    rm -f "$err_file"

    say "${YELLOW}尝试加载: $(basename "$f")${NC}"
    show_ko_info "$f"
    save_dmesg_before

    if insmod "$f" 2>"$err_file"; then
        say "${GREEN}加载成功: $(basename "$f")${NC}"
        return 0
    fi

    if is_loaded; then
        say "${GREEN}$MODULE_NAME 已经加载，按成功处理。${NC}"
        return 0
    fi

    diagnose_failure "$f" "$(cat "$err_file" 2>/dev/null)"
    return 1
}

auto_install() {
    found=0
    tried=""

    if is_loaded; then
        say "${YELLOW}$MODULE_NAME 已在 lsmod 中显示为已加载。${NC}"
        return 0
    fi

    while IFS= read -r f; do
        [ -n "$f" ] || continue
        found=1
        tried="$tried
$f"
        try_insmod "$f" && return 0
    done <<EOF
$(candidate_order)
EOF

    if [ "$found" = "0" ]; then
        log_no_candidate
        say "${RED}未找到适配内核 $(kernel_short) 的 ko，目录: $SCRIPT_DIR${NC}"
        say "${YELLOW}当前目录 ko:${NC}"
        ko_list | sed 's|.*/|  - |'
        show_log_notice
        return 1
    fi


    say "${RED}刷入失败。${NC}"
    show_log_notice
    return 1
}

manual_install() {
    i=1
    files="$(ko_list)"
    [ -n "$files" ] || { say "${RED}当前目录没有 .ko 文件${NC}"; return 1; }

    say "${GREEN}可用驱动:${NC}"
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        echo "  ($i) $(basename "$f")"
        i=$((i + 1))
    done <<EOF
$files
EOF
    max=$((i - 1))

    printf "请输入序号 (1-$max，0退出): "
    read choice
    choice="$(printf "%s" "$choice" | tr -d '\r')"
    [ "$choice" = "0" ] && return 0
    case "$choice" in ''|*[!0-9]*) say "${RED}输入无效${NC}"; return 1 ;; esac
    [ "$choice" -ge 1 ] 2>/dev/null && [ "$choice" -le "$max" ] 2>/dev/null || {
        say "${RED}序号超出范围${NC}"
        return 1
    }

    i=1
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        if [ "$i" = "$choice" ]; then
            try_insmod "$f"
            rc=$?
            if [ "$rc" != "0" ]; then
                say "${RED}刷入失败。${NC}"
                show_log_notice
            fi
            return $rc
        fi
        i=$((i + 1))
    done <<EOF
$files
EOF
    return 1
}

uninstall_module() {
    say "${YELLOW}准备卸载隐藏模块${NC}"
    prepare_hidden_module_unload
    unhide_rc=$?
    stop_overlay_process

    tried=""
    for module_name in "$MODULE_NAME" qti_rawnet NBG; do
        case " $tried " in *" $module_name "*) continue ;; esac
        tried="$tried $module_name"
        say "${YELLOW}卸载模块: $module_name${NC}"
        if rmmod "$module_name" 2>/data/local/tmp/${MODULE_NAME}_rmmod.err; then
            say "${GREEN}卸载成功: $module_name${NC}"
            return 0
        fi
    done

    say "${RED}卸载失败${NC}"
    rmmod_err="$(cat /data/local/tmp/${MODULE_NAME}_rmmod.err 2>/dev/null)"
    [ -n "$rmmod_err" ] && printf "%s\n" "$rmmod_err" | sed 's/^/  rmmod: /'
    log_rmmod_failure "$rmmod_err"
    say "${YELLOW}解隐藏返回: $unhide_rc${NC}"
    snapshot_dmesg | grep -Ei 'NBG|module|rmmod|busy|in use|unload|refcount' | tail -n 40
    show_log_notice
    return 1
}

main_menu() {
    while true; do
        say ""
        say "${GREEN}请选择操作:${NC}"
        echo "  (1) 自动匹配并加载"
        echo "  (2) 手动选择加载"
        echo "  (3) 卸载 $MODULE_NAME"
        echo "  (4) 显示环境和候选"
        echo "  (0) 退出"
        printf "输入选项: "
        read op
        op="$(printf "%s" "$op" | tr -d '\r')"

        case "$op" in
            1) auto_install ;;
            2) manual_install ;;
            3) uninstall_module ;;
            4)
                print_env
                say "${CYAN}自动候选顺序:${NC}"
                candidate_order | sed 's|.*/|  - |'
                say "${CYAN}全部 ko:${NC}"
                ko_list | sed 's|.*/|  - |'
                ;;
            0) exit 0 ;;
            *) say "${RED}无效选项${NC}" ;;
        esac
    done
}

need_root
print_env

case "$1" in
    install|auto|"") auto_install ;;
    manual) manual_install ;;
    uninstall|remove|rm) uninstall_module ;;
    menu) main_menu ;;
    info) candidate_order | sed 's|.*/|  - |' ;;
    *) main_menu ;;
esac
