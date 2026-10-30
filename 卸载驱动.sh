#!/system/bin/sh

MODULE_NAMES="NBG qti_rawnet"
LOG_FILE="${NBG_UNLOAD_LOG:-/data/local/tmp/nbg_unload.log}"

SCRIPT_DIR="$(
    cd "$(dirname "$0")" 2>/dev/null && pwd
)"
[ -n "$SCRIPT_DIR" ] || SCRIPT_DIR="."

find_ls_test() {
    for candidate in \
        "$SCRIPT_DIR/LS_test" \
        "$SCRIPT_DIR/arm64-v8a/LS_test" \
        "$SCRIPT_DIR/libs/arm64-v8a/LS_test" \
        "$SCRIPT_DIR/test/libs/arm64-v8a/LS_test" \
        /data/local/tmp/LS_test \
        /data/local/tmp/arm64-v8a/LS_test; do
        if [ -x "$candidate" ]; then
            LS_TEST="$candidate"
            return 0
        fi
    done
    return 1
}

run_rmmod_fallback() {
    rc=1
    for module_name in $MODULE_NAMES; do
        if rmmod "$module_name" >>"$LOG_FILE" 2>&1; then
            echo "卸载成功: $module_name"
            return 0
        fi
    done
    return "$rc"
}

echo "===== NBG 卸载脚本 $(date '+%F %T') =====" >"$LOG_FILE" 2>/dev/null

if [ "$(id -u 2>/dev/null)" != "0" ]; then
    echo "请用 su/root 执行"
    exit 1
fi

if find_ls_test; then
    echo "使用 LS_test: $LS_TEST"
    echo "使用 LS_test: $LS_TEST" >>"$LOG_FILE" 2>&1
    "$LS_TEST" --unhide-module >>"$LOG_FILE" 2>&1
    ls_rc=$?
    cat "$LOG_FILE" 2>/dev/null

    if [ "$ls_rc" -eq 0 ]; then
        echo "卸载完成"
        exit 0
    fi

    if [ "$ls_rc" -eq 4 ]; then
        echo "仍有其它认证客户端占用，先退出 NBG 程序后再执行"
        exit 4
    fi

    echo "LS_test 卸载返回: $ls_rc，继续尝试 rmmod fallback"
else
    echo "未找到 LS_test，继续尝试 rmmod fallback"
    echo "未找到 LS_test" >>"$LOG_FILE" 2>&1
fi

if run_rmmod_fallback; then
    exit 0
fi

echo "卸载失败，日志: $LOG_FILE"
cat "$LOG_FILE" 2>/dev/null
dmesg | tail -80 2>/dev/null
exit 1
