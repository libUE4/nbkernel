#!/system/bin/sh
# Transaction copy: preserve existing kernel logs and the actual insmod status.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MODULE_PATH="$HERE/NBG.ko"
[ -f "$MODULE_PATH" ] || { echo "Error: Module file not found: $MODULE_PATH"; exit 1; }
sha256sum "$MODULE_PATH"
insmod "$MODULE_PATH"
rc=$?
if [ "$rc" -eq 0 ]; then
    echo "刷入成功"
    dmesg | tail -60 | grep -i -E 'NBG|qti_rawnet' || true
else
    echo "刷入失败: insmod exit=$rc"
    dmesg | tail -60
fi
exit "$rc"
