#!/bin/bash
set -e
# ============================================================
# NBG-driver 编译脚本
#
# 用法:
#   ./build.sh                       # 默认 android15-6.6, 自动选择原生/DDK, 关闭日志
#   ./build.sh android14-6.1         # 指定版本
#   ./build.sh --debug               # 启用日志(NBG_DEBUG=1)
#   ./build.sh --debug android14-6.1
#   ./build.sh --ddk android15-6.6   # 强制使用 DDK (需 Docker)
#   ./build.sh --native android15-6.6 # 强制使用本机 /opt/ddk/kdir
# ============================================================

GREEN='\033[0;32m'; NC='\033[0m'
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FORCE_DDK=false
FORCE_NATIVE=false
NBG_DEBUG=0

cleanup_build_artifacts() {
    make --no-print-directory clean-artifacts 2>/dev/null || true
}

validate_module_versions() {
    local ko="$1"
    local size_hex
    local size_dec

    [ -f "$ko" ] || {
        echo "产物缺失: $ko"
        return 2
    }

    size_hex="$(readelf -SW "$ko" 2>/dev/null |
        awk '$2 == "__versions" { print $6; exit }')"
    [ -n "$size_hex" ] || {
        echo "产物校验失败: __versions section 缺失"
        return 2
    }
    size_dec=$((16#$size_hex))
    [ "$size_dec" -gt 0 ] || {
        echo "产物校验失败: __versions section 为空"
        return 2
    }

    strings -a "$ko" | grep -qx 'module_layout' || {
        echo "产物校验失败: module_layout CRC 缺失"
        return 2
    }
    echo "KO_CHECK __versions=0x${size_hex} module_layout=ok"
}

native_modpost_source() {
    local ddk_root
    local candidate

    ddk_root="$(cd "$(dirname "$KDIR")/.." 2>/dev/null && pwd)"
    candidate="${ddk_root}/src/${TARGET}/scripts/mod/modpost.c"
    if [ -f "$candidate" ]; then
        printf '%s\n' "$candidate"
        return 0
    fi

    candidate="${KDIR}/source/scripts/mod/modpost.c"
    if [ -f "$candidate" ]; then
        printf '%s\n' "$candidate"
        return 0
    fi

    if [ -f "${KDIR}/scripts/mod/.modpost.o.cmd" ]; then
        candidate="$(sed -n 's/^source_scripts\/mod\/modpost\.o := //p' \
            "${KDIR}/scripts/mod/.modpost.o.cmd" | head -n 1)"
        if [ -f "$candidate" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    fi
    return 1
}

NBG_NATIVE_MODPOST_TMP=""
NBG_NATIVE_MODPOST_BACKUP=""
NBG_NATIVE_MODPOST_INSTALLED=0

restore_native_modpost() {
    if [ "$NBG_NATIVE_MODPOST_INSTALLED" = "1" ] &&
        [ -n "$NBG_NATIVE_MODPOST_BACKUP" ] &&
        [ -f "$NBG_NATIVE_MODPOST_BACKUP" ]; then
        cp -f "$NBG_NATIVE_MODPOST_BACKUP" "${KDIR}/scripts/mod/modpost" 2>/dev/null || true
    fi
    if [ -n "$NBG_NATIVE_MODPOST_TMP" ] && [ -d "$NBG_NATIVE_MODPOST_TMP" ]; then
        rm -rf "$NBG_NATIVE_MODPOST_TMP"
    fi
}

prepare_native_modpost() {
    local modpost_c
    local modpost_dir
    local hostcc
    local hostcflags
    local unit

    modpost_c="$(native_modpost_source)" || {
        echo "native modpost 源文件未找到: ${KDIR}"
        return 2
    }
    modpost_dir="$(dirname "$modpost_c")"
    hostcc="${HOSTCC:-cc}"
    hostcflags="${HOSTCFLAGS:-}"
    NBG_NATIVE_MODPOST_TMP="${SCRIPT_DIR}/.native-modpost.$$"
    mkdir -p "$NBG_NATIVE_MODPOST_TMP"

    cp -f "$modpost_c" "$NBG_NATIVE_MODPOST_TMP/modpost.c"
    sed -i \
        -e 's#^[[:space:]]*//[[:space:]]*s->module = exp->module;#\t\ts->module = exp->module;#' \
        -e 's#^[[:space:]]*//[[:space:]]*check_exports(mod);#\t\tcheck_exports(mod);#' \
        "$NBG_NATIVE_MODPOST_TMP/modpost.c"
    grep -q '^[[:space:]]*s->module = exp->module;' \
        "$NBG_NATIVE_MODPOST_TMP/modpost.c" || {
        echo "native modpost 补丁校验失败: s->module"
        return 2
    }
    grep -q '^[[:space:]]*check_exports(mod);' \
        "$NBG_NATIVE_MODPOST_TMP/modpost.c" || {
        echo "native modpost 补丁校验失败: check_exports"
        return 2
    }

    # modpost.c is the patched copy; the other units use the kernel sources.
    "$hostcc" $hostcflags -Wall -Wmissing-prototypes -Wstrict-prototypes \
        -O2 -fomit-frame-pointer -std=gnu11 \
        -I"${KDIR}/scripts/mod" -I"${modpost_dir}" \
        -c "$NBG_NATIVE_MODPOST_TMP/modpost.c" \
        -o "$NBG_NATIVE_MODPOST_TMP/modpost.o"
    for unit in file2alias sumversion symsearch; do
        "$hostcc" $hostcflags -Wall -Wmissing-prototypes -Wstrict-prototypes \
            -O2 -fomit-frame-pointer -std=gnu11 \
            -I"${KDIR}/scripts/mod" -I"${modpost_dir}" \
            -c "${modpost_dir}/${unit}.c" \
            -o "$NBG_NATIVE_MODPOST_TMP/${unit}.o"
    done
    "$hostcc" $hostcflags -o "$NBG_NATIVE_MODPOST_TMP/modpost" \
        "$NBG_NATIVE_MODPOST_TMP/modpost.o" \
        "$NBG_NATIVE_MODPOST_TMP/file2alias.o" \
        "$NBG_NATIVE_MODPOST_TMP/sumversion.o" \
        "$NBG_NATIVE_MODPOST_TMP/symsearch.o"

    NBG_NATIVE_MODPOST_BACKUP="${NBG_NATIVE_MODPOST_TMP}/modpost.original"
    if [ -f "${KDIR}/scripts/mod/modpost" ]; then
        cp -f "${KDIR}/scripts/mod/modpost" "$NBG_NATIVE_MODPOST_BACKUP"
    fi
    cp -f "$NBG_NATIVE_MODPOST_TMP/modpost" "${KDIR}/scripts/mod/modpost"
    touch "${KDIR}/scripts/mod/modpost"
    NBG_NATIVE_MODPOST_INSTALLED=1
    trap restore_native_modpost EXIT
    echo "native modpost: 导出符号版本校验已启用"
}

prepare_native_symvers() {
    local source="${NBG_NATIVE_MODULE_SYMVERS:-${KDIR}/Module.symvers}"

    [ -s "$source" ] || {
        echo "内核 Module.symvers 不存在或为空: $source"
        return 2
    }
    grep -qE $'^[^[:space:]]+[[:space:]]+module_layout[[:space:]]' "$source" || {
        echo "内核 Module.symvers 缺少 module_layout: $source"
        return 2
    }
    cp -f "$source" "${SCRIPT_DIR}/Module.symvers"
    echo "native Module.symvers: $(grep -m1 -w module_layout "$source")"
}

prepare_abi_override_env() {
    local target="$1"
    local short_ver="${2:-}"
    local abi_dir
    local hint
    local rel

    unset NBG_MODULE_SYMVERS NBG_KERNEL_RELEASE

    case "$short_ver" in
        6.12) hint="android16-6.12-ab13938768" ;;
        6.12-a16-6) hint="android16-6.12-ab15213644" ;;
        *) hint="" ;;
    esac

    if [ -n "$hint" ] && [ -d "${SCRIPT_DIR}/builds/${hint}" ]; then
        abi_dir="${SCRIPT_DIR}/builds/${hint}"
    else
        abi_dir="$(find "${SCRIPT_DIR}/builds" -maxdepth 1 -type d -name "${target}-ab*" 2>/dev/null | sort | head -1)"
    fi
    if [ -n "$abi_dir" ] && [ -f "${abi_dir}/Module.symvers" ] && [ -f "${abi_dir}/gki-info.txt" ]; then
        rel="$(awk -F= '/^kernel_release=/{print $2; exit}' "${abi_dir}/gki-info.txt")"
        if [ -n "$rel" ]; then
            NBG_MODULE_SYMVERS="/build/builds/$(basename "$abi_dir")/Module.symvers"
            NBG_KERNEL_RELEASE="$rel"
            export NBG_MODULE_SYMVERS NBG_KERNEL_RELEASE
            echo "精确 ABI: $(basename "$abi_dir")"
            echo "kernel.release: $NBG_KERNEL_RELEASE"
            grep -w module_layout "${abi_dir}/Module.symvers" | head -1
        fi
    fi
}

# 解析开关位置随意,直到吃完所有 -- 前缀
while [ "${1:0:2}" = "--" ]; do
    case "$1" in
        --ddk)    FORCE_DDK=true ;;
        --native) FORCE_NATIVE=true ;;
        --debug)  NBG_DEBUG=1    ;;
        *) echo "未知开关: $1" ; exit 1 ;;
    esac
    shift
done

TARGET="${1:-android15-6.6}"
cd "$SCRIPT_DIR"

declare -A VER_MAP=(
    ["android12-5.10"]="5.10"
    ["android13-5.10"]="5.10-a13"
    ["android13-5.15"]="5.15"
    ["android14-5.15"]="5.15-a14"
    ["android14-6.1"]="6.1"
    ["android15-6.6"]="6.6"
    ["android16-6.12"]="6.12"
)
SHORT_VER="${VER_MAP[$TARGET]:-unknown}"
KDIR="/opt/ddk/kdir/${TARGET}"

if [ "$NBG_DEBUG" = "1" ]; then
    echo -e "[日志] ${GREEN}启用${NC} NBG_DEBUG=1 (运行期 nbg_log_set_level 控制级别)"
else
    echo "[日志] 关闭(NBG_xxx 宏全部编译为空)"
fi

if $FORCE_DDK && $FORCE_NATIVE; then
    echo "--ddk 和 --native 参数互斥"
    exit 1
fi

USE_DDK=false
if $FORCE_DDK; then
    USE_DDK=true
elif ! $FORCE_NATIVE && [ ! -f "$KDIR/Makefile" ] && command -v ddk &>/dev/null; then
    USE_DDK=true
fi

# ---------- DDK 模式 ----------
if $USE_DDK; then
    command -v ddk &>/dev/null || { echo "未找到 ddk 命令"; exit 1; }
    echo "[DDK 模式] ${TARGET}"
    ddk pull "$TARGET" 2>/dev/null || true
    make clean 2>/dev/null || true
    prepare_abi_override_env "$TARGET" "$SHORT_VER"
    NBG_DEBUG="$NBG_DEBUG" JOBS="$(nproc)" bash "${SCRIPT_DIR}/tools/ddk_build_module.sh" "$TARGET"
    KO_NAME="$(awk '/^MODULE_NAME[[:space:]]*:=/{print $3; exit}' Makefile)"
    [ -z "$KO_NAME" ] && KO_NAME="qti_rawnet"
    validate_module_versions "${SCRIPT_DIR}/${KO_NAME}.ko"
    mkdir -p "${SCRIPT_DIR}/output_ddk"
    cp "${SCRIPT_DIR}/${KO_NAME}.ko" "${SCRIPT_DIR}/output_ddk/${SHORT_VER}.ko"
    if [ -n "${NBG_EXPECTED_KERNEL_RELEASE:-}" ]; then
        actual="$(strings "${SCRIPT_DIR}/${KO_NAME}.ko" 2>/dev/null |
            sed -n 's/^vermagic=//p' | head -n 1 | awk '{print $1}')"
        [ "$actual" = "$NBG_EXPECTED_KERNEL_RELEASE" ] || {
            echo "ABI 校验失败: 产物=${actual:-unknown}, 目标=$NBG_EXPECTED_KERNEL_RELEASE"
            echo "保留编译结果但停止发布为目标内核模块"
            exit 2
        }
        echo "ABI 校验通过: $actual"
    fi
    ls -lh "${SCRIPT_DIR}/output_ddk/${SHORT_VER}.ko"
    cleanup_build_artifacts
    echo "已清理编译残留，保留 ko"
    exit 0
fi

# ---------- 原生模式(默认) ----------
echo "[原生模式] ${TARGET}"

if [ ! -f "$KDIR/Makefile" ]; then
    echo "内核环境不存在: $KDIR"
    echo "可直接使用: ./build.sh --ddk ${TARGET}"
    echo "或安装原生环境: bash setup_and_build.sh ${TARGET}"
    exit 1
fi

export KDIR ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu-

check_expected_kernel_release() {
    expected="${NBG_EXPECTED_KERNEL_RELEASE:-}"
    [ -n "$expected" ] || return 0
    actual="$(strings "${SCRIPT_DIR}/${KO_NAME}" 2>/dev/null |
        sed -n 's/^vermagic=//p' | head -n 1 | awk '{print $1}')"
    if [ "$actual" != "$expected" ]; then
        echo "ABI 校验失败: 产物=${actual:-unknown}, 目标=$expected"
        echo "保留编译结果但停止发布为目标内核模块"
        return 2
    fi
    echo "ABI 校验通过: $actual"
}

# secret.h 保存 socket ioctl 鉴权 token;驱动和 LS_test 必须同时使用同一份。
[ -f secret.h ] || { echo "缺少 secret.h"; exit 1; }

KO_NAME="$(awk '/^MODULE_NAME[[:space:]]*:=/{print $3; exit}' Makefile)"
[ -z "$KO_NAME" ] && KO_NAME="qti_rawnet"
make clean 2>/dev/null || true
prepare_native_symvers
prepare_native_modpost
make -j"$(nproc)" NBG_DEBUG="$NBG_DEBUG" 2>&1

validate_module_versions "${SCRIPT_DIR}/${KO_NAME}.ko"
mkdir -p output_ddk
cp "${SCRIPT_DIR}/${KO_NAME}.ko" "${SCRIPT_DIR}/output_ddk/${SHORT_VER}.ko"
check_expected_kernel_release
validate_module_versions "${SCRIPT_DIR}/output_ddk/${SHORT_VER}.ko"
echo ""
echo -e "${GREEN}编译完成:${NC} output_ddk/${SHORT_VER}.ko"
ls -lh "${SCRIPT_DIR}/output_ddk/${SHORT_VER}.ko"
cleanup_build_artifacts
echo "已清理编译残留，保留 ko"
