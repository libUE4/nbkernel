#!/bin/bash

# 添加 DDK 到 PATH
export PATH="$HOME/.local/bin:$PATH"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

# DDK 目标版本映射（根据你的需求）
# 常见的 Android 内核版本：
# android15-6.6, android14-6.1, android13-5.15, android12-5.10 等

declare -A DDK_TARGETS=(
    ["6.12-a16-6"]="android16-6.12"
    ["6.12"]="android16-6.12"
    ["6.6"]="android15-6.6"
    ["6.1"]="android14-6.1"
    ["5.15"]="android13-5.15"
    ["5.15-a14"]="android14-5.15"
    ["5.10"]="android12-5.10"
    ["5.10-a13"]="android13-5.10"
)

declare -A ABI_DIR_HINTS=(
    ["6.12"]="android16-6.12-ab13938768"
    ["6.12-a16-6"]="android16-6.12-ab15213644"
)

# 输出目录
OUTPUT_DIR="./output_ddk"
mkdir -p "$OUTPUT_DIR"

cleanup_build_artifacts() {
    make --no-print-directory clean-artifacts 2>/dev/null || true
}

prepare_abi_override_env() {
    local target="$1"
    local version="${2:-}"
    local abi_dir
    local hint

    unset NBG_MODULE_SYMVERS NBG_KERNEL_RELEASE

    hint="${ABI_DIR_HINTS[$version]:-}"
    if [ -n "$hint" ] && [ -d "${SCRIPT_DIR}/builds/${hint}" ]; then
        abi_dir="${SCRIPT_DIR}/builds/${hint}"
    else
        abi_dir="$(find "${SCRIPT_DIR}/builds" -maxdepth 1 -type d -name "${target}-ab*" 2>/dev/null | sort | head -1)"
    fi
    [ -n "$abi_dir" ] && prepare_abi_override_env_dir "$abi_dir"
}

prepare_abi_override_env_dir() {
    local abi_dir="$1"
    local rel

    unset NBG_MODULE_SYMVERS NBG_KERNEL_RELEASE

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

echo "=========================================="
echo "使用 DDK 编译内核驱动模块"
echo "=========================================="
echo ""

# 显示可用目标
echo "可用的编译目标："
for version in "${!DDK_TARGETS[@]}"; do
    echo "  - $version (${DDK_TARGETS[$version]})"
done
echo ""

# 参数格式：
#   ./build_with_ddk.sh                 # 编译默认全部版本
#   ./build_with_ddk.sh 6.6 6.12        # 只编译指定版本
#   ./build_with_ddk.sh 6.6 -- W=1      # 指定版本并透传 make 参数
#   ./build_with_ddk.sh -- W=1          # 默认全部版本并透传 make 参数
MAKE_ARGS=()
VERSIONS=()
while [ $# -gt 0 ]; do
    case "$1" in
        --)
            shift
            MAKE_ARGS=("$@")
            break
            ;;
        *)
            VERSIONS+=("$1")
            shift
            ;;
    esac
done

if [ ${#VERSIONS[@]} -eq 0 ]; then
    # 默认编译所有版本
    VERSIONS=("6.12" "6.12-a16-6" "6.6" "6.1" "5.15" "5.15-a14" "5.10" "5.10-a13")
fi

if [ ${#MAKE_ARGS[@]} -gt 0 ]; then
    echo "透传 make 参数: ${MAKE_ARGS[*]}"
    echo ""
fi

SUCCESS_COUNT=0
FAIL_COUNT=0

for version in "${VERSIONS[@]}"; do
    target="${DDK_TARGETS[$version]}"

    if [ -z "$target" ]; then
        echo "✗ 未知版本: $version"
        ((FAIL_COUNT++))
        continue
    fi

    echo "=========================================="
    echo "编译版本: $version (DDK target: $target)"
    echo "=========================================="

    # 拉取 DDK 镜像（如果还没有）
    echo "检查 DDK 镜像..."
    if ! ddk list | grep -q "$target"; then
        echo "拉取 DDK 镜像: $target"
        if ! ddk pull "$target"; then
            echo "✗ 拉取镜像失败: $target"
            ((FAIL_COUNT++))
            continue
        fi
    fi

    # 清理
    make clean

    prepare_abi_override_env "$target" "$version"

    # 使用 DDK 编译。公开输出始终保持每个版本一个 ko。
    echo "开始编译..."
    if NBG_DEBUG="${NBG_DEBUG:-0}" JOBS="$(nproc)" bash "${SCRIPT_DIR}/tools/ddk_build_module.sh" "$target" "${MAKE_ARGS[@]}"; then
        echo "✓ 编译成功: $version"
        if [ -f "NBG.ko" ]; then
            cp NBG.ko "$OUTPUT_DIR/${version}.ko"
            echo "✓ 已保存到: $OUTPUT_DIR/${version}.ko"
            cleanup_build_artifacts
            echo "✓ 已清理编译残留，保留 ko"
            ((SUCCESS_COUNT++))
        else
            echo "✗ 编译后缺少 ko"
            ((FAIL_COUNT++))
        fi
    else
        echo "✗ 编译失败: $version"
        ((FAIL_COUNT++))
    fi

    echo ""
done

echo "=========================================="
echo "编译完成统计:"
echo "成功: $SUCCESS_COUNT"
echo "失败: $FAIL_COUNT"
echo "输出目录: $OUTPUT_DIR"
echo "=========================================="

if [ -d "$OUTPUT_DIR" ] && [ "$(ls -A $OUTPUT_DIR)" ]; then
    ls -lh "$OUTPUT_DIR"
fi

if [ "$FAIL_COUNT" -ne 0 ]; then
    exit 1
fi
exit 0
