#!/bin/bash
set -e
# ============================================================
# NBG-driver 一键安装编译脚本
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
log_step()  { echo -e "${CYAN}[STEP]${NC}  $1"; }

TARGET="${1:-android15-6.6}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output_ddk"
mkdir -p "$OUTPUT_DIR"

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
KSRC="/opt/ddk/src/${TARGET}"

echo "NBG-driver 编译: ${TARGET} (内核 ${SHORT_VER})"

# ============================================================
# Step 1: 依赖
# ============================================================
log_step "检查编译工具..."
for pkg in clang lld pahole python3; do
    command -v $pkg &>/dev/null || { apt-get update -qq; apt-get install -y -qq clang lld llvm pahole; break; }
done
log_info "clang $(clang --version 2>&1 | head -1 | cut -d' ' -f4)"

# ============================================================
# Step 2: 获取内核源码 (仅首次)
# ============================================================
log_step "检查内核编译环境..."

MISSING=false
[ -d "$KDIR" ] && [ -f "$KDIR/Makefile" ] || MISSING=true
[ -d "$KSRC" ] && [ -f "$KSRC/Makefile" ] || MISSING=true

if $MISSING; then
    log_info "首次运行，拉取 DDK 镜像..."
    apt-get install -y -qq skopeo curl 2>&1 | tail -1

    IMG_DIR="/tmp/ddk_cache_${SHORT_VER}"
    ROOTFS="/tmp/ddk_root_${SHORT_VER}"
    mkdir -p "$IMG_DIR" "$ROOTFS"

    # skopeo 拉取
    if [ ! -f "$IMG_DIR/manifest.json" ]; then
        skopeo copy "docker://ghcr.io/ylarod/ddk:${TARGET}" "dir:${IMG_DIR}" 2>&1 | tail -3
    fi

    # 解压
    if [ ! -d "$ROOTFS/opt/ddk" ]; then
        log_info "解压镜像..."
        cd "$ROOTFS"
        python3 -c "
import json
for l in json.load(open('${IMG_DIR}/manifest.json'))['layers']:
    print(l['digest'].split(':')[1])
" | while read d; do tar -xzf "${IMG_DIR}/${d}" 2>/dev/null; done
        cd "$SCRIPT_DIR"
    fi

    # 建立链接
    [ -L /opt/ddk ] || ln -sf "${ROOTFS}/opt/ddk" /opt/ddk

    # 构建 host 工具
    log_info "构建 host 工具..."
    (cd "$KSRC" && make -C scripts/basic fixdep 2>/dev/null) || true
    cp -f "$KSRC/scripts/basic/fixdep" "$KDIR/scripts/basic/" 2>/dev/null || true

    if [ ! -f "$KDIR/scripts/mod/modpost" ]; then
        mkdir -p "$KDIR/scripts/mod"
        cd "$KSRC/scripts/mod"
        cc -I"$KDIR/scripts/mod" -O2 \
            -c modpost.c file2alias.c sumversion.c symsearch.c
        cc *.o -o modpost
        cp modpost "$KDIR/scripts/mod/"
        cd "$SCRIPT_DIR"
    fi

    # 禁用 BTF (DDK 镜像的 x86_64 工具链在 ARM64 原生环境无法运行)
    for c in "$KDIR/.config" "$KDIR/include/config/auto.conf"; do
        [ -f "$c" ] && sed -i \
            -e 's/CONFIG_DEBUG_INFO_BTF=y/CONFIG_DEBUG_INFO_BTF=n/g' \
            -e 's/CONFIG_DEBUG_INFO_BTF_MODULES=y/CONFIG_DEBUG_INFO_BTF_MODULES=n/g' "$c"
    done

    # stub resolve_btfids
    mkdir -p "$KDIR/tools/bpf/resolve_btfids"
    echo -e '#!/bin/bash\nexit 0' > "$KDIR/tools/bpf/resolve_btfids/resolve_btfids"
    chmod +x "$KDIR/tools/bpf/resolve_btfids/resolve_btfids"

    log_info "内核环境准备完成"
else
    log_info "内核环境已就绪，跳过拉取"
fi

# ============================================================
# Step 3: 编译
# ============================================================
log_step "编译 NBG 驱动..."

export KDIR KSRC ARCH=arm64 LLVM=1 LLVM_IAS=1 CROSS_COMPILE=aarch64-linux-gnu-

cd "$SCRIPT_DIR"
make clean 2>/dev/null || true
make -j"$(nproc)" 2>&1

# ============================================================
# Step 4: 保存
# ============================================================
echo ""
if [ -f "${SCRIPT_DIR}/NBG.ko" ]; then
    cp "${SCRIPT_DIR}/NBG.ko" "${OUTPUT_DIR}/${SHORT_VER}.ko"
    log_info "编译成功: ${OUTPUT_DIR}/${SHORT_VER}.ko"
    ls -lh "${OUTPUT_DIR}/${SHORT_VER}.ko"
else
    echo -e "${RED}编译失败: 未找到 NBG.ko${NC}"
    exit 1
fi
