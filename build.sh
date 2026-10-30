#!/bin/bash
set -euo pipefail
# ============================================================
# NBG-driver 远程编译脚本
#
# 编译在 GitHub Actions 的 Android DDK 容器里完成，本机不再需要
# 内核源码树、交叉工具链或 Docker。
#
# 用法:
#   ./build.sh                        # 编译 .ddk-version 指定的目标
#   ./build.sh android14-6.1          # 指定目标
#   ./build.sh --debug                # 带 NBG_DEBUG 日志编译
#   ./build.sh --push android15-6.6   # 先 push 当前分支再编译
# ============================================================

REPO="libUE4/nbkernel"
WORKFLOW="build-kernel.yml"
BRANCH="main"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'

NBG_DEBUG=0
DO_PUSH=false
TARGET=""

declare -A SHORT_NAME=(
    [android12-5.10]=5.10
    [android13-5.10]=5.10-a13
    [android13-5.15]=5.15
    [android14-5.15]=5.15-a14
    [android14-6.1]=6.1
    [android15-6.6]=6.6
    [android16-6.12]=6.12
    [android17-6.18]=6.18
)

die() { echo -e "${RED}$*${NC}" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --debug) NBG_DEBUG=1 ;;
        --push)  DO_PUSH=true ;;
        -h|--help)
            sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        -*) die "未知参数: $1" ;;
        *)  TARGET="$1" ;;
    esac
    shift
done

if [ -z "$TARGET" ] && [ -f "$SCRIPT_DIR/.ddk-version" ]; then
    TARGET="$(tr -d '[:space:]' < "$SCRIPT_DIR/.ddk-version")"
fi
[ -n "$TARGET" ] || die "未指定目标，且 .ddk-version 不存在"
[ -n "${SHORT_NAME[$TARGET]:-}" ] || die "不支持的目标: $TARGET（可选: ${!SHORT_NAME[*]}）"

SHORT_VER="${SHORT_NAME[$TARGET]}"

# ---------- 凭据 ----------
# 优先 GITHUB_TOKEN，否则复用 git 凭据助手，避免在脚本里另存 token。
gh_token() {
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        printf '%s' "$GITHUB_TOKEN"
        return 0
    fi
    git credential fill <<< 'protocol=https
host=github.com
' 2>/dev/null | sed -n 's/^password=//p' | head -n 1
}

TOKEN="$(gh_token)"
[ -n "$TOKEN" ] || die "拿不到 GitHub 凭据：设置 GITHUB_TOKEN，或先配置 git credential helper"

api() {
    local method="$1" path="$2" body="${3:-}"
    if [ -n "$body" ]; then
        curl -sS -X "$method" "https://api.github.com${path}" \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "Accept: application/vnd.github+json" \
            -d "$body"
    else
        curl -sS -X "$method" "https://api.github.com${path}" \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "Accept: application/vnd.github+json"
    fi
}

command -v curl >/dev/null 2>&1 || die "缺少 curl"
command -v python3 >/dev/null 2>&1 || die "缺少 python3"

# ---------- 推送 ----------
cd "$SCRIPT_DIR"
if ! git rev-parse --git-dir >/dev/null 2>&1; then
    die "当前目录不是 git 仓库，无法触发远程编译"
fi

if $DO_PUSH; then
    echo "[push] ${BRANCH}"
    git push origin "HEAD:${BRANCH}"
fi

if [ -n "$(git status --porcelain -- . ':!.github')" ]; then
    echo -e "${RED}警告: 工作区有未提交改动，远程编译用的是已推送的代码${NC}"
    echo "      需要包含这些改动时加 --push，或先自行 commit"
fi

HEAD_SHA="$(git rev-parse HEAD)"
REMOTE_SHA="$(git ls-remote origin "refs/heads/${BRANCH}" | awk '{print $1}')"
if [ "$HEAD_SHA" != "$REMOTE_SHA" ]; then
    die "本地 HEAD (${HEAD_SHA:0:8}) 与 origin/${BRANCH} (${REMOTE_SHA:0:8}) 不一致，先 --push"
fi

# ---------- 触发 ----------
echo "[dispatch] ${TARGET} NBG_DEBUG=${NBG_DEBUG}"
DISPATCH_BODY="$(python3 -c "
import json, sys
print(json.dumps({'ref': sys.argv[1], 'inputs': {'kmi': sys.argv[2], 'debug': sys.argv[3] == '1'}}))
" "$BRANCH" "$TARGET" "$NBG_DEBUG")"

HTTP="$(curl -sS -o /dev/null -w '%{http_code}' -X POST \
    "https://api.github.com/repos/${REPO}/actions/workflows/${WORKFLOW}/dispatches" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -d "$DISPATCH_BODY")"
[ "$HTTP" = "204" ] || die "触发失败 HTTP ${HTTP}"

# ---------- 等 run 出现 ----------
RUN_ID=""
for _ in $(seq 1 30); do
    sleep 4
    RUN_ID="$(api GET "/repos/${REPO}/actions/runs?event=workflow_dispatch&branch=${BRANCH}&per_page=5" |
        python3 -c "
import json, sys
head = sys.argv[1]
for run in json.load(sys.stdin).get('workflow_runs', []):
    if run['head_sha'] == head:
        print(run['id'])
        break
" "$HEAD_SHA")"
    [ -n "$RUN_ID" ] && break
done
[ -n "$RUN_ID" ] || die "未找到对应的 workflow run"
echo "[run] ${RUN_ID}"

# ---------- 等结果 ----------
JOB_PATTERN="Build NBG.ko for ${TARGET}"
while :; do
    read -r JOB_STATE ARTIFACT_ID < <(api GET "/repos/${REPO}/actions/runs/${RUN_ID}/jobs?per_page=40" |
        python3 -c "
import json, sys
want = sys.argv[1]
for job in json.load(sys.stdin).get('jobs', []):
    if job['name'] == want:
        print(job['status'], job.get('conclusion') or '-')
        break
else:
    print('missing -')
" "$JOB_PATTERN")

    case "$JOB_STATE" in
        completed)
            if [ "$ARTIFACT_ID" != "success" ]; then
                die "远程编译失败: ${JOB_PATTERN} -> ${ARTIFACT_ID}
查看日志: https://github.com/${REPO}/actions/runs/${RUN_ID}"
            fi
            break ;;
        missing) die "run 里没有找到 job: ${JOB_PATTERN}" ;;
    esac
    printf '.'
    sleep 10
done
echo

# ---------- 下载产物 ----------
ARTIFACT_ID="$(api GET "/repos/${REPO}/actions/runs/${RUN_ID}/artifacts" |
    python3 -c "
import json, sys
want = sys.argv[1]
for art in json.load(sys.stdin).get('artifacts', []):
    if art['name'] == want and not art['expired']:
        print(art['id'])
        break
" "nbg-kernel-${TARGET}")"
[ -n "$ARTIFACT_ID" ] || die "未找到产物 nbg-kernel-${TARGET}（可能已过期）"

mkdir -p "$SCRIPT_DIR/output_ddk"
ZIP_PATH="$SCRIPT_DIR/output_ddk/NBG-${TARGET}.zip"
# 产物下载会 302 到对象存储，重定向后必须去掉 Authorization 头。
curl -sSL -o "$ZIP_PATH" \
    -H "Authorization: Bearer ${TOKEN}" \
    "https://api.github.com/repos/${REPO}/actions/artifacts/${ARTIFACT_ID}/zip"

python3 - "$ZIP_PATH" "$SCRIPT_DIR/output_ddk" <<'PY'
import sys
import zipfile

archive, out_dir = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(archive) as zf:
    for info in zf.infolist():
        zf.extract(info, out_dir)
        print("extract", info.filename)
PY
rm -f "$ZIP_PATH"

KO_PATH="$SCRIPT_DIR/output_ddk/${SHORT_VER}.ko"
cp "$SCRIPT_DIR/output_ddk/NBG-${TARGET}.ko" "$KO_PATH"

# ---------- 校验 ----------
grep -aq 'module_layout' "$KO_PATH" || die "产物缺 module_layout，设备端会拒绝加载"

if [ -n "${NBG_EXPECTED_KERNEL_RELEASE:-}" ]; then
    actual="$(grep -ao 'vermagic=[^ ]*' "$KO_PATH" | head -n 1 | sed 's/^vermagic=//')"
    [ "$actual" = "$NBG_EXPECTED_KERNEL_RELEASE" ] || die "ABI 校验失败: 产物=${actual:-unknown}, 目标=$NBG_EXPECTED_KERNEL_RELEASE"
    echo "ABI 校验通过: $actual"
fi

echo ""
echo -e "${GREEN}编译完成:${NC} output_ddk/${SHORT_VER}.ko"
ls -lh "$KO_PATH"
