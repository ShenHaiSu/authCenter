#!/usr/bin/env bash
# ============================================================================
# build.sh — AuthCenter 双平台 Bundle 构建脚本（后端架构文档 07 §4）
#
# 与 build.ps1 等价：在任一平台运行均产出两个平台的完整 Bundle（需求 C6）：
#   Bundle/windows/authcenter.exe + web/ + Caddyfile.example + README.txt
#   Bundle/linux/authcenter        + web/ + authcenter.service + Caddyfile.example + README.md
#   Bundle/SHA256SUMS.txt          （含全部产物 SHA256 校验和）
#
# 步骤（文档 07 §4）：
#   1. 版本号 = git describe --tags --always（无 tag 取 commit 短哈希）
#   2. go vet ./...（失败即中止）
#   3. 复制 FrontEnd/* → BackEnd/internal/web/（go:embed 构建期复制，07 §2.2）
#   4. CGO_ENABLED=0 交叉编译 windows/amd64 → Bundle/windows/authcenter.exe
#   5. CGO_ENABLED=0 交叉编译 linux/amd64   → Bundle/linux/authcenter
#   6. 前端静态文件副本 → 两个平台的 web/（C6 落点）
#   7. 部署辅助文件（deploy/*）→ 两个平台目录
#   8. 生成 Bundle/SHA256SUMS.txt
#
# 用法：
#   ./build.sh                 # 版本号取 git describe
#   ./build.sh 0.1.0           # 指定版本（注入二进制 version）
#   SKIP_VET=1 ./build.sh      # 跳过 go vet（调试用）
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND="$ROOT/BackEnd"
FRONTEND="$ROOT/FrontEnd"
WEBPKG="$BACKEND/internal/web"
BUNDLE="$ROOT/Bundle"
DEPLOY="$ROOT/deploy"

# ---------- 1. 版本号 ----------
VERSION="${1:-}"
if [[ -z "$VERSION" ]]; then
  VERSION="$(git -C "$ROOT" describe --tags --always 2>/dev/null || echo dev)"
fi
echo "==> [1/8] 版本: $VERSION"

# ---------- 2. 静态检查 ----------
if [[ "${SKIP_VET:-}" != "1" ]]; then
  echo "==> [2/8] go vet ./..."
  (cd "$BACKEND" && go vet ./...)
else
  echo "==> [2/8] 跳过 go vet（SKIP_VET=1）"
fi

# ---------- 3. 复制前端 → BackEnd/internal/web/（保留源码白名单） ----------
# 白名单：.gitkeep 占位 + embed.go/embed_test.go（go:embed 声明源码必须保留，
# 否则 web 包无法编译，见 07 §2.2 与 .gitignore 例外说明）。
echo "==> [3/8] 复制前端 FrontEnd/* -> BackEnd/internal/web/"
find "$WEBPKG" -mindepth 1 \
  ! -name '.gitkeep' ! -name 'embed.go' ! -name 'embed_test.go' \
  -exec rm -rf {} +
cp -r "$FRONTEND"/. "$WEBPKG"/

LDFLAGS="-s -w -X main.version=$VERSION"

# ---------- 4. 交叉编译 windows/amd64 ----------
echo "==> [4/8] 交叉编译 windows/amd64"
(cd "$BACKEND" && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -trimpath -ldflags "$LDFLAGS" \
  -o "$BUNDLE/windows/authcenter.exe" ./cmd/authcenter)

# ---------- 5. 交叉编译 linux/amd64 ----------
echo "==> [5/8] 交叉编译 linux/amd64"
(cd "$BACKEND" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags "$LDFLAGS" \
  -o "$BUNDLE/linux/authcenter" ./cmd/authcenter)

# ---------- 6. 前端静态文件副本 → 两个平台 web/（C6 落点） ----------
for os in windows linux; do
  echo "==> [6/8] 前端副本 -> Bundle/$os/web/"
  rm -rf "$BUNDLE/$os/web"
  mkdir -p "$BUNDLE/$os/web"
  cp -r "$FRONTEND"/. "$BUNDLE/$os/web"/
done

# ---------- 7. 部署辅助文件 ----------
cp "$DEPLOY/Caddyfile.example"  "$BUNDLE/windows/Caddyfile.example"
cp "$DEPLOY/Caddyfile.example"  "$BUNDLE/linux/Caddyfile.example"
cp "$DEPLOY/authcenter.service" "$BUNDLE/linux/authcenter.service"
cp "$DEPLOY/README.windows.txt" "$BUNDLE/windows/README.txt"
cp "$DEPLOY/README.linux.md"    "$BUNDLE/linux/README.md"
echo "==> [7/8] 部署辅助文件已复制"

# ---------- 8. SHA256 校验和 ----------
echo "==> [8/8] 生成 Bundle/SHA256SUMS.txt"
(cd "$BUNDLE" && find . -type f ! -name 'SHA256SUMS.txt' -print0 | sort -z \
  | xargs -0 sha256sum > SHA256SUMS.txt)

echo ""
echo "===== 构建完成 ====="
(cd "$BUNDLE" && find . -type f | sort)
echo "校验和: $BUNDLE/SHA256SUMS.txt"
