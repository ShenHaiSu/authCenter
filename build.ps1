# ============================================================================
# build.ps1 — AuthCenter 双平台 Bundle 构建脚本（后端架构文档 07 §4）
#
# 与 build.sh 等价：在任一平台运行均产出两个平台的完整 Bundle（需求 C6）：
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
#   .\build.ps1                # 版本号取 git describe
#   .\build.ps1 -Version 0.1.0 # 指定版本（注入二进制 version）
#   .\build.ps1 -SkipVet       # 跳过 go vet（调试用）
# ============================================================================
[CmdletBinding()]
param(
    [string]$Version = "",
    [switch]$SkipVet
)
$ErrorActionPreference = "Stop"

$Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackEnd   = Join-Path $Root "BackEnd"
$FrontEnd  = Join-Path $Root "FrontEnd"
$WebPkg    = Join-Path $BackEnd "internal\web"
$Bundle    = Join-Path $Root "Bundle"
$Deploy    = Join-Path $Root "deploy"

# ---------- 1. 版本号 ----------
if (-not $Version) {
    $Version = & git -C $Root describe --tags --always 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $Version) { $Version = "dev" }
}
Write-Host "==> [1/8] 版本: $Version"

# ---------- 2. 静态检查 ----------
if (-not $SkipVet) {
    Write-Host "==> [2/8] go vet ./..."
    Push-Location $BackEnd
    try {
        go vet ./...
        if ($LASTEXITCODE -ne 0) { throw "go vet 失败（中止构建）" }
    } finally { Pop-Location }
} else {
    Write-Host "==> [2/8] 跳过 go vet（-SkipVet）"
}

# ---------- 3. 复制前端 → BackEnd/internal/web/（保留源码白名单） ----------
# 白名单：.gitkeep 占位 + embed.go/embed_test.go（go:embed 声明源码必须保留，
# 否则 web 包无法编译，见 07 §2.2 与 .gitignore 例外说明）。
Write-Host "==> [3/8] 复制前端 FrontEnd/* -> BackEnd/internal/web/"
Get-ChildItem -Path $WebPkg -Force |
    Where-Object { $_.Name -notin @(".gitkeep", "embed.go", "embed_test.go") } |
    Remove-Item -Recurse -Force
Copy-Item -Path (Join-Path $FrontEnd "*") -Destination $WebPkg -Recurse -Force

$LdFlags = "-s -w -X main.version=$Version"

# ---------- 4. 交叉编译 windows/amd64 ----------
Write-Host "==> [4/8] 交叉编译 windows/amd64"
$env:CGO_ENABLED = "0"
$env:GOOS = "windows"; $env:GOARCH = "amd64"
Push-Location $BackEnd
try {
    go build -trimpath -ldflags $LdFlags -o (Join-Path $Bundle "windows\authcenter.exe") ./cmd/authcenter
    if ($LASTEXITCODE -ne 0) { throw "windows 交叉编译失败" }
} finally { Pop-Location }

# ---------- 5. 交叉编译 linux/amd64 ----------
Write-Host "==> [5/8] 交叉编译 linux/amd64"
$env:GOOS = "linux"; $env:GOARCH = "amd64"
Push-Location $BackEnd
try {
    go build -trimpath -ldflags $LdFlags -o (Join-Path $Bundle "linux\authcenter") ./cmd/authcenter
    if ($LASTEXITCODE -ne 0) { throw "linux 交叉编译失败" }
} finally { Pop-Location }

# ---------- 6. 前端静态文件副本 → 两个平台 web/（C6 落点） ----------
foreach ($os in @("windows", "linux")) {
    $webDest = Join-Path $Bundle "$os\web"
    if (Test-Path $webDest) { Remove-Item -Recurse -Force $webDest }
    New-Item -ItemType Directory -Path $webDest -Force | Out-Null
    Copy-Item -Path (Join-Path $FrontEnd "*") -Destination $webDest -Recurse -Force
    Write-Host "==> [6/8] 前端副本 -> Bundle/$os/web/"
}

# ---------- 7. 部署辅助文件 ----------
Copy-Item -Path (Join-Path $Deploy "Caddyfile.example")     -Destination (Join-Path $Bundle "windows\Caddyfile.example") -Force
Copy-Item -Path (Join-Path $Deploy "Caddyfile.example")     -Destination (Join-Path $Bundle "linux\Caddyfile.example") -Force
Copy-Item -Path (Join-Path $Deploy "authcenter.service")     -Destination (Join-Path $Bundle "linux\authcenter.service") -Force
Copy-Item -Path (Join-Path $Deploy "README.windows.txt")    -Destination (Join-Path $Bundle "windows\README.txt") -Force
Copy-Item -Path (Join-Path $Deploy "README.linux.md")       -Destination (Join-Path $Bundle "linux\README.md") -Force
Write-Host "==> [7/8] 部署辅助文件已复制"

# ---------- 8. SHA256 校验和 ----------
Write-Host "==> [8/8] 生成 Bundle/SHA256SUMS.txt"
$sums = Get-ChildItem -Path $Bundle -Recurse -File |
    Where-Object { $_.Name -ne "SHA256SUMS.txt" } |
    ForEach-Object {
        $rel  = $_.FullName.Substring($Bundle.Length + 1).Replace("\", "/")
        $hash = (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash.ToLower()
        "$hash  $rel"
    }
$sums | Sort-Object | Set-Content -Path (Join-Path $Bundle "SHA256SUMS.txt") -Encoding utf8

Write-Host ""
Write-Host "===== 构建完成 ====="
Get-ChildItem -Path $Bundle -Recurse -File | Select-Object FullName, Length | Format-Table -AutoSize
Write-Host "校验和: $Bundle\SHA256SUMS.txt"
