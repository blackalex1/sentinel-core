param(
    [string]$Version = "",
    [string]$OutputDir = "..\x-prox\app\src\main\jniLibs"
)

$ErrorActionPreference = "Stop"

# Automatically resolve version from Git if not explicitly specified
if ([string]::IsNullOrWhiteSpace($Version) -or $Version -eq "auto") {
    $gitTag = git describe --tags --exact-match 2>$null
    if ($LASTEXITCODE -eq 0 -and $gitTag) {
        $Version = $gitTag
    } else {
        $gitDesc = git describe --tags --always 2>$null
        if ($LASTEXITCODE -eq 0 -and $gitDesc) {
            $Version = $gitDesc
        } else {
            $gitCommit = git rev-parse --short HEAD 2>$null
            $Version = if ($gitCommit) { "git-$gitCommit" } else { "dev" }
        }
    }
}

Write-Host "Building Sentinel-Core JNI for Android (Version: $Version)..." -ForegroundColor Cyan

# Locate Android NDK
$ndkBase = "$env:LOCALAPPDATA\Android\Sdk\ndk"
if (-not (Test-Path $ndkBase)) {
    throw "Android NDK directory not found at $ndkBase"
}

$ndkVersionDir = Get-ChildItem -Path $ndkBase | Sort-Object Name -Descending | Select-Object -First 1
if (-not $ndkVersionDir) {
    throw "No NDK version installed in $ndkBase"
}

$toolchain = Join-Path $ndkVersionDir.FullName "toolchains\llvm\prebuilt\windows-x86_64\bin"
Write-Host "Using NDK Toolchain: $toolchain" -ForegroundColor Gray

$env:CGO_ENABLED = "1"
$env:GOOS = "android"
$env:CGO_LDFLAGS = "-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384"
$ldflags = "-s -w -X main.Version=$Version -extldflags=-Wl,-z,max-page-size=16384"

$targets = @(
    @{ Arch = "arm64"; CC = "aarch64-linux-android24-clang.cmd"; Out = "arm64-v8a" },
    @{ Arch = "arm";   CC = "armv7a-linux-androideabi24-clang.cmd"; Out = "armeabi-v7a" },
    @{ Arch = "amd64"; CC = "x86_64-linux-android24-clang.cmd";    Out = "x86_64" }
)

foreach ($t in $targets) {
    $env:GOARCH = $t.Arch
    $env:CC = Join-Path $toolchain $t.CC
    $targetDir = Join-Path $OutputDir $t.Out
    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }
    $targetFile = Join-Path $targetDir "libsentinel_core.so"
    
    Write-Host "Compiling $($t.Out) (16 KB page-aligned) -> $targetFile" -ForegroundColor Yellow
    go build -buildmode=c-shared -ldflags="$ldflags" -o $targetFile ./cmd/cshared
    Write-Host "Built $($t.Out) successfully." -ForegroundColor Green
}

Write-Host "All Android native libraries built and deployed successfully!" -ForegroundColor Green
