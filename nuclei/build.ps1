# Build script for WAF Testing Tool (Windows)
# Supports cross-compilation for Windows, Linux, and macOS

Write-Host "Building WAF Testing Tool..." -ForegroundColor Cyan
Write-Host ""

# Build for current platform (Windows)
Write-Host "Building for Windows (current platform)..." -ForegroundColor Yellow
go build -o nuclei-waf.exe ./cmd/nuclei-waf
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Built: nuclei-waf.exe" -ForegroundColor Green
} else {
    Write-Host "✗ Build failed" -ForegroundColor Red
    exit 1
}

# Cross-compile for other platforms
Write-Host ""
Write-Host "Cross-compiling for other platforms..." -ForegroundColor Cyan

# Linux (amd64)
Write-Host "Building for Linux (amd64)..." -ForegroundColor Yellow
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o nuclei-waf-linux-amd64 ./cmd/nuclei-waf
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Built: nuclei-waf-linux-amd64" -ForegroundColor Green
}

# macOS (amd64)
Write-Host "Building for macOS (amd64)..." -ForegroundColor Yellow
$env:GOOS = "darwin"
$env:GOARCH = "amd64"
go build -o nuclei-waf-darwin-amd64 ./cmd/nuclei-waf
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Built: nuclei-waf-darwin-amd64" -ForegroundColor Green
}

# macOS (arm64 - Apple Silicon)
Write-Host "Building for macOS (arm64)..." -ForegroundColor Yellow
$env:GOOS = "darwin"
$env:GOARCH = "arm64"
go build -o nuclei-waf-darwin-arm64 ./cmd/nuclei-waf
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Built: nuclei-waf-darwin-arm64" -ForegroundColor Green
}

# Reset environment variables
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Build complete! Executables:" -ForegroundColor Cyan
Get-ChildItem -Filter "nuclei-waf*" | Select-Object Name, @{Name="Size (MB)";Expression={[math]::Round($_.Length/1MB, 2)}} | Format-Table -AutoSize
