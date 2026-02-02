# WAF Efficacy - Auto Setup Script
# Run this AFTER installing Go

Write-Host "================================" -ForegroundColor Cyan
Write-Host "WAF Efficacy Framework - Setup" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Go installation
Write-Host "[1/5] Checking Go installation..." -ForegroundColor Yellow
try {
    $goVersion = go version
    Write-Host "✓ Go is installed: $goVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Go is NOT installed!" -ForegroundColor Red
    Write-Host "Please install Go from: https://go.dev/dl/" -ForegroundColor Yellow
    Write-Host "Then restart PowerShell and run this script again." -ForegroundColor Yellow
    exit 1
}

# Step 2: Install Nuclei
Write-Host ""
Write-Host "[2/5] Installing Nuclei scanner..." -ForegroundColor Yellow
try {
    $nucleiCheck = nuclei -version 2>$null
    Write-Host "✓ Nuclei is already installed: $nucleiCheck" -ForegroundColor Green
} catch {
    Write-Host "Installing Nuclei via Go..." -ForegroundColor Cyan
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    
    # Verify installation
    $nucleiVersion = nuclei -version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Nuclei installed successfully: $nucleiVersion" -ForegroundColor Green
    } else {
        Write-Host "✗ Nuclei installation failed!" -ForegroundColor Red
        Write-Host "Try manually: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" -ForegroundColor Yellow
        exit 1
    }
}

# Step 3: Download Go dependencies
Write-Host ""
Write-Host "[3/5] Downloading Go dependencies..." -ForegroundColor Yellow
go mod download
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Dependencies downloaded" -ForegroundColor Green
} else {
    Write-Host "✗ Failed to download dependencies" -ForegroundColor Red
    exit 1
}

# Step 4: Build WAF Efficacy
Write-Host ""
Write-Host "[4/5] Building WAF Efficacy Framework..." -ForegroundColor Yellow
go build -ldflags="-s -w" -o wafefficacy.exe
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Build successful!" -ForegroundColor Green
    $fileSize = (Get-Item wafefficacy.exe).Length / 1MB
    Write-Host "  Binary size: $([math]::Round($fileSize, 2)) MB" -ForegroundColor Cyan
} else {
    Write-Host "✗ Build failed!" -ForegroundColor Red
    exit 1
}

# Step 5: Verify installation
Write-Host ""
Write-Host "[5/5] Verifying installation..." -ForegroundColor Yellow
$output = .\wafefficacy.exe --help 2>&1
if ($LASTEXITCODE -eq 0 -or $output -match "wafefficacy") {
    Write-Host "✓ WAF Efficacy is ready to use!" -ForegroundColor Green
} else {
    Write-Host "✗ Verification failed" -ForegroundColor Red
    exit 1
}

# Summary
Write-Host ""
Write-Host "================================" -ForegroundColor Cyan
Write-Host "Setup Complete!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Quick Start:" -ForegroundColor Yellow
Write-Host "  .\wafefficacy.exe run -u http://target.com" -ForegroundColor White
Write-Host ""
Write-Host "Examples:" -ForegroundColor Yellow
Write-Host "  # Test specific attacks" -ForegroundColor Gray
Write-Host "  .\wafefficacy.exe run -u http://target.com --attacks sqli,xss" -ForegroundColor White
Write-Host ""
Write-Host "  # Custom WAF response code" -ForegroundColor Gray
Write-Host "  .\wafefficacy.exe run -u http://target.com -r '403 Forbidden'" -ForegroundColor White
Write-Host ""
Write-Host "  # Verbose output" -ForegroundColor Gray
Write-Host "  .\wafefficacy.exe run -u http://target.com -v" -ForegroundColor White
Write-Host ""
Write-Host "For more info, see: SETUP_GUIDE.md" -ForegroundColor Cyan
