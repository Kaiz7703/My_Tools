# Quick Installation Guide

## Step 1: Install Go

### Download and Install:
1. Open browser: https://go.dev/dl/
2. Download: `go1.23.x.windows-amd64.msi`
3. Run installer → Next → Next → Install
4. **IMPORTANT: Restart PowerShell/Terminal**

### Verify:
```powershell
go version
# Should show: go version go1.23.x windows/amd64
```

---

## Step 2: Run Auto Setup Script

After Go is installed and you've restarted PowerShell:

```powershell
cd C:\Users\minht\Downloads\Open\My_Tools\wafefficacy
.\setup.ps1
```

The script will automatically:
- ✅ Check Go installation
- ✅ Install Nuclei scanner
- ✅ Download dependencies
- ✅ Build WAF Efficacy
- ✅ Verify installation

---

## Step 3: Test Run

```powershell
# Show help
.\wafefficacy.exe --help

# Test against a target (replace with your WAF URL)
.\wafefficacy.exe run -u http://localhost:8080
```

---

## Troubleshooting

### If setup.ps1 won't run:
```powershell
# Enable script execution
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Then run again
.\setup.ps1
```

### If Nuclei not found after installation:
```powershell
# Add Go bin to PATH
$env:PATH += ";$env:USERPROFILE\go\bin"

# Or restart PowerShell
```

---

## What You Need:

1. **Go** - Download from https://go.dev/dl/
2. **Internet connection** - To download Nuclei and dependencies
3. **5-10 minutes** - For complete setup

---

## Next Steps:

After setup completes, see:
- `SETUP_GUIDE.md` - Detailed usage guide
- `README.md` - Framework documentation
