# WAF Efficacy Framework - Setup Guide

Complete guide to set up and use the WAF Efficacy Framework on Windows.

---

## 📋 Prerequisites

### 1. **Go Programming Language**

#### Installation
1. Download Go from official website:
   - Visit: https://go.dev/dl/
   - Download: `go1.21.x.windows-amd64.msi` (or latest version)

2. Run installer:
   - Double-click the `.msi` file
   - Follow installation wizard
   - Default installation path: `C:\Program Files\Go`

3. Verify installation:
   ```powershell
   go version
   # Output: go version go1.21.x windows/amd64
   ```

4. Check environment variables:
   ```powershell
   echo $env:GOPATH
   # Should show: C:\Users\<username>\go
   
   echo $env:PATH
   # Should include: C:\Program Files\Go\bin
   ```

---

### 2. **Nuclei Scanner**

Nuclei is the core engine used by WAF Efficacy Framework.

#### Installation Methods

**Method 1: Using Go (Recommended)**
```powershell
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**Method 2: Download Binary**
1. Visit: https://github.com/projectdiscovery/nuclei/releases
2. Download: `nuclei_<version>_windows_amd64.zip`
3. Extract to a directory (e.g., `C:\Tools\nuclei\`)
4. Add to PATH:
   ```powershell
   $env:PATH += ";C:\Tools\nuclei"
   # Or add permanently via System Properties > Environment Variables
   ```

**Method 3: Using Chocolatey**
```powershell
choco install nuclei
```

#### Verify Installation
```powershell
nuclei -version
# Output: Nuclei v3.x.x
```

---

### 3. **Git (Optional but Recommended)**

For cloning the repository and version control.

#### Installation
1. Download from: https://git-scm.com/download/win
2. Run installer with default settings
3. Verify:
   ```powershell
   git --version
   ```

---

## 🚀 Building WAF Efficacy Framework

### Step 1: Navigate to Project Directory
```powershell
cd C:\Users\minht\Downloads\Open\My_Tools\wafefficacy
```

### Step 2: Verify Go Module
```powershell
# Check go.mod exists
cat go.mod

# Should show:
# module wafefficacy
# go 1.21
# require github.com/spf13/cobra v1.x.x
```

### Step 3: Download Dependencies
```powershell
go mod download
# This downloads all required packages (cobra, etc.)
```

### Step 4: Build the Project
```powershell
# Build for current platform
go build

# Or build with specific output name
go build -o wafefficacy.exe

# Or build with optimizations (smaller binary)
go build -ldflags="-s -w" -o wafefficacy.exe
```

**Build Output:**
- Creates `wafefficacy.exe` in current directory
- File size: ~5-10 MB

### Step 5: Verify Build
```powershell
.\wafefficacy.exe --help

# Output:
# Usage:
#   wafefficacy [command]
# 
# Available Commands:
#   run         Run WAF Efficacy Tests
#   ...
```

---

## ⚙️ Configuration

### 1. **Review config.yaml**
```powershell
cat config.yaml
```

**Key Settings:**
```yaml
concurrency: 4                    # Adjust based on your system
header:
  - 'User-Agent: Mozilla/5.0...'  # Customize headers
templates:
  - http                          # Template directory
tags: false-positive,true-positive
jsonl: true                       # JSON Lines output
include-rr: true                  # Include request/response
```

### 2. **Check Templates**
```powershell
# List available attack types
ls nuclei-templates\http

# Output:
# cmdexe/
# sqli/
# traversal/
# xss/
```

### 3. **Review Payloads**
```powershell
# Example: View SQL injection payloads
cat nuclei-templates\helpers\payloads\sqli\true-positives.txt
cat nuclei-templates\helpers\payloads\sqli\false-positives.txt
```

---

## 🎯 Usage Examples

### Basic Usage

#### 1. **Test Against Local WAF**
```powershell
.\wafefficacy.exe run -u http://localhost:8080
```

#### 2. **Test Specific Attack Types**
```powershell
# Test only SQL injection and XSS
.\wafefficacy.exe run -u http://target.com --attacks sqli,xss
```

#### 3. **Custom WAF Response Code**
```powershell
# If your WAF returns 403 instead of 406
.\wafefficacy.exe run -u http://target.com -r "403 Forbidden"
```

#### 4. **Verbose Output**
```powershell
.\wafefficacy.exe run -u http://target.com -v
```

#### 5. **Custom Config File**
```powershell
.\wafefficacy.exe run -u http://target.com -c custom-config.yaml
```

---

## 📊 Understanding Output

### Console Output
```
Running efficacy tests using Nuclei version 3.x.x

-------------CMDEXE-------------
True Positives 42
False Negatives 8
True Negatives 47
False Positives 3
Efficacy 88.500

-------------SQLI-------------
True Positives 45
False Negatives 5
True Negatives 48
False Positives 2
Efficacy 92.500

-------------TRAVERSAL-------------
True Positives 38
False Negatives 12
True Negatives 49
False Positives 1
Efficacy 87.000

-------------XSS-------------
True Positives 40
False Negatives 10
True Negatives 46
False Positives 4
Efficacy 86.000

------------- WAF Efficacy -------------
Overall efficacy: 88.500
```

### JSON Output (data.json)
```json
{"template-id":"sqli-true-positive","info":{"name":"SQL Injection","author":["wafefficacy"],"tags":["sqli","true-positive"]},"type":"http","request":"GET /anything?p=%27+OR+%271%27%3D%271 HTTP/1.1...","response":"HTTP/1.1 406 Not Acceptable..."}
```

---

## 🔧 Troubleshooting

### Issue 1: "nuclei: command not found"
**Solution:**
```powershell
# Check if nuclei is in PATH
where.exe nuclei

# If not found, add to PATH or use full path
$env:PATH += ";C:\Users\<username>\go\bin"
```

### Issue 2: "go: command not found"
**Solution:**
- Reinstall Go
- Verify PATH includes `C:\Program Files\Go\bin`
- Restart PowerShell/Terminal

### Issue 3: Build fails with "cannot find package"
**Solution:**
```powershell
# Clean module cache
go clean -modcache

# Re-download dependencies
go mod download

# Rebuild
go build
```

### Issue 4: "Error: must specify target URL/host to scan"
**Solution:**
```powershell
# Always provide -u flag
.\wafefficacy.exe run -u http://target.com
```

### Issue 5: No results or 0 efficacy
**Possible causes:**
1. WAF not configured to block with 406 status
   - Solution: Use `-r` flag with correct status
2. Target not reachable
   - Solution: Verify target URL is accessible
3. Templates not found
   - Solution: Check `nuclei-templates/` directory exists

---

## 🎓 Advanced Usage

### 1. **Adding New Attack Type**

**Example: Add SSRF testing**

```powershell
# Create directories
mkdir nuclei-templates\http\ssrf
mkdir nuclei-templates\helpers\payloads\ssrf

# Create payload files
New-Item nuclei-templates\helpers\payloads\ssrf\true-positives.txt
New-Item nuclei-templates\helpers\payloads\ssrf\false-positives.txt

# Create template files
New-Item nuclei-templates\http\ssrf\true-positives.yaml
New-Item nuclei-templates\http\ssrf\false-positives.yaml
```

**Edit true-positives.yaml:**
```yaml
id: ssrf-true-positive

info:
  name: Server-Side Request Forgery (SSRF)
  author: wafefficacy
  severity: info
  tags: ssrf,true-positive

http:
  - raw:
      - |
        GET /anything?url={{url_encode(ssrf)}} HTTP/1.1
        Host: {{Hostname}}
        Connection: close

    payloads:
      ssrf: helpers/payloads/ssrf/true-positives.txt

    matchers:
      - type: status
        status:
          - 1
        negative: true
```

**Run with new attack type:**
```powershell
.\wafefficacy.exe run -u http://target.com --attacks cmdexe,sqli,xss,ssrf
```

### 2. **Regression Testing**

**Save baseline:**
```powershell
# First run - establish baseline
.\wafefficacy.exe run -u http://target.com -o baseline.json
```

**Compare future runs:**
```powershell
# Future run - compare against baseline
.\wafefficacy.exe run -u http://target.com -i baseline.json

# Exits with error if efficacy drops below baseline
```

### 3. **Continuous Integration**

**Example CI script:**
```powershell
# ci-test.ps1
$target = "http://staging-waf.company.com"
$baseline = "baseline-efficacy.json"

# Run test
.\wafefficacy.exe run -u $target -i $baseline

# Check exit code
if ($LASTEXITCODE -ne 0) {
    Write-Error "WAF efficacy regression detected!"
    exit 1
}

Write-Host "WAF efficacy test passed!"
```

---

## 📝 Best Practices

### 1. **Testing Environment**
- ✅ Test against staging/dev WAF first
- ✅ Ensure WAF is configured to block (not just log)
- ✅ Verify blocked response status code
- ✅ Use realistic test target endpoints

### 2. **Payload Management**
- ✅ Keep payloads up-to-date
- ✅ Add real-world attack patterns
- ✅ Include edge cases
- ✅ Balance true/false positive payloads

### 3. **Monitoring**
- ✅ Run tests regularly (daily/weekly)
- ✅ Track efficacy trends over time
- ✅ Alert on significant drops
- ✅ Document WAF rule changes

### 4. **Performance**
- ✅ Adjust concurrency based on target capacity
- ✅ Use rate limiting if needed
- ✅ Monitor target system during tests

---

## 🔗 Resources

- **Nuclei Documentation:** https://docs.nuclei.sh/
- **Go Documentation:** https://go.dev/doc/
- **WAF Efficacy GitHub:** https://github.com/projectdiscovery/wafefficacy
- **Nuclei Templates:** https://github.com/projectdiscovery/nuclei-templates

---

## 📞 Quick Reference

### Minimum Requirements
- Windows 10/11 or Windows Server 2016+
- 4GB RAM
- 1GB free disk space
- Internet connection (for initial setup)

### Installation Time
- Go: ~5 minutes
- Nuclei: ~2 minutes
- Build WAF Efficacy: ~1 minute
- **Total: ~10 minutes**

### Common Commands
```powershell
# Build
go build

# Run basic test
.\wafefficacy.exe run -u http://target.com

# Run with custom attacks
.\wafefficacy.exe run -u http://target.com --attacks sqli,xss

# Verbose output
.\wafefficacy.exe run -u http://target.com -v

# Custom WAF response
.\wafefficacy.exe run -u http://target.com -r "403 Forbidden"
```

---

**Ready to test your WAF efficacy!** 🚀
