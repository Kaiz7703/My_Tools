# WAF Testing Tool - User Guide

## 📖 Overview

This tool is a custom modification of the Nuclei engine designed to test Web Application Firewall (WAF) effectiveness. It runs Nuclei templates and checks whether payloads successfully bypass the WAF.

**A WAF bypass is detected when**:
- ✅ HTTP Status Code = **200**
- ✅ Response Header `X-WAF-Status` = **`Passed`**

---

## 🚀 Building the Tool

```powershell
# Navigate to nuclei directory
cd c:\Users\minht\Downloads\Open\My_Tools\nuclei

# Build WAF testing tool
go build -o nuclei-waf.exe ./cmd/nuclei-waf

# Verify build
.\nuclei-waf.exe --help
```

---

## 💡 Basic Usage

### Syntax

```powershell
.\nuclei-waf.exe -t <TEMPLATE_DIR> -u <TARGET_URL> [OPTIONS]
```

### Simple Example

```powershell
.\nuclei-waf.exe -t "C:\Payloads\CVE" -u "https://testapp.local"
```

**Output Files**:
- 📄 `waf_test_results.csv` - All test results
- 📄 `waf_test_results_bypassed.csv` - Only successful bypasses
- 📄 `waf_test_state.json` - Progress tracking file

---

## 🎯 Key Features

### 1️⃣ Progressive Execution (Batch Processing)

The tool runs templates in batches (default 10 templates at a time) and saves progress:

```powershell
# Run batch 1 (templates 1-10)
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -bs 10

# Press Ctrl+C to stop

# Run batch 2 (templates 11-20) - automatically skips batch 1
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -bs 10
```

### 2️⃣ Dual CSV Output (Two Result Files)

**File 1: Comprehensive** (`waf_test_results.csv`)
- Contains ALL test results (both bypassed and blocked)
- Use for complete audit

**File 2: Bypassed Only** (`waf_test_results_bypassed.csv`)
- Contains only successful bypasses
- Use for immediate remediation

### 3️⃣ Summary Statistics

After each batch, the tool displays:
```
═══════════════════════════════════════════════════════════
Results: 7/10 bypassed (70.0%)
Cumulative: 7/10 templates completed
═══════════════════════════════════════════════════════════
```

Upon completion:
```
╔════════════════════════════════════════════════════════════╗
║              WAF Testing Summary Report                    ║
╠════════════════════════════════════════════════════════════╣
║ Total Templates Tested:     100                            ║
║ Successful Bypasses:         67                            ║
║ Blocked by WAF:              33                            ║
║ Bypass Rate:                 67.0%                         ║
╚════════════════════════════════════════════════════════════╝
```

### 4️⃣ State Management (Template Tracking)

**Automatic Resume**: The tool tracks completed templates and never re-runs them.

```powershell
# First run (completes 30 templates)
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com"

# Second run (automatically continues from template 31)
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com"
```

**State File** (`waf_test_state.json`):
```json
{
  "completed_templates": [
    "C:\\Payloads\\CVE\\CVE-2016-0001.yaml",
    "C:\\Payloads\\CVE\\CVE-2016-0002.yaml"
  ],
  "last_batch_index": 10,
  "total_templates": 100,
  "bypassed_count": 7,
  "blocked_count": 3,
  "last_updated": "2026-02-04T10:15:30+07:00"
}
```

---

## 🔧 Command-Line Flags

### Required Flags

| Flag | Short | Description | Example |
|------|-------|-------------|---------|
| `--template-dir` | `-t` | Templates directory path | `-t "C:\Payloads\CVE"` |
| `--target` | `-u` | Target URL to test | `-u "https://example.com"` |

### Optional Flags

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--csv-output` | `-o` | `waf_test_results.csv` | Comprehensive CSV file |
| `--csv-bypassed` | `-ob` | Auto-generated | Bypassed-only CSV file |
| `--state-file` | `-sf` | `waf_test_state.json` | State file path |
| `--batch-size` | `-bs` | `10` | Templates per batch |
| `--reset` | `-r` | `false` | Reset state and start fresh |
| `--verbose` | `-v` | `false` | Enable verbose output |
| `--silent` | `-s` | `false` | Silent mode (summary only) |

---

## 📋 Usage Examples

### Example 1: Test WAF with batch size 20

```powershell
.\nuclei-waf.exe -t "C:\Payloads\OWASP" -u "https://example.com" -bs 20
```

### Example 2: Custom output files

```powershell
.\nuclei-waf.exe `
  -t "C:\Payloads" `
  -u "https://example.com" `
  -o "results_2026-02-04.csv" `
  -ob "dangerous_payloads.csv"
```

### Example 3: Reset and start fresh

```powershell
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" --reset
```

### Example 4: Verbose mode

```powershell
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -v
```

---

## 📊 CSV Output Format

### Comprehensive CSV

```csv
Template ID,Template Name,Severity,Target URL,Status,HTTP Status Code,X-WAF-Status Header,Timestamp,Payload
CVE-2016-0001,SQL Injection,high,https://example.com/search,Bypassed,200,Passed,2026-02-04 10:05:23,' OR '1'='1
CVE-2016-0002,XSS Test,medium,https://example.com/page,Blocked,403,,2026-02-04 10:05:24,<script>alert(1)</script>
```

### Bypassed CSV

```csv
Template ID,Template Name,Severity,Target URL,Status,HTTP Status Code,X-WAF-Status Header,Timestamp,Payload
CVE-2016-0001,SQL Injection,high,https://example.com/search,Bypassed,200,Passed,2026-02-04 10:05:23,' OR '1'='1
```

---

## 🔄 Real-World Workflow

### Scenario 1: First-time WAF Testing

```powershell
# 1. Build tool
go build -o nuclei-waf.exe ./cmd/nuclei-waf

# 2. Run test
.\nuclei-waf.exe -t "C:\Payloads\CVE" -u "https://prod.example.com"

# 3. Review bypassed payloads
Import-Csv waf_test_results_bypassed.csv | Format-Table

# 4. Fix WAF rules based on results

# 5. Re-test to verify fixes
.\nuclei-waf.exe -t "C:\Payloads\CVE" -u "https://prod.example.com" --reset
```

### Scenario 2: Progressive Testing

```powershell
# Run first 10 templates
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -bs 10

# Stop and review results
Import-Csv waf_test_results.csv | Format-Table

# Continue with next 10 templates
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -bs 10

# Repeat until complete
```

---

## ❓ Troubleshooting

### Error: "Template directory is required"

**Cause**: Missing `-t` flag

**Solution**:
```powershell
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com"
```

### Error: "No templates found"

**Cause**: Template directory is empty or path is incorrect

**Solution**:
```powershell
# Check if templates exist
dir "C:\Payloads\*.yaml"

# Use correct path
.\nuclei-waf.exe -t "C:\Payloads\CVE" -u "https://example.com"
```

### Want to start over

**Solution 1**: Use `--reset` flag
```powershell
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" --reset
```

**Solution 2**: Manually delete files
```powershell
del waf_test_state.json
del waf_test_results.csv
del waf_test_results_bypassed.csv
```

### All results show "Blocked"

**Cause**: Target not returning `X-WAF-Status: Passed` header

**Solution**: Verify WAF/target application is configured to return this header on successful bypass

---

## 📚 Additional Documentation

For detailed technical documentation, see the artifacts directory:

1. **[FINAL_SUMMARY.md](file:///C:/Users/minht/.gemini/antigravity/brain/bad82065-81e4-4653-9183-f36bbef5701d/FINAL_SUMMARY.md)** - Complete overview
2. **[quick_start.md](file:///C:/Users/minht/.gemini/antigravity/brain/bad82065-81e4-4653-9183-f36bbef5701d/quick_start.md)** - Quick start guide
3. **[user_guide.md](file:///C:/Users/minht/.gemini/antigravity/brain/bad82065-81e4-4653-9183-f36bbef5701d/user_guide.md)** - Detailed user manual
4. **[walkthrough.md](file:///C:/Users/minht/.gemini/antigravity/brain/bad82065-81e4-4653-9183-f36bbef5701d/walkthrough.md)** - Technical implementation
5. **[feature_summary.md](file:///C:/Users/minht/.gemini/antigravity/brain/bad82065-81e4-4653-9183-f36bbef5701d/feature_summary.md)** - Feature overview

---

## 🎯 Quick Reference

```powershell
# Basic usage
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com"

# Custom batch size
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -bs 20

# Custom output files
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -o "results.csv" -ob "bypassed.csv"

# Reset and start fresh
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" --reset

# Verbose mode
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -v

# Silent mode (summary only)
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -s
```

---

## 📦 Resource Requirements

**Source Code** (new additions):
- 8 Go files: ~50 KB
- Very lightweight addition to codebase

**Executable** (after build):
- `nuclei-waf.exe`: **~45 MB**
- Similar to original Nuclei size

**Go Dependencies** (already included with Nuclei):
- ~200+ packages
- ~1-2 GB in `$GOPATH/pkg/mod`
- Downloaded once, reused for subsequent builds

**Runtime** (when running):
- RAM: **~100-200 MB** (depends on batch size)
- Disk for output: **Minimal**
  - CSV files: ~1-10 MB (depends on template count)
  - State file: <1 MB

---

## ✅ Pre-Run Checklist

- [ ] Tool built: `go build -o nuclei-waf.exe ./cmd/nuclei-waf`
- [ ] Templates exist in specified directory
- [ ] Target URL is accessible
- [ ] Target application configured to return `X-WAF-Status` header
- [ ] Sufficient disk space for output files

---

**Happy Testing! 🚀**

For issues or questions, check the detailed documentation files listed above or review the source code in `pkg/waftest/`.
