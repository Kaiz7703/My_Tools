# WAF Testing Tool - Hướng Dẫn Sử Dụng

## 📖 Tổng Quan

Tool này là custom modification của Nuclei engine để test hiệu quả của WAF (Web Application Firewall). Tool sẽ chạy các Nuclei templates và kiểm tra xem payload có bypass được WAF hay không.

**WAF Bypass được xác định khi**:
- ✅ HTTP Status Code = **200**
- ✅ Response Header `X-WAF-Status` = **`Passed`**

---

## 🚀 Build Tool

```powershell
# Navigate to nuclei directory
cd c:\Users\minht\Downloads\Open\My_Tools\nuclei

# Build WAF testing tool
go build -o nuclei-waf.exe ./cmd/nuclei-waf

# Verify build
.\nuclei-waf.exe --help
```

---

## 💡 Sử Dụng Cơ Bản

### Cú pháp

```powershell
.\nuclei-waf.exe -t <TEMPLATE_DIR> -u <TARGET_URL> [OPTIONS]
```

### Ví dụ đơn giản

```powershell
.\nuclei-waf.exe -t "C:\Payloads\CVE" -u "https://testapp.local"
```

**Kết quả**:
- 📄 `waf_test_results.csv` - Tất cả kết quả test
- 📄 `waf_test_results_bypassed.csv` - Chỉ các payload bypass thành công
- 📄 `waf_test_state.json` - File tracking tiến trình

---

## 🎯 Các Tính Năng Chính

### 1️⃣ Progressive Execution (Chạy Từng Batch)

Tool chạy templates theo batch (mặc định 10 templates/lần) và lưu tiến trình:

```powershell
# Chạy batch 1 (templates 1-10)
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -bs 10

# Nhấn Ctrl+C để dừng

# Chạy tiếp batch 2 (templates 11-20) - tự động skip batch 1
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -bs 10
```

### 2️⃣ Dual CSV Output (2 File Kết Quả)

**File 1: Comprehensive** (`waf_test_results.csv`)
- Chứa TẤT CẢ kết quả test (cả bypass và blocked)
- Dùng để audit đầy đủ

**File 2: Bypassed Only** (`waf_test_results_bypassed.csv`)
- Chỉ chứa các payload bypass thành công
- Dùng để fix ngay các lỗ hổng

### 3️⃣ Summary Statistics (Thống Kê Tổng Hợp)

Sau mỗi batch, tool hiển thị:
```
═══════════════════════════════════════════════════════════
Results: 7/10 bypassed (70.0%)
Cumulative: 7/10 templates completed
═══════════════════════════════════════════════════════════
```

Khi hoàn thành:
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

---

## 🔧 Command-Line Flags

### Required (Bắt buộc)

| Flag | Short | Mô tả | Ví dụ |
|------|-------|-------|-------|
| `--template-dir` | `-t` | Thư mục chứa templates | `-t "C:\Payloads\CVE"` |
| `--target` | `-u` | URL target để test | `-u "https://example.com"` |

### Optional (Tùy chọn)

| Flag | Short | Default | Mô tả |
|------|-------|---------|-------|
| `--csv-output` | `-o` | `waf_test_results.csv` | File CSV tổng hợp |
| `--csv-bypassed` | `-ob` | Auto | File CSV chỉ bypass |
| `--state-file` | `-sf` | `waf_test_state.json` | File lưu tiến trình |
| `--batch-size` | `-bs` | `10` | Số templates/batch |
| `--reset` | `-r` | `false` | Reset và chạy lại từ đầu |
| `--verbose` | `-v` | `false` | Hiển thị chi tiết |
| `--silent` | `-s` | `false` | Chỉ hiển thị summary |

---

## 📋 Ví Dụ Sử Dụng

### Ví dụ 1: Test WAF với batch size 20

```powershell
.\nuclei-waf.exe -t "C:\Payloads\OWASP" -u "https://example.com" -bs 20
```

### Ví dụ 2: Custom output files

```powershell
.\nuclei-waf.exe `
  -t "C:\Payloads" `
  -u "https://example.com" `
  -o "results_2026-02-04.csv" `
  -ob "dangerous_payloads.csv"
```

### Ví dụ 3: Reset và chạy lại từ đầu

```powershell
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" --reset
```

### Ví dụ 4: Verbose mode

```powershell
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -v
```

---

## 📊 Format CSV Output

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

## 🔄 Workflow Thực Tế

### Scenario 1: Test WAF lần đầu

```powershell
# 1. Build tool
go build -o nuclei-waf.exe ./cmd/nuclei-waf

# 2. Chạy test
.\nuclei-waf.exe -t "C:\Payloads\CVE" -u "https://prod.example.com"

# 3. Review kết quả bypass
Import-Csv waf_test_results_bypassed.csv | Format-Table

# 4. Fix WAF rules dựa trên kết quả

# 5. Test lại để verify
.\nuclei-waf.exe -t "C:\Payloads\CVE" -u "https://prod.example.com" --reset
```

### Scenario 2: Progressive Testing

```powershell
# Chạy 10 templates đầu
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -bs 10

# Dừng lại review kết quả
Import-Csv waf_test_results.csv | Format-Table

# Tiếp tục 10 templates tiếp theo
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -bs 10

# Lặp lại cho đến hết
```

---

## ❓ Troubleshooting

### Lỗi: "Template directory is required"

**Nguyên nhân**: Thiếu flag `-t`

**Giải pháp**:
```powershell
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com"
```

### Lỗi: "No templates found"

**Nguyên nhân**: Thư mục templates rỗng hoặc đường dẫn sai

**Giải pháp**:
```powershell
# Kiểm tra templates có tồn tại
dir "C:\Payloads\*.yaml"

# Dùng đường dẫn đúng
.\nuclei-waf.exe -t "C:\Payloads\CVE" -u "https://example.com"
```

### Muốn chạy lại từ đầu

**Giải pháp 1**: Dùng flag `--reset`
```powershell
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" --reset
```

**Giải pháp 2**: Xóa file state thủ công
```powershell
del waf_test_state.json
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com"
```

### Tất cả kết quả đều "Blocked"

**Nguyên nhân**: Target không trả về header `X-WAF-Status: Passed`

**Giải pháp**: Kiểm tra cấu hình WAF/target application phải trả về header này khi bypass thành công

---

## 📚 Documentation Đầy Đủ

Các file documentation chi tiết trong thư mục artifacts:

1. **[FINAL_SUMMARY.md](file:///C:/Users/minht/.gemini/antigravity/brain/bad82065-81e4-4653-9183-f36bbef5701d/FINAL_SUMMARY.md)** - Tổng hợp toàn bộ
2. **[quick_start.md](file:///C:/Users/minht/.gemini/antigravity/brain/bad82065-81e4-4653-9183-f36bbef5701d/quick_start.md)** - Hướng dẫn nhanh
3. **[user_guide.md](file:///C:/Users/minht/.gemini/antigravity/brain/bad82065-81e4-4653-9183-f36bbef5701d/user_guide.md)** - Hướng dẫn chi tiết
4. **[walkthrough.md](file:///C:/Users/minht/.gemini/antigravity/brain/bad82065-81e4-4653-9183-f36bbef5701d/walkthrough.md)** - Technical details
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

# Silent mode (only summary)
.\nuclei-waf.exe -t "C:\Payloads" -u "https://example.com" -s
```

---

## ✅ Checklist Trước Khi Chạy

- [ ] Đã build tool: `go build -o nuclei-waf.exe ./cmd/nuclei-waf`
- [ ] Có templates trong thư mục chỉ định
- [ ] Target URL accessible
- [ ] Target application configured để trả về `X-WAF-Status` header
- [ ] Đủ disk space cho output files

---

**Happy Testing! 🚀**

Nếu có vấn đề, xem các file documentation chi tiết ở trên hoặc check source code trong `pkg/waftest/`.
