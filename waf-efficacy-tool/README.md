# WAF Efficacy Testing Tool

## 📋 Overview

A Go-based tool for testing Web Application Firewall (WAF) efficacy with support for True Positive and False Positive testing.

## 🏗️ Features

- ✅ **3 Test Modes:**
  - `--tp-only`: Test True Positive (malicious payloads)
  - `--fp-only`: Test False Positive (legitimate requests)
  - `--mixed`: Test both TP and FP

- ✅ **Detection Logic:**
  - Status 200 = Allowed (bypassed WAF)
  - Status 400/403 = Blocked (caught by WAF)

- ✅ **Output:**
  - CSV files with detailed results
  - Summary statistics
  - Concurrent execution with progress bar

## 📦 Installation

```bash
# Clone or copy the tool
cd waf-efficacy-tool

# Download dependencies
go mod download

# Build
go build -o waf-efficacy ./cmd/waf-efficacy
```

## 🚀 Usage

### **Basic Usage**

```bash
# Test True Positive only
./waf-efficacy -u http://your-waf.com --tp-only

# Test False Positive only
./waf-efficacy -u http://your-waf.com --fp-only

# Test both (default)
./waf-efficacy -u http://your-waf.com
```

### **Verbose Mode**

```bash
# Show each request summary
./waf-efficacy -u http://your-waf.com -v
```

**Output:**
```
[DEBUG] GET http://waf.com/?p=<script>alert(1)</script>
[DEBUG] Response: 403 (blocked=true)
```

### **Debug Mode (Detailed)**

```bash
# Show full request/response details
./waf-efficacy -u http://your-waf.com --debug
```

**Output:**
```
======================================================================
📤 REQUEST
----------------------------------------------------------------------
GET http://waf.com/?p=<script>alert(1)</script>

Headers:
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
  Connection: close

Body:
(empty)
----------------------------------------------------------------------
📥 RESPONSE
----------------------------------------------------------------------
Status: 403 Forbidden

Headers:
  Content-Type: text/html
  Server: nginx
  Cloudrity-WAF-Return: backend

Body (189 bytes):
<!DOCTYPE html>
<head>
<title>Cloudrity</title>
</head>
<body>
<h1>The server name is not supported.</h1>
</body>
</html>
----------------------------------------------------------------------
Result: isBlocked=true
======================================================================
```

### **Advanced Options**

```bash
./waf-efficacy \
  -u http://your-waf.com \
  -malicious ./Data/Malicious \
  -legitimate ./Data/Legitimate \
  -o ./results \
  -timeout 10 \
  -workers 20 \
  --debug
```

### **Flags**

| Flag | Description | Default |
|------|-------------|---------|
| `-u` | WAF URL to test (required) | - |
| `-malicious` | Path to malicious dataset | `Data/Malicious` |
| `-legitimate` | Path to legitimate dataset | `Data/Legitimate` |
| `-o` | Output directory | `.` |
| `-timeout` | Request timeout (seconds) | `5` |
| `-workers` | Concurrent workers | `10` |
| `--tp-only` | Test TP only | `false` |
| `--fp-only` | Test FP only | `false` |
| `-v` | Verbose mode (show request summary) | `false` |
| `--debug` | Debug mode (show full request/response) | `false` |

## 📊 Dataset Format

Datasets should be JSON files with the following structure:

```json
[
  {
    "method": "GET",
    "url": "/?p=<script>alert(1)</script>",
    "headers": {
      "User-Agent": "Mozilla/5.0...",
      "Connection": "close"
    },
    "data": ""
  },
  {
    "method": "POST",
    "url": "/",
    "headers": {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    "data": "p=1' OR '1'='1"
  }
]
```

## 📈 Output Files

### **TP Results (`tp_results.csv`)**
```csv
test_name,url,method,status_code,is_blocked,bypassed
sql-injection,/?p=1' OR '1'='1,GET,403,true,false
xss,/?p=<script>alert(1)</script>,GET,200,false,true
```

### **FP Results (`fp_results.csv`)**
```csv
test_name,url,method,status_code,is_blocked,false_positive
ecommerce,/search?q=javascript,GET,403,true,true
banking,/api/users?id=123,GET,200,false,false
```

### **Mixed Results (`mixed_results.csv`)**
```csv
test_name,url,method,status_code,is_blocked,bypassed,false_positive,dataset_type
sql-injection,...,GET,403,true,false,,Malicious
ecommerce,...,GET,403,true,,true,Legitimate
```

## 📊 Summary Output

### **True Positive Test**
```
============================================================
TRUE POSITIVE TEST RESULTS
============================================================
Total Malicious Requests: 73924
Bypassed (200):           1500
Blocked (400/403):        72424
Bypass Rate:              2.03%
============================================================
```

### **False Positive Test**
```
============================================================
FALSE POSITIVE TEST RESULTS
============================================================
Total Legitimate Requests: 973964
Allowed (200):             950000
False Positives (400/403): 23964
False Positive Rate:       2.46%
============================================================
```

### **Mixed Test**
```
============================================================
MIXED TEST RESULTS
============================================================
True Positive Metrics:
  Bypassed:     1500
  Blocked:      72424
  Bypass Rate:  2.03%

False Positive Metrics:
  Allowed:      950000
  FP Count:     23964
  FP Rate:      2.46%
============================================================
```

## 🔧 Project Structure

```
waf-efficacy-tool/
├── cmd/
│   └── waf-efficacy/
│       └── main.go          # Entry point
├── pkg/
│   └── efficacy/
│       ├── types.go         # Data structures
│       ├── config.go        # Configuration
│       ├── loader.go        # Dataset loader
│       ├── client.go        # HTTP client
│       ├── analyzer.go      # Results analyzer
│       └── writer.go        # CSV writer
├── go.mod
└── README.md
```

## 🐛 Troubleshooting

### **No Requests Reaching WAF**

**Problem:** Tool runs but no requests appear in WAF logs.

**Solution:** Use debug mode to verify requests:
```bash
./waf-efficacy -u http://your-waf.com --tp-only --debug
```

Check:
- ✅ WAF URL is correct
- ✅ Network connectivity
- ✅ Firewall rules
- ✅ Request headers in debug output

### **All Requests Timeout**

**Problem:** All requests return status code 0.

**Solution:**
```bash
# Increase timeout
./waf-efficacy -u http://your-waf.com -timeout 30

# Reduce workers
./waf-efficacy -u http://your-waf.com -workers 5
```

### **Unexpected Detection Results**

**Problem:** WAF blocks legitimate requests or allows malicious ones.

**Solution:** Use debug mode to inspect responses:
```bash
./waf-efficacy -u http://your-waf.com --debug
```

Check response:
- Status code (200 vs 400/403)
- Response headers (WAF headers)
- Response body (block message)

### **Dataset Not Found**

**Problem:** `Failed to load datasets: no such file or directory`

**Solution:**
```bash
# Verify dataset path
ls Data/Malicious/*.json
ls Data/Legitimate/*.json

# Or specify custom path
./waf-efficacy -u http://waf.com \
  -malicious /path/to/malicious \
  -legitimate /path/to/legitimate
```

## 🎯 Use Cases

1. **WAF Benchmarking:** Compare your WAF against industry datasets
2. **Rule Tuning:** Identify false positives to refine WAF rules
3. **Bypass Testing:** Find malicious payloads that bypass WAF
4. **Compliance:** Validate WAF effectiveness for security audits

## 📝 License

Apache 2.0

## 🤝 Contributing

Contributions welcome! Please open an issue or PR.
