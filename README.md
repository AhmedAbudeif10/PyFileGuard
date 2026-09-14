# PyFileGuard 🛡️

A Python-based static file security analyzer designed for educational cybersecurity research.

## 🔍 Features

- MD5, SHA-1 and SHA-256 hash calculation
- Shannon entropy analysis
- Suspicious file extension detection
- Double extension detection
- Suspicious command/script keyword detection
- URL detection
- IPv4 address detection
- Base64-like data detection
- Explainable risk scoring system
- JSON security reports
- Static analysis without executing files

## ⚙️ How It Works

PyFileGuard analyzes a file without executing it.

It checks the file for multiple indicators that may be associated with suspicious files and calculates a risk score from `0` to `100`.

### Risk Levels

| Score | Verdict |
|---|---|
| 0–19 | LOW |
| 20–49 | MEDIUM |
| 50–79 | HIGH |
| 80–100 | CRITICAL |

## 🚀 Usage

Run the analyzer from a terminal:

```bash
python "PyFileGuard.py" "sample.txt"
