<div align="center">

<img src="static/logo.png" alt="SecEngine Logo" width="160"/>

# SecEngine

### Automated Web Security & Threat Detection Suite
**IBM SkillsBuild Cyber Security 2026 · Conducted by BharatCares**  
**Candidate Name:** Akshay Sharma | **Repository:** [CS-Bob-Project](https://github.com/AxeyTech/CS-Bob-Project)

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3+-000000?style=flat-square&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)]()
[![Free](https://img.shields.io/badge/Cost-100%25%20Free-blue?style=flat-square)]()

*Enterprise-grade cybersecurity tools — completely free, no account required.*

</div>

---

## Overview

**SecEngine** is a full-stack cybersecurity intelligence platform built with Python Flask. It provides three production-ready security analysis tools in a single, modern web interface:

| Tool | What it does |
|------|-------------|
| 🔍 **HTTP Security Audit** | Scans any domain for missing security headers and SSL/TLS certificate health. Scores out of 100 with grades A+ to F. |
| 🎣 **Phishing URL Inspector** | Detects brand impersonation, suspicious TLDs, raw IPs, and phishing keywords in URLs. Risk scored 0–100%. |
| 📨 **Email / SMS Scanner** | Identifies urgency tactics, financial lures, credential harvesting phrases, and shortened URLs in message text. |

---

## Screenshots

> Run `python app.py` and open `http://localhost:5000` to see the full interface.

The UI features an animated particle-network hero, live SOC dashboard preview, glassmorphism cards, threat intelligence world map, and animated scan result dashboards.

---

## Features

- ✅ **Zero account required** — open the browser, start scanning
- ✅ **3 REST API endpoints** — integrate with any CI/CD pipeline
- ✅ **Real-time results** — async fetch, no page reloads
- ✅ **Actionable remediation** — every missing header includes a ready-to-paste Nginx/Apache config fix
- ✅ **PDF export** — `window.print()` generates a clean professional audit report
- ✅ **Live SOC dashboard** — simulated real-time threat event feed with auto-updating metrics
- ✅ **Responsive design** — works on desktop, tablet, and mobile
- ✅ **100% free** — no tiers, no paywalls, no rate limits

---

## Dataset & Threat Intelligence Reference

SecEngine integrates heuristic datasets and corpora for evaluating web security and detecting social engineering threats:

| Dataset / Reference | Format | Description | Direct Link |
|---------------------|--------|-------------|-------------|
| **Phishing URLs Dataset** | JSON | Benchmark of benign vs. phishing URLs with threat classifications | [datasets/sample_phishing_urls.json](datasets/sample_phishing_urls.json) |
| **Phishing Messages Corpus** | JSON | Social engineering SMS & email templates categorized by psychological triggers | [datasets/sample_phishing_messages.json](datasets/sample_phishing_messages.json) |
| **OWASP Secure Headers** | Standard | OWASP Secure Headers Project specifications and recommended values | [OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) |
| **MITRE ATT&CK T1566** | Framework | Adversary tactics for Phishing (Spearphishing Link, Spearphishing Attachment) | [MITRE ATT&CK T1566](https://attack.mitre.org/techniques/T1566/) |

---

## Submission Deliverables (IBM SkillsBuild & BharatCares)

This project satisfies all requirements for the IBM SkillsBuild Cyber Security 2026 submission:

- 📁 **Code File**: [`AkshaySharma_SecEngine.ipynb`](AkshaySharma_SecEngine.ipynb) (Interactive Jupyter Notebook) & [`AkshaySharma_SecEngine.py`](AkshaySharma_SecEngine.py)
- 📋 **Requirements File**: [`requirements.txt`](requirements.txt)
- 📄 **Project Report**: [`AkshaySharma_ProjectReport.docx`](AkshaySharma_ProjectReport.docx) (Microsoft Word format)
- 📖 **README File**: [`README.md`](README.md) (Markdown format)

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.10+, Flask 2.3+ |
| HTTP Client | Requests 2.31+ |
| SSL Inspection | Python `ssl`, `socket` (stdlib) |
| Pattern Matching | Python `re` (stdlib) |
| Frontend | HTML5, CSS3, Vanilla JavaScript (ES5) |
| Typography | Plus Jakarta Sans, JetBrains Mono |
| Icons | Font Awesome 6 |

---

## Getting Started

### Prerequisites

- Python 3.10 or higher
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/AxeyTech/CS-Bob-Project.git
cd CS-Bob-Project

# 2. (Optional) Create a virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the app
python app.py
```

### Open in Browser

```
http://localhost:5000
```

---

## API Reference

All endpoints accept `Content-Type: application/json` via `POST`.

### `POST /api/scan-headers`

Scans a domain for HTTP security headers and SSL certificate health.

**Request**
```json
{ "url": "https://example.com" }
```

**Response**
```json
{
  "success": true,
  "score": 100,
  "grade": "A+",
  "ssl_info": {
    "valid": true,
    "expires": "Mar 15 12:00:00 2026 GMT",
    "days_remaining": 142,
    "issuer": "DigiCert Inc"
  },
  "headers_report": [
    {
      "key": "Strict-Transport-Security",
      "label": "HSTS",
      "present": true,
      "value": "max-age=31536000; includeSubDomains",
      "remediation": "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;"
    }
  ],
  "summary": "6/6 security headers present. SSL valid. Overall score: 100/100 (Grade A+)."
}
```

---

### `POST /api/scan-phishing-url`

Analyzes a URL for phishing indicators using heuristic analysis.

**Request**
```json
{ "url": "http://suspicious-paypal-secure.xyz/verify" }
```

**Response**
```json
{
  "success": true,
  "score": 85,
  "level": "CRITICAL PHISHING RISK",
  "indicators": [
    "Brand impersonation detected: \"paypal\" found in unofficial domain",
    "Suspicious TLD detected: .xyz",
    "Phishing keywords in URL: verify"
  ]
}
```

---

### `POST /api/scan-phishing-text`

Scans email or SMS text for social engineering patterns.

**Request**
```json
{ "text": "URGENT! Your SBI account has been suspended. Enter OTP immediately: http://bit.ly/verify-now" }
```

**Response**
```json
{
  "success": true,
  "score": 90,
  "risk_level": "HIGH RISK — LIKELY PHISHING",
  "detected_categories": [
    { "category": "Urgency / Fear Tactics", "matches": ["urgent", "suspended", "immediately"] },
    { "category": "Credential Harvesting", "matches": ["enter otp"] },
    { "category": "Shortened / Obfuscated URLs", "matches": ["http://bit.ly/verify-now"] }
  ],
  "urls_found": ["http://bit.ly/verify-now"],
  "advice": "Do NOT interact with this message. Block the sender and report it as phishing immediately."
}
```

---

## Scoring Logic

### Security Header Audit

| Component | Points |
|-----------|--------|
| Strict-Transport-Security (HSTS) | 10 |
| Content-Security-Policy (CSP) | 10 |
| X-Frame-Options | 10 |
| X-Content-Type-Options | 10 |
| Referrer-Policy | 10 |
| Permissions-Policy | 10 |
| Valid SSL Certificate | 40 |
| **Total** | **100** |

| Score | Grade | Rating |
|-------|-------|--------|
| 90–100 | A+ | Excellent |
| 80–89 | A | Very Good |
| 70–79 | B | Good |
| 60–69 | C | Fair |
| 50–59 | D | Poor |
| < 50 | F | Critical |

### Phishing URL Risk

| Check | Risk Added |
|-------|-----------|
| Raw IP address as hostname | +35 |
| Brand impersonation (unofficial domain) | +40 |
| Suspicious TLD (.xyz, .tk, .top, etc.) | +25 |
| Phishing keywords in URL | +20 |
| Structural anomalies (hyphens, @, subdomain abuse) | +15 |

Score is capped at **100%**. Classification: `SAFE` (0–29) · `MODERATE RISK` (30–65) · `CRITICAL PHISHING RISK` (66–100).

---

## Project Structure

```
SecEngine/
├── app.py                  # Flask application & all API endpoints
├── requirements.txt        # Python dependencies (3 packages)
├── README.md               # This file
├── static/
│   └── logo.png            # SecEngine favicon / brand logo
└── templates/
    └── index.html          # Complete single-page frontend (HTML + CSS + JS)
```

---

## Security Headers Reference

| Header | Attack Prevented | Recommended Value |
|--------|-----------------|-------------------|
| `Strict-Transport-Security` | SSL Stripping, MITM | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | XSS, Data Injection | `default-src 'self';` |
| `X-Frame-Options` | Clickjacking | `SAMEORIGIN` |
| `X-Content-Type-Options` | MIME Sniffing | `nosniff` |
| `Referrer-Policy` | Information Leakage | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Feature Abuse | `geolocation=(), microphone=()` |

---

## License

This project is licensed under the **MIT License** — free to use, modify, and distribute.

---

## Disclaimer

SecEngine is intended for **educational and authorized security testing purposes only**. Only scan domains and URLs that you own or have explicit permission to test. The authors are not responsible for any misuse of this tool.

---

<div align="center">

Built with ❤️ for the cybersecurity community · © 2026 SecEngine

</div>
