# 🛡️ Smart Phishing & URL Analyzer

> Real-time AI-assisted phishing URL detection engine & dual-layered cybersecurity telemetry dashboard. Built using multi-agent asynchronous orchestration.

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Node.js](https://img.shields.io/badge/Node.js-v18+-green.svg)
![Express](https://img.shields.io/badge/Express-v4.18-lightgrey.svg)
![CSS3](https://img.shields.io/badge/Frontend-Glassmorphism-cyan.svg)

---

## 🌟 Overview

**Smart Phishing & URL Analyzer** is a full-stack cybersecurity application designed to analyze web links for phishing indicators, malicious subdomains, SSL anomalies, and credential harvesting patterns.

### 🎭 Dual-Persona Design
- **Normal User Mode (Default)**: Clean, intuitive interface presenting a normalized Risk Score (0-100), color-coded safety badge (Safe, Caution, High Risk), plain-English threat summary, and clear actionable recommendations.
- **Analyst Mode (Technical Deep-Dive)**: Expanded view exposing domain breakdown (protocol, subdomains, TLD, query parameters), Level 1 threat telemetry, simulated HTTP security headers, matched regex patterns, and raw collapsible JSON logs with one-click copy functionality.

---

## 📐 Architecture & Multi-Agent Workflow

```
                        ┌─────────────────────────────────┐
                        │      Client Web Dashboard       │
                        │    (Dual-Persona UI: User/      │
                        │      Analyst Deep-Dive)         │
                        └────────────────┬────────────────┘
                                         │
                                 HTTP POST /api/analyze
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │      Node.js Express Server     │
                        │        (Port 5000 / CORS)       │
                        └────────────────┬────────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │     Level 1 Security Engine     │
                        │  - Protocol & SSL Verification  │
                        │  - Subdomain Obfuscation Check  │
                        │  - Length & Query Heuristics    │
                        │  - Phishing Keyword Scans       │
                        └────────────────┬────────────────┘
                                         │
                                         ▼
                        ┌─────────────────────────────────┐
                        │     Dual-Layered JSON Output    │
                        │  ├── user_layer (Score/Summary) │
                        │  └── expert_layer (Telemetry)   │
                        └─────────────────────────────────┘
```

---

## ⚡ Level 1 Threat Detection Rules

1. **Protocol Inspection**: Flags unencrypted `http:` connections (-25 pts).
2. **Subdomain Obfuscation**: Detects excessive subdomains (> 2) and brand-impersonation tokens (`paypal`, `login`, `bank`, `secure`).
3. **URL Length & Payload**: Flags URLs exceeding 75 characters (MODERATE) and 100 characters (HIGH RISK), query parameter counts > 5, and `@` symbol obfuscation tricks.
4. **Phishing Keyword Engine**: Scans domain and URI paths against high-risk credential harvesting tokens (`login`, `verify`, `account`, `signin`, `banking`, `apple`, `google`, `microsoft`, `support`, `wallet`, `credential`, `token`, `update`, `auth`).

---

## 🚀 Getting Started

### Prerequisites
- Node.js (v16 or higher)
- npm

### Installation & Local Launch

1. **Clone the repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/smart-phishing-analyzer.git
   cd smart-phishing-analyzer
   ```

2. **Install Backend Dependencies**:
   ```bash
   cd backend
   npm install
   ```

3. **Start the Unified Server**:
   ```bash
   npm start
   ```

4. **Access the Dashboard**:
   Open your browser and navigate to `http://localhost:5000`.

---

## 📡 API Reference

### `POST /api/analyze`

**Request Body**:
```json
{
  "url": "http://login.paypal.verify-account.info/auth/signin?token=12345"
}
```

**Response Payload**:
```json
{
  "user_layer": {
    "risk_score": 55,
    "risk_level": "Caution",
    "summary": "Proceed with caution. The URL uses an unencrypted HTTP connection, which is less secure. Suspicious keywords often associated with phishing were found in the subdomains."
  },
  "expert_layer": {
    "domain_breakdown": {
      "protocol": "http:",
      "hostname": "login.paypal.verify-account.info",
      "subdomain": "login.paypal",
      "domain": "verify-account",
      "tld": "info",
      "path": "/auth/signin",
      "query_params_count": 1
    },
    "telemetry": {
      "url_length": 63,
      "url_length_flag": "Safe",
      "https_valid": false,
      "ssl_simulated_status": "Insecure",
      "suspicious_subdomains_detected": true,
      "phishing_keywords_found": ["login", "paypal", "verify", "account", "signin", "token", "auth"],
      "regex_matches": [],
      "simulated_http_headers": {
        "x-frame-options": "SAMEORIGIN",
        "strict-transport-security": "none"
      }
    }
  }
}
```

---

## 🌐 Deployment Options

### Deploy to Vercel
1. Install Vercel CLI: `npm i -g vercel`
2. Run `vercel` in the project root directory.

### Deploy to Render
1. Connect your GitHub repository to Render.
2. Select **Web Service**.
3. Set Build Command: `cd backend && npm install`
4. Set Start Command: `cd backend && node server.js`

---

## 📄 License
This project is licensed under the MIT License.
