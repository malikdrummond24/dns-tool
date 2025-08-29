# dnswatch (macOS) – DNS Cache Monitor with VirusTotal + Alerts

## 📌 Overview
`dnswatch` is a Python-based DNS cache monitoring and threat detection tool.  
It collects DNS lookups from macOS logs, stores them in SQLite, and checks each domain/IP against the VirusTotal API.  
If malicious activity is detected, alerts can be sent via Slack or Discord in real-time.  

This project demonstrates applied knowledge of **Python, networking, security, APIs, and automation**. It is designed as a lightweight threat detection tool for educational and research purposes.  

---

## ✨ Features
- Collects recent DNS lookups on macOS
- Stores results in **SQLite** for analysis
- Integrates with **VirusTotal API** to detect malicious domains/IPs
- Sends alerts via **Slack/Discord webhooks**
- Supports **manual runs** and **continuous monitoring** with custom intervals
- Easy to configure via `.env` file  

---

## 🚀 Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/dns-tool.git
cd dns-tool
