# 🧨 NoSec — Intentionally Vulnerable Web App

> A deliberately insecure Node.js + Express app for learning and practicing web application security vulnerabilities.  
> Built for ethical hackers, CTF players, and bug bounty hunters.

---

## 🚀 Overview

**NoSec** is a minimal, front-end styled vulnerable web app designed to simulate real-world bugs in a safe environment.  
You can exploit vulnerabilities like **JWT manipulation**, **XSS**, **File Upload RCE**, **IDOR**, **SSRF**, and more — all in one simple Node.js app.

---

## ⚙️ Tech Stack

- **Backend:** Node.js + Express
- **Frontend:** HTML + CSS (vanilla)
- **Auth:** JWT (intentionally weak)
- **No Database:** All logic is file/memory-based for simplicity

---

## 💣 Vulnerabilities Included

| # | Vulnerability         | Path                          | Status |
|---|------------------------|-------------------------------|--------|
| 1 | 🔐 JWT Token Tampering | `/login` → `/admin`           | ✅     |
| 2 | 🔓 IDOR                | `/profile?user=admin`         | ✅     |
| 3 | 🧨 OS Command Injection| `/os-command?host=...`        | ✅     |
| 4 | 📤 File Upload         | `/upload` + `/uploads/file`   | ✅     |
| 5 | 🌐 SSRF                | `/ssrf?url=...`               | ✅     |
| 6 | 🚫 403 Bypass          | Directly access protected pages| ✅     |
| 7 | 📝 XSS (Stored)        | Upload `.html`/`.svg` files   | ✅     |

---

## 🛠️ Setup Instructions

### 1. Clone the repo
```bash
git clone https://github.com/yourusername/nosec.git
cd nosec
