# 🔍 LOG ANALYZER - XE105

Welcome to **Log Analyzer**, a Python-based tool developed as part of the **ThinkCyber Python Fundamentals (XE105)** project. This script scans and extracts valuable insights from `/var/log/auth.log` (or any specified `auth.log` file) for security auditing, system behavior monitoring, and incident response.

---

## 📌 Project Overview

**🎯 Objective:**  
Transform raw system authentication logs into structured, readable insights that reveal:

- Command usage
- User account changes
- Privilege escalation attempts
- Failed sudo authentications
- Brute-force attacks
- Unexpected logins
- Unusual or potentially malicious command executions

**📚 Developed As Part Of:**  
- **Program:** Python Fundamentals  
- **Class Code:** RTX  
- **Student:** Shimon  
- **Unit Code:** XE105  

---

## ⚙️ Features

- 🔐 Root and passcode authentication (`password = mrsuda`)  
- 📁 Dynamic `auth.log` file selection (manual or automatic)  
- 📝 Output saved in a well-formatted `.log` report  
- 👀 Optional preview of results after scan  
- ⛔ Graceful handling of `CTRL+C` interruptions  
- 🎨 Color-coded terminal UI for better UX  
- 📊 Organized and readable section formatting  

---

## 🧪 What It Analyzes

| Section				| Description							|
|---------------------------------------|---------------------------------------------------------------|
| **COMMAND USAGE**			| Logs terminal command executions with timestamp & user	|
| **USER ACCOUNT CHANGES**		| Detects added, deleted, or failed user creation attempts	|
| **PASSWORD CHANGES**			| Logs all user password changes				|
| **PRIVILEGE ESCALATION**		| Captures `sudo` and `su` usage patterns			|
| **SUDO FAILURES**			| Identifies failed `sudo` attempts				|
| **BRUTE FORCE ATTEMPTS**		| Detects failed SSH login attempts				|
| **UNEXPECTED LOGIN LOCATIONS**	| Flags successful logins from unfamiliar IPs			|
| **UNUSUAL COMMAND EXECUTIONS**	| Highlights potentially dangerous commands			|

---

## 📁 File Structure

```text
log-analyzer/
├── LOG_ANALYZER.py           # Main Python script
├── LOG_ANALYZER_PDF.pdf      # Project report (submission-ready)
├── Log_Analyzer_Report.log   # Generated after script execution
└── README.md                 # You're reading it :)
