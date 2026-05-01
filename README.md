# HeaderShield

A web security analysis tool that evaluates HTTP headers, cookies, and TLS configuration to identify risks and provide actionable fixes.

---

## Live Demo

[Open HeaderShield](https://headershield.onrender.com)

---

## Features

- Security header analysis (CSP, HSTS, X-Frame, etc.)
- Cookie security checks (HttpOnly, Secure, SameSite)
- TLS / HTTPS inspection
- Vulnerability detection with severity levels
- Scan intelligence (response size, redirects, timing)
- Downloadable PDF reports

---

## Disclaimer

This analysis is based on HTTP response data and provides a surface-level assessment.  
It should not be considered a full security audit.

---

## Tech Stack

- Python (Flask)
- HTML, CSS (Bootstrap 5)
- JavaScript
- pdfkit (for report generation)

---

## Installation (Local)

```bash
git clone https://github.com/paulouseph/headershield.git
cd headershield
pip install -r requirements.txt
python app.py
