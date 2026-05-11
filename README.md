# SafeScan – Website Security & Compliance Checker

SafeScan is a free, open‑source tool that helps small businesses and developers check if their website is secure, legally compliant, and accessible.  

It scans a given URL for **SSL validity**, **HTTPS redirects**, **security headers**, **privacy policy links**, and **image alt text** – giving you a clear, colour‑coded report with actionable insights.

## Live Demo

🔗 [SafeScan on Render](https://safescan-bfub.onrender.com)

> *The free instance may spin down after inactivity. The first request might take ~30 seconds to wake up.*

## Features

- ✅ **SSL Certificate** – validity, expiry date, issuer  
- 🔒 **HTTPS Redirect** – ensures HTTP automatically redirects to HTTPS  
- 🛡️ **Security Headers** – checks HSTS, CSP, X‑Frame‑Options  
- 📜 **Privacy Policy** – detects a privacy policy link on the homepage  
- 🖼️ **Image Alt Text** – accessibility check for missing `alt` attributes  

All checks are presented in a clean, responsive report with pass/warn/fail indicators.

## How to Run Locally

1. **Clone the repository**
   ```bash
   git clone https://github.com/tejabdhhskas-a11y/SafeScan.git
   cd SafeScan
