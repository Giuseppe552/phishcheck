# PhishCheck — URL Phishing Detector
Client-side phishing analyzer in **HTML/CSS/JS**. No libraries, no tracking, no server.

**Live:** https://Giuseppe552.github.io/phishcheck/

### What it does
- Scores risk (0–100) with **transparent reasons**
- Flags: HTTP, IP-in-URL, “@” trick, many subdomains, heavy `%` encoding
- Detects **punycode/confusables**, **shorteners**, suspicious **TLDs**
- Simple **brand-typosquat** heuristic
- Shows **actionable tips**. All offline (privacy).

### Run
```bash
npx http-server -p 5174 -c-1 .
