# 🛡️ PhishGuard

### Defensive URL Analysis · Phishing Indicators · Web Security

PhishGuard is a lightweight Flask web application that analyzes URLs for common phishing indicators without automatically visiting the destination.

## Features

- URL normalization and validation
- HTTPS detection
- IP-based URL detection
- Embedded credential detection
- Suspicious keyword detection
- Deep-subdomain detection
- IDN/punycode indicators
- URL-shortener detection
- Unusually long URL detection
- Encoded-character detection
- Simple 0–100 heuristic risk score
- Clean responsive dashboard

## Tech Stack

- Python
- Flask
- HTML/CSS
- Jinja2

## Run Locally

```bash
git clone https://github.com/btwsalts/phishguard.git
cd phishguard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open **http://127.0.0.1:5000**.

## How It Works

The analyzer parses the URL locally and checks structural characteristics. Each indicator contributes a small heuristic weight to the final score.

### Example

`http://192.0.2.10/login/verify`

may trigger multiple indicators such as:

- HTTP instead of HTTPS
- raw IP address
- credential-related keywords

The result is presented as LOW, MEDIUM, or HIGH risk.

## Important Limitations

PhishGuard is an educational heuristic analyzer. A risk score does **not** prove that a URL is malicious or safe. It does not crawl pages, submit credentials, bypass protections, or automatically interact with destinations.

## Roadmap

- DNS and domain metadata checks
- Safe redirect-chain inspection
- Reputation API integrations
- Screenshot-based page inspection
- Batch URL analysis
- CSV/JSON reports
- Analysis history
- Unit tests
- Docker support

## Security Note

Only analyze URLs in contexts where you are authorized to do so. Treat suspicious links as untrusted and do not enter credentials into unknown websites.

## Author

Built by **btwsalts** as a cybersecurity and software-engineering learning project.
