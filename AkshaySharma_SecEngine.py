import ssl
import socket
import datetime
import re
from urllib.parse import urlparse

import requests
import urllib3
from flask import Flask, request, jsonify, render_template

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('index.html')


# ---------------------------------------------------------------------------
# Endpoint 1 — Security Headers + SSL
# ---------------------------------------------------------------------------

SECURITY_HEADERS = [
    {
        'key': 'Strict-Transport-Security',
        'label': 'HSTS',
        'remediation': "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;",
    },
    {
        'key': 'Content-Security-Policy',
        'label': 'CSP',
        'remediation': 'add_header Content-Security-Policy "default-src \'self\';" always;',
    },
    {
        'key': 'X-Frame-Options',
        'label': 'X-Frame-Options',
        'remediation': "add_header X-Frame-Options 'SAMEORIGIN' always;",
    },
    {
        'key': 'X-Content-Type-Options',
        'label': 'X-Content-Type-Options',
        'remediation': "add_header X-Content-Type-Options 'nosniff' always;",
    },
    {
        'key': 'Referrer-Policy',
        'label': 'Referrer-Policy',
        'remediation': "add_header Referrer-Policy 'strict-origin-when-cross-origin' always;",
    },
    {
        'key': 'Permissions-Policy',
        'label': 'Permissions-Policy',
        'remediation': "add_header Permissions-Policy 'geolocation=(), microphone=()' always;",
    },
]


def _get_ssl_info(hostname):
    """Return dict with SSL certificate details or an error message."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        not_after_raw = cert.get('notAfter', '')
        expiry_dt = datetime.datetime.strptime(not_after_raw, '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry_dt - datetime.datetime.utcnow()).days

        issuer = {}
        for rdn in cert.get('issuer', []):
            for k, v in rdn:
                issuer[k] = v
        issuer_org = issuer.get('organizationName', issuer.get('O', 'Unknown'))

        return {
            'valid': True,
            'expires': not_after_raw,
            'days_remaining': days_left,
            'issuer': issuer_org,
        }
    except Exception as exc:
        return {'valid': False, 'error': str(exc)}


@app.route('/api/scan-headers', methods=['POST'])
def scan_headers():
    try:
        data = request.get_json(force=True)
        url = data.get('url', '').strip()

        if not url.startswith('http://') and not url.startswith('https://'):
            url = 'https://' + url

        hostname = urlparse(url).hostname or ''

        resp = requests.get(
            url,
            timeout=6,
            headers={'User-Agent': 'SecEngine-Auditor/1.0'},
            verify=False,
        )

        headers_report = []
        header_score = 0
        for hdr in SECURITY_HEADERS:
            present = hdr['key'] in resp.headers
            if present:
                header_score += 10
            headers_report.append({
                'key': hdr['key'],
                'label': hdr['label'],
                'present': present,
                'value': resp.headers.get(hdr['key'], ''),
                'remediation': hdr['remediation'],
            })

        ssl_info = _get_ssl_info(hostname)
        ssl_score = 40 if ssl_info.get('valid') else 0

        score = header_score + ssl_score

        if score >= 90:
            grade = 'A+'
        elif score >= 80:
            grade = 'A'
        elif score >= 70:
            grade = 'B'
        elif score >= 60:
            grade = 'C'
        elif score >= 50:
            grade = 'D'
        else:
            grade = 'F'

        headers_present = sum(1 for h in headers_report if h['present'])
        summary = (
            f"{headers_present}/6 security headers present. "
            f"SSL {'valid' if ssl_info.get('valid') else 'invalid/missing'}. "
            f"Overall score: {score}/100 (Grade {grade})."
        )

        return jsonify({
            'success': True,
            'score': score,
            'grade': grade,
            'ssl_info': ssl_info,
            'headers_report': headers_report,
            'summary': summary,
        })

    except Exception as exc:
        return jsonify({'success': False, 'error': str(exc)})


# ---------------------------------------------------------------------------
# Endpoint 2 — Phishing URL Inspector
# ---------------------------------------------------------------------------

BRAND_KEYWORDS = [
    'paypal', 'google', 'amazon', 'netflix', 'sbi', 'microsoft', 'apple', 'facebook',
]
SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.work', '.loan', '.click', '.fit', '.gq'}
PHISHING_KEYWORDS = ['login', 'verify', 'kyc', 'banking', 'secure', 'update', 'account', 'claim']


@app.route('/api/scan-phishing-url', methods=['POST'])
def scan_phishing_url():
    data = request.get_json(force=True)
    url = data.get('url', '').strip()

    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    parsed = urlparse(url)
    hostname = (parsed.hostname or '').lower()
    full_url_lower = url.lower()

    risk = 0
    indicators = []

    # 1. Direct IP address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
        risk += 35
        indicators.append('Host is a raw IP address (no domain name)')

    # 2. Brand impersonation / typosquatting
    OFFICIAL_DOMAINS = {
        'paypal': ['paypal.com'],
        'google': ['google.com', 'google.co.in'],
        'amazon': ['amazon.com', 'amazon.in'],
        'netflix': ['netflix.com'],
        'sbi': ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'],
        'microsoft': ['microsoft.com'],
        'apple': ['apple.com'],
        'facebook': ['facebook.com'],
    }

    for brand in BRAND_KEYWORDS:
        if brand in hostname:
            # Check if it's the legitimate official domain or a subdomain
            official_list = OFFICIAL_DOMAINS.get(brand, [f'{brand}.com'])
            is_legit = any(hostname == dom or hostname.endswith('.' + dom) for dom in official_list)
            if not is_legit:
                risk += 40
                indicators.append(f'Brand impersonation detected: "{brand}" found in unofficial domain')
                break

    # 3. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            risk += 25
            indicators.append(f'Suspicious TLD detected: {tld}')
            break

    # 4. Phishing keywords in URL
    found_kw = [kw for kw in PHISHING_KEYWORDS if kw in full_url_lower]
    if found_kw:
        risk += 20
        indicators.append(f'Phishing keywords in URL: {", ".join(found_kw)}')

    # 5. Structural anomalies
    structural_issues = []
    if hostname.count('-') >= 2:
        structural_issues.append('multiple hyphens in domain')
    if '@' in url:
        structural_issues.append('@ symbol in URL')
    if hostname.count('.') >= 3:
        structural_issues.append('excessive subdomains (3+ dots)')
    if structural_issues:
        risk += 15
        indicators.append(f'Structural anomalies: {", ".join(structural_issues)}')

    score = min(risk, 100)

    if score < 30:
        level = 'SAFE'
    elif score <= 65:
        level = 'MODERATE RISK'
    else:
        level = 'CRITICAL PHISHING RISK'

    return jsonify({
        'success': True,
        'score': score,
        'level': level,
        'indicators': indicators,
    })


# ---------------------------------------------------------------------------
# Endpoint 3 — Phishing Email / SMS Text Scanner
# ---------------------------------------------------------------------------

URGENCY_PHRASES = ['urgent', 'suspended', '24 hours', 'action required', 'immediately', 'blocked']
FINANCIAL_LURES = ['lottery', 'won', 'cashback', 'prize', 'refund', 'bonus', 'claim now']
CREDENTIAL_HARVESTING = ['enter otp', 'share password', 'verify pin', 'update kyc', 'cvv']
SHORTENED_URL_DOMAINS = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'rb.gy']


@app.route('/api/scan-phishing-text', methods=['POST'])
def scan_phishing_text():
    data = request.get_json(force=True)
    text = data.get('text', '').strip()
    text_lower = text.lower()

    risk = 0
    detected_categories = []

    # Urgency
    found_urgency = [p for p in URGENCY_PHRASES if p in text_lower]
    if found_urgency:
        risk += 30
        detected_categories.append({
            'category': 'Urgency / Fear Tactics',
            'matches': found_urgency,
        })

    # Financial lure
    found_lure = [p for p in FINANCIAL_LURES if p in text_lower]
    if found_lure:
        risk += 30
        detected_categories.append({
            'category': 'Financial Lure / Reward Bait',
            'matches': found_lure,
        })

    # Credential harvesting
    found_cred = [p for p in CREDENTIAL_HARVESTING if p in text_lower]
    if found_cred:
        risk += 40
        detected_categories.append({
            'category': 'Credential Harvesting',
            'matches': found_cred,
        })

    # URL extraction + shortened URL check
    urls_in_text = re.findall(r'https?://[^\s]+', text, re.IGNORECASE)
    shortened = [u for u in urls_in_text if any(d in u.lower() for d in SHORTENED_URL_DOMAINS)]
    if shortened:
        risk = min(risk + 20, 100)
        detected_categories.append({
            'category': 'Shortened / Obfuscated URLs',
            'matches': shortened,
        })

    score = min(risk, 100)

    if score < 30:
        risk_level = 'LOW RISK'
        advice = 'This message appears safe. No major phishing signals detected.'
    elif score <= 65:
        risk_level = 'MODERATE RISK'
        advice = 'Exercise caution. Do not click links or share personal information without verifying the sender.'
    else:
        risk_level = 'HIGH RISK — LIKELY PHISHING'
        advice = 'Do NOT interact with this message. Block the sender and report it as phishing immediately.'

    return jsonify({
        'success': True,
        'score': score,
        'risk_level': risk_level,
        'detected_categories': detected_categories,
        'urls_found': urls_in_text,
        'advice': advice,
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True, port=5000)
