from flask import Flask, render_template, request
import ssl
import socket
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

app = Flask(__name__)

# ---------- 1. SSL CHECK ----------
def check_ssl(url):
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                is_valid = expiry_date > datetime.now()
                return {
                    'valid': is_valid,
                    'expiry': expiry_date.strftime('%Y-%m-%d'),
                    'issuer': dict(x[0] for x in cert['issuer']).get('organizationName', 'Unknown'),
                    'error': None
                }
    except socket.timeout:
        return {'valid': False, 'expiry': None, 'issuer': None, 'error': 'Connection timed out'}
    except socket.gaierror:
        return {'valid': False, 'expiry': None, 'issuer': None, 'error': 'Invalid domain or DNS resolution failed'}
    except Exception as e:
        return {'valid': False, 'expiry': None, 'issuer': None, 'error': str(e)}

# ---------- 2. HTTPS REDIRECT CHECK ----------
def check_https_redirect(url):
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    try:
        http_response = requests.get(f'http://{domain}', timeout=5, allow_redirects=False)
        if http_response.status_code in [301, 302]:
            location = http_response.headers.get('Location', '')
            if 'https://' in location:
                return {'status': '✅', 'message': 'Redirects HTTP → HTTPS'}
            else:
                return {'status': '⚠️', 'message': 'Redirects, but not to HTTPS'}
        else:
            return {'status': '⚠️', 'message': 'Does not redirect; serves HTTP directly'}
    except requests.ConnectionError:
        return {'status': '❌', 'message': 'Site unreachable'}
    except Exception as e:
        return {'status': '❌', 'message': f'Error: {str(e)}'}

# ---------- 3. SECURITY HEADERS CHECK ----------
def check_security_headers(url):
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    try:
        response = requests.get(f'https://{domain}', timeout=5)
        headers = response.headers
        hsts = headers.get('Strict-Transport-Security', 'Not set')
        csp = headers.get('Content-Security-Policy', 'Not set')
        xframe = headers.get('X-Frame-Options', 'Not set')
        
        score = 0
        if hsts != 'Not set': score += 1
        if csp != 'Not set': score += 1
        if xframe != 'Not set': score += 1
        
        if score == 3:
            status = '✅'
            msg = 'All key security headers present'
        elif score >= 1:
            status = '⚠️'
            msg = f'Missing some headers (HSTS: {hsts[:30]}, CSP: {csp[:30]}, XFO: {xframe})'
        else:
            status = '❌'
            msg = 'No security headers found'
        
        return {'status': status, 'message': msg, 'hsts': hsts, 'csp': csp, 'xframe': xframe}
    except:
        return {'status': '❌', 'message': 'Could not retrieve headers', 'hsts': 'Error', 'csp': 'Error', 'xframe': 'Error'}

# ---------- 4. PRIVACY POLICY DETECTION ----------
def check_privacy_policy(url):
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    try:
        response = requests.get(f'https://{domain}', timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        # Look for links containing 'privacy' in text or href
        privacy_links = soup.find_all('a', href=True)
        for link in privacy_links:
            text = link.get_text().lower()
            href = link['href'].lower()
            if 'privacy' in text or 'privacy' in href:
                return {'status': '✅', 'message': 'Privacy policy link found'}
        return {'status': '⚠️', 'message': 'No obvious privacy policy link on homepage'}
    except Exception as e:
        return {'status': '❌', 'message': f'Error: {str(e)}'}

# ---------- 5. MISSING ALT TEXT CHECK (Accessibility) ----------
def check_alt_text(url):
    domain = url.replace('https://', '').replace('http://', '').split('/')[0]
    try:
        response = requests.get(f'https://{domain}', timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        images = soup.find_all('img')
        missing_alt = [img for img in images if not img.get('alt')]
        total = len(images)
        missing_count = len(missing_alt)
        if total == 0:
            return {'status': '✅', 'message': 'No images found (no alt issues)'}
        elif missing_count == 0:
            return {'status': '✅', 'message': f'All {total} images have alt text'}
        else:
            return {'status': '⚠️', 'message': f'{missing_count} out of {total} images missing alt text'}
    except Exception as e:
        return {'status': '❌', 'message': f'Error: {str(e)}'}

# ---------- HOMEPAGE ----------
@app.route('/')
def index():
    return render_template('index.html')

# ---------- SCAN ROUTE (collects all checks) ----------
@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    
    results = {
        'ssl': check_ssl(url),
        'redirect': check_https_redirect(url),
        'headers': check_security_headers(url),
        'privacy': check_privacy_policy(url),
        'alttext': check_alt_text(url)
    }
    
    return render_template('result.html', url=url, results=results)

# ---------- RUN ----------
if __name__ == '__main__':
    app.run(debug=True)