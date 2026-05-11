from flask import Flask, render_template, request
import ssl
import socket
from datetime import datetime

app = Flask(__name__)

def check_ssl(url):
    # Remove http:// or https:// and get domain
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

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    result = check_ssl(url)
    
    if result['error']:
        ssl_status = f"❌ Error: {result['error']}"
    elif result['valid']:
        ssl_status = f"✅ Valid SSL certificate (expires {result['expiry']}, issuer: {result['issuer']})"
    else:
        ssl_status = f"⚠️ SSL certificate expired on {result['expiry']}"
    
    return f"""
    <h1>SSL Check for {url}</h1>
    <p>{ssl_status}</p>
    <a href="/">Back</a>
    """

if __name__ == '__main__':
    app.run(debug=True)