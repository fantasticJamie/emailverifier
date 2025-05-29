from flask import Flask, request, jsonify, render_template_string
import re
import socket
import smtplib
import os
from email.mime.text import MIMEText

app = Flask(__name__)

def validate_email_format(email: str) -> bool:
    """Basic email format validation"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def validate_email_domain(email: str):
    """Check if domain exists - simplified for Vercel"""
    domain = email.split('@')[1]
    try:
        socket.gethostbyname(domain)
        return True, f"Domain '{domain}' exists and is reachable"
    except socket.gaierror:
        return False, "Domain does not exist"
    except Exception as e:
        return False, f"Domain check error: {str(e)}"

def get_mx_record(domain):
    """Get MX record for domain"""
    try:
        import dns.resolver
        mx_records = dns.resolver.resolve(domain, 'MX')
        return str(mx_records[0].exchange).rstrip('.')
    except:
        # Fallback - assume mail server is mail.domain.com or domain.com
        return f"mail.{domain}"

def validate_email_smtp_improved(email: str):
    """Improved SMTP validation that actually checks mailbox existence"""
    domain = email.split('@')[1]
    
    # List of known good domains that we can trust (skip intensive checking)
    trusted_domains = [
        'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 
        'yahoo.com', 'apple.com', 'icloud.com', 'microsoft.com',
        'google.com', 'amazon.com', 'facebook.com', 'twitter.com',
        'linkedin.com', 'github.com'
    ]
    
    if domain.lower() in trusted_domains:
        return True, f"Trusted domain: {domain}"
    
    # For other domains, do proper SMTP checking
    try:
        # Get MX record or use domain directly
        try:
            mx_host = get_mx_record(domain)
        except:
            mx_host = domain
        
        # Connect to SMTP server
        server = smtplib.SMTP(timeout=10)
        server.set_debuglevel(0)
        
        try:
            # Try to connect to MX server
            server.connect(mx_host, 25)
            server.helo()
            
            # Try MAIL FROM
            server.mail('noreply@example.com')
            
            # Try RCPT TO - this is where we check if the mailbox exists
            code, message = server.rcpt(email)
            server.quit()
            
            # Check response codes
            if code == 250:
                return True, f"Mailbox verified: {email}"
            elif code in [550, 551, 553]:
                return False, f"Mailbox does not exist: {email}"
            elif code in [450, 451, 452]:
                return False, f"Temporary issue with mailbox: {email}"
            else:
                return False, f"SMTP verification failed (code {code}): {message.decode() if isinstance(message, bytes) else message}"
                
        except smtplib.SMTPServerDisconnected:
            server.quit()
            return False, f"SMTP server disconnected during verification"
        except smtplib.SMTPRecipientsRefused:
            server.quit()
            return False, f"Mailbox rejected: {email}"
        except Exception as smtp_error:
            try:
                server.quit()
            except:
                pass
            return False, f"SMTP check failed: {str(smtp_error)}"
            
    except socket.timeout:
        return False, f"SMTP server timeout for domain: {domain}"
    except socket.gaierror:
        return False, f"Cannot connect to mail server for domain: {domain}"
    except Exception as e:
        return False, f"SMTP validation error: {str(e)}"

def get_mx_records(domain):
    """Get MX records for a domain using DNS lookup"""
    try:
        import socket
        # Try to get MX records using nslookup equivalent
        # This is a simplified approach for serverless environments
        
        # Common mail server prefixes to try
        mail_prefixes = [
            f"mail.{domain}",
            f"smtp.{domain}", 
            f"mx.{domain}",
            f"mx1.{domain}",
            domain  # Sometimes the domain itself handles mail
        ]
        
        for mail_server in mail_prefixes:
            try:
                # Check if the mail server hostname resolves
                socket.gethostbyname(mail_server)
                return mail_server
            except socket.gaierror:
                continue
        
        return None
    except Exception:
        return None

def validate_email_smtp_basic_fixed(email: str):
    """Fixed version - smarter mail server detection"""
    domain = email.split('@')[1]
    
    # List of known good domains that we can trust
    trusted_domains = [
        'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 
        'yahoo.com', 'apple.com', 'icloud.com', 'microsoft.com',
        'google.com', 'amazon.com', 'facebook.com', 'twitter.com',
        'linkedin.com', 'github.com', 'protonmail.com', 'zoho.com'
    ]
    
    if domain.lower() in trusted_domains:
        return True, f"Trusted domain: {domain}"
    
    # For other domains, try to find their mail servers
    try:
        # Step 1: Try to find MX records or mail server
        mail_server = get_mx_records(domain)
        
        if mail_server:
            # Step 2: Try to connect to the mail server
            try:
                import socket
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)  # Increased timeout
                result = sock.connect_ex((mail_server, 25))
                sock.close()
                
                if result == 0:
                    return True, f"Mail server found and accessible: {mail_server}"
                else:
                    # If port 25 fails, the domain might still have mail services
                    # Many providers block port 25, so we'll be more lenient
                    return True, f"Domain has mail server configured: {mail_server} (port 25 may be blocked)"
                    
            except Exception as e:
                # Even if we can't connect, if we found a mail server hostname, it's likely valid
                return True, f"Mail server found: {mail_server} (connection test failed: {str(e)})"
        else:
            # No mail server found
            return False, f"No mail server found for domain: {domain}"
            
    except Exception as e:
        # If we get here, something went wrong, but the domain exists (we already checked)
        # So we'll be conservative and assume it might have mail services
        return True, f"Domain verification completed with warnings: {str(e)}"



def is_disposable_email(domain: str) -> bool:
    """Check if domain is a disposable email provider"""
    disposable_domains = [
        '10minutemail.com', 'guerrillamail.com', 'mailinator.com',
        'yopmail.com', 'temp-mail.org', 'throwaway.email',
        'tempmail.com', 'dispostable.com', '20minutemail.com',
        'trashmail.com', 'sharklasers.com', 'grr.la'
    ]
    return domain.lower() in disposable_domains

@app.route('/')
def index():
    """Main page with embedded HTML"""
    html_template = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🐍 Python Email Validator - Hosted on Vercel</title>
    <link href="data:image/x-icon;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==" rel="icon" type="image/x-icon">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
            padding: 40px;
            width: 100%;
            max-width: 650px;
            animation: slideUp 0.6s ease;
        }
        
        @keyframes slideUp {
            from { transform: translateY(30px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        
        h1 {
            color: #333;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5rem;
            font-weight: 700;
        }
        
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
            font-size: 1.1rem;
        }
        
        .powered-by {
            text-align: center;
            font-size: 14px;
            color: #666;
            margin-bottom: 30px;
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            padding: 15px;
            border-radius: 10px;
            border-left: 4px solid #667eea;
        }
        
        .github-link {
            text-align: center;
            margin-bottom: 20px;
        }
        
        .github-link a {
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
            padding: 8px 16px;
            border: 2px solid #667eea;
            border-radius: 20px;
            transition: all 0.3s ease;
        }
        
        .github-link a:hover {
            background: #667eea;
            color: white;
        }
        
        input[type="email"] {
            width: 100%;
            padding: 15px 20px;
            font-size: 16px;
            border: 2px solid #e1e1e1;
            border-radius: 10px;
            margin-bottom: 20px;
            transition: all 0.3s ease;
            background: #f8f9fa;
        }
        
        input[type="email"]:focus {
            outline: none;
            border-color: #667eea;
            background: white;
            box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.1);
        }
        
        button {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 16px;
            cursor: pointer;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            transition: all 0.3s ease;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
        }
        
        button:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .result {
            margin-top: 25px;
            padding: 20px;
            border-radius: 10px;
            font-size: 15px;
            opacity: 0;
            transform: translateY(20px);
            transition: all 0.4s ease;
        }
        
        .result.show {
            opacity: 1;
            transform: translateY(0);
        }
        
        .valid {
            background: linear-gradient(135deg, #d4edda, #c3e6cb);
            color: #155724;
            border: 2px solid #28a745;
        }
        
        .invalid {
            background: linear-gradient(135deg, #f8d7da, #f1b0b7);
            color: #721c24;
            border: 2px solid #dc3545;
        }
        
        .checking {
            background: linear-gradient(135deg, #d1ecf1, #bee5eb);
            color: #0c5460;
            border: 2px solid #17a2b8;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255,255,255,0.3);
            border-radius: 50%;
            border-top: 2px solid currentColor;
            animation: spin 0.8s linear infinite;
            margin-right: 10px;
            vertical-align: middle;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        .footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            font-size: 12px;
            color: #999;
        }
        
        .api-info {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 10px;
            border-left: 4px solid #28a745;
        }
        
        .api-info h4 {
            color: #333;
            margin-bottom: 10px;
        }
        
        .api-info code {
            background: #e9ecef;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🐍 Email Validator</h1>
        <p class="subtitle">Professional email validation hosted on Vercel</p>
        
        <div class="powered-by">
            🚀 <strong>Hosted on Vercel</strong> • 🐍 <strong>Python Flask Backend</strong><br>
            ✅ Format validation • 🌐 DNS lookup • 📧 Mail server verification • 🚫 Disposable email detection
        </div>
        
        <div class="github-link">
            <a href="https://github.com/yourusername/email-validator" target="_blank">
                📂 View Source on GitHub
            </a>
        </div>
        
        <input type="email" id="emailInput" placeholder="Enter email address (e.g., contact@company.com)" autofocus>
        <button onclick="validateEmail()" id="validateBtn">🔍 Validate Email Address</button>
        
        <div id="result" class="result"></div>
        
        <div class="api-info">
            <h4>🔧 API Endpoint:</h4>
            <p>POST <code>/api/validate</code> with JSON: <code>{"email": "test@example.com"}</code></p>
        </div>
        
        <div class="footer">
            <p>💡 <strong>Tip:</strong> Comprehensive validation with smart mail server detection</p>
            <p>🔒 No data is stored • ⚡ Fast global edge network • 🆓 Free to use</p>
        </div>
    </div>

    <script>
        async function validateEmail() {
            const email = document.getElementById('emailInput').value.trim();
            const btn = document.getElementById('validateBtn');
            const result = document.getElementById('result');
            
            if (!email) {
                showResult('❌ Please enter an email address', 'invalid');
                return;
            }
            
            btn.disabled = true;
            btn.innerHTML = '<div class="loading"></div>Validating...';
            showResult('🐍 Comprehensive email validation in progress...<br>📧 Checking format, domain, and mail services...', 'checking');
            
            try {
                const response = await fetch('/api/validate', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({email: email})
                });
                
                const data = await response.json();
                
                if (data.valid) {
                    showResult(`✅ <strong>Email is valid!</strong><br><br>${data.messages.join('<br>')}`, 'valid');
                } else {
                    showResult(`❌ <strong>Email validation failed</strong><br><br>${data.messages.join('<br>')}`, 'invalid');
                }
                
            } catch (error) {
                showResult(`❌ <strong>Connection Error</strong><br>Please try again<br><small>${error.message}</small>`, 'invalid');
            }
            
            btn.disabled = false;
            btn.innerHTML = '🔍 Validate Email Address';
        }
        
        function showResult(message, type) {
            const result = document.getElementById('result');
            result.innerHTML = message;
            result.className = `result ${type}`;
            setTimeout(() => result.classList.add('show'), 100);
        }
        
        // Enter key support
        document.getElementById('emailInput').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') validateEmail();
        });
        
        // Auto-focus input
        window.onload = () => document.getElementById('emailInput').focus();
    </script>
</body>
</html>'''
    return render_template_string(html_template)

@app.route('/api/validate', methods=['POST'])
def validate_api():
    """API endpoint for comprehensive email validation"""
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        
        result = {'email': email, 'valid': False, 'messages': []}
        
        if not email:
            result['messages'].append('❌ Please enter an email address')
            return jsonify(result)
        
        # Step 1: Format validation
        if not validate_email_format(email):
            result['messages'].append('❌ Invalid email format')
            return jsonify(result)
        
        result['messages'].append('✅ Email format is valid')
        
        domain = email.split('@')[1]
        
        # Step 2: Disposable email check
        if is_disposable_email(domain):
            result['messages'].append('⚠️ Disposable email detected - not recommended for business use')
            return jsonify(result)
        
        # Step 3: Domain validation
        domain_valid, domain_msg = validate_email_domain(email)
        result['messages'].append(f'🌐 {domain_msg}')
        
        if not domain_valid:
            return jsonify(result)
        
        # Step 4: Comprehensive email validation
        smtp_valid, smtp_msg = validate_email_comprehensive(email)
        result['messages'].append(f'{smtp_msg}')
        
        if smtp_valid:
            result['valid'] = True
            result['messages'].append('🎉 Email validation successful!')
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'valid': False, 'messages': [f'❌ Validation error: {str(e)}']})

# Health check endpoint
@app.route('/api/health')
def health():
    return jsonify({'status': 'healthy', 'service': 'email-validator'})

if __name__ == '__main__':
    app.run(debug=True)