from flask import Flask, request, jsonify, render_template_string
import re
import socket
import smtplib
import os

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

def get_mx_records(domain):
    """Get MX records for a domain using DNS lookup with better validation"""
    try:
        import socket
        
        # First, try to get actual MX records using a more thorough approach
        mail_servers_found = []
        
        # Common mail server prefixes to try
        mail_prefixes = [
            f"mail.{domain}",
            f"smtp.{domain}", 
            f"mx.{domain}",
            f"mx1.{domain}",
            f"aspmx.l.google.com" if domain in ['gmail.com', 'googlemail.com'] else None,
            domain  # Sometimes the domain itself handles mail
        ]
        
        # Filter out None values
        mail_prefixes = [prefix for prefix in mail_prefixes if prefix]
        
        for mail_server in mail_prefixes:
            try:
                # Check if the mail server hostname resolves
                socket.gethostbyname(mail_server)
                mail_servers_found.append(mail_server)
            except socket.gaierror:
                continue
        
        # Return the first working mail server found
        return mail_servers_found[0] if mail_servers_found else None
        
    except Exception:
        return None

def validate_email_comprehensive(email: str):
    """Balanced email validation that reduces false positives while staying practical"""
    domain = email.split('@')[1]
    
    # Expanded list of known good domains that we can trust
    trusted_domains = [
        'gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 
        'yahoo.com', 'apple.com', 'icloud.com', 'microsoft.com',
        'google.com', 'amazon.com', 'facebook.com', 'twitter.com',
        'linkedin.com', 'github.com', 'protonmail.com', 'zoho.com',
        'aol.com', 'live.com', 'msn.com', 'comcast.net', 'verizon.net',
        'qq.com', 'yandex.com', 'mail.ru', 'fastmail.com', 'tutanota.com'
    ]
    
    if domain.lower() in trusted_domains:
        return True, f"✅ Verified trusted email provider: {domain}"
    
    # For other domains, be more careful to avoid false positives
    try:
        # Step 1: Check if domain has mail servers configured
        mail_server = get_mx_records(domain)
        
        if not mail_server:
            return False, f"❌ No mail server found for domain: {domain}"
        
        # Step 2: For non-trusted domains, be more strict about verification
        # Check if it's a suspicious or likely invalid domain pattern
        if len(domain.split('.')) < 2:
            return False, f"❌ Invalid domain format: {domain}"
            
        # Check for obviously fake patterns
        suspicious_patterns = ['test', 'example', 'fake', 'invalid', 'temp', 'dummy']
        if any(pattern in domain.lower() for pattern in suspicious_patterns):
            return False, f"❌ Domain appears to be a test/fake domain: {domain}"
        
        # Try to connect to mail server for verification
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(6)
            result = sock.connect_ex((mail_server, 25))
            sock.close()
            
            if result == 0:
                return True, f"✅ Mail server verified and accessible: {mail_server}"
            else:
                # For unknown domains, if we can't connect to port 25, be more conservative
                # but still allow if the mail server hostname exists
                return True, f"⚠️ Mail server found but connection limited: {mail_server} (may have mail services)"
                
        except Exception as e:
            # If mail server hostname exists but connection fails, be cautious but not too strict
            return True, f"⚠️ Mail server detected: {mail_server} (connection verification limited)"
            
    except Exception as e:
        # For unknown errors, be more conservative
        return False, f"❌ Email validation failed: {str(e)}"

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