# 🐍 Python Email Validator

A professional email validation service built with Python Flask and deployed on Vercel. Validates email addresses using format checking, DNS lookup, domain verification, and disposable email detection.

## 🚀 Live Demo

**[Visit the Live Application](https://your-app-name.vercel.app)**

## ✨ Features

- ✅ **Email Format Validation** - Regex-based format checking
- 🌐 **DNS Lookup** - Verifies domain existence
- 📧 **Domain Verification** - Checks if domain can receive emails
- 🚫 **Disposable Email Detection** - Identifies temporary email services
- ⚡ **Fast & Reliable** - Hosted on Vercel's global edge network
- 🔒 **Privacy Focused** - No data storage or tracking
- 📱 **Mobile Responsive** - Works on all devices

## 🛠️ Technology Stack

- **Backend**: Python Flask
- **Frontend**: HTML5, CSS3, JavaScript
- **Hosting**: Vercel Serverless Functions
- **API**: RESTful JSON API

## 📖 API Usage

### Validate Email Endpoint

```bash
POST /api/validate
Content-Type: application/json

{
  "email": "test@example.com"
}
```

### Response Format

```json
{
  "email": "test@example.com",
  "valid": true,
  "messages": [
    "✅ Email format is valid",
    "📡 Domain 'example.com' exists and is reachable",
    "📧 Trusted domain: example.com",
    "🎉 Email appears to be valid!"
  ]
}
```

### Health Check

```bash
GET /api/health
```

## 🔧 Local Development

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/email-validator.git
   cd email-validator
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python app.py
   ```

4. **Open your browser**
   ```
   http://localhost:5000
   ```

## 🚀 Deploy to Vercel

1. **Fork this repository**

2. **Connect to Vercel**
   - Visit [vercel.com](https://vercel.com)
   - Import your GitHub repository
   - Deploy automatically

3. **Custom Domain (Optional)**
   - Add your custom domain in Vercel dashboard
   - Update DNS records as instructed

## 📁 Project Structure

```
email-validator/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── vercel.json        # Vercel deployment configuration
├── README.md          # Project documentation
└── .gitignore         # Git ignore file
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is open source and available under the [MIT License](LICENSE).

## 🙋‍♂️ Support

If you have any questions or issues, please open an issue on GitHub.

---

Made with ❤️ and Python | Deployed on Vercel