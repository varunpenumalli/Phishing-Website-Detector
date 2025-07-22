# Phishing URL Detector

A web-based application that analyzes URLs for potential phishing characteristics and provides instant risk assessments.

## Features

- **Real-time URL Analysis**: Instant detection of suspicious URL patterns
- **Comprehensive Detection**: Multiple heuristics including IP addresses, suspicious keywords, random sequences, and more
- **User-friendly Interface**: Clean, responsive web interface with dark theme
- **Detailed Reporting**: Visual risk assessment with explanations for each detection

## Detection Methods

- IP address usage instead of domain names
- Suspicious symbols and special characters (@, excessive hyphens)
- URL length analysis
- HTTPS protocol verification
- Domain structure analysis (excessive subdomains)
- Common phishing keywords detection
- URL shortener identification
- Random character sequence detection

## Installation & Setup

### Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

### Installation Steps

1. **Download all files** from this project
2. **Create project directory**:
   ```bash
   mkdir phishing-detector
   cd phishing-detector
   ```

3. **Install required packages**:
   ```bash
   pip install flask
   ```

4. **Run the application**:
   ```bash
   python app.py
   ```

5. **Access the application**:
   Open your web browser and go to: `http://localhost:5000`

## File Structure

```
phishing-detector/
├── app.py              # Main Flask application
├── phishing_detector.py # Detection algorithm
├── templates/
│   └── index.html      # Web interface template
├── static/
│   └── style.css       # Custom styling
└── README.md           # This file
```

## Usage

1. Open the web application in your browser
2. Enter a URL in the input field (with or without http/https)
3. Click "Analyze" to get instant results
4. Review the risk assessment and detailed analysis

## Example URLs to Test

**Legitimate URLs** (should score low):
- https://google.com
- https://github.com
- https://stackoverflow.com

**Suspicious URLs** (should score medium-high):
- http://paypal-verify.suspicious-domain.com
- https://x7k9mz2q.fake-bank.com/login
- http://192.168.1.1/secure-banking
- https://bit.ly/fake-link

## Risk Levels

- **Legitimate (0-3 points)**: Low risk, likely safe to visit
- **Suspicious (4-7 points)**: Medium risk, exercise caution
- **Phishing (8+ points)**: High risk, likely malicious

## Technical Details

- **Framework**: Flask (Python web framework)
- **Frontend**: Bootstrap 5 with custom dark theme
- **Analysis**: Heuristic-based detection using multiple algorithms
- **Responsive**: Works on desktop and mobile devices

## Deployment

For production deployment, consider using:
- Gunicorn as WSGI server
- Environment variables for configuration
- Reverse proxy (nginx/Apache)
- HTTPS encryption

## License

This project is for educational purposes. Use responsibly and always verify suspicious URLs through official channels.