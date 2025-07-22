# Phishing URL Detector

A web-based application that analyzes URLs for potential phishing characteristics and provides instant risk assessments.

## Features

* **Real-time URL Analysis**: Instant detection of suspicious URL patterns
* **Comprehensive Detection**: Multiple heuristics including IP addresses, suspicious keywords, random sequences, and more
* **User-friendly Interface**: Clean, responsive web interface with modern dark theme and smooth animations
* **Detailed Reporting**: Visual risk assessment with severity levels, progress bars, and point-based explanations
* **AJAX-Powered UX**: Fast, dynamic results without refreshing the page

## Detection Methods

* IP address usage instead of domain names
* Suspicious symbols and special characters (@, excessive hyphens)
* URL length analysis
* HTTPS protocol verification
* Domain structure analysis (e.g., excessive subdomains)
* Common phishing keyword detection (e.g., "login", "verify", "update")
* URL shortener detection (e.g., bit.ly, tinyurl)
* Random character sequence detection
* Encoded character analysis
* Double slash misuse (e.g., `//login.php`)
* TLD reputation check (e.g., .buzz, .xyz)
* Non-standard port usage

## Installation & Setup

### Prerequisites

* Python 3.7 or higher
* pip (Python package installer)

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
├── app.py                # Main Flask application
├── phishing_detector.py  # Detection algorithm logic
├── templates/
│   └── index.html        # Web interface template (AJAX enabled)
├── static/
│   └── style.css         # Custom gradient styling and layout
└── README.md             # Project documentation
```

## Usage

1. Open the web application in your browser
2. Enter a URL in the input field (with or without http/https)
3. Click "Analyze" to get instant results
4. Review the score, verdict, and detailed breakdown of detections

## Example URLs to Test

**Legitimate URLs** (should score low):

* [https://google.com](https://google.com)
* [https://github.com](https://github.com)
* [https://stackoverflow.com](https://stackoverflow.com)

**Suspicious URLs** (should score medium-high):

* [http://paypal-verify.suspicious-domain.com](http://paypal-verify.suspicious-domain.com)
* [https://x7k9mz2q.fake-bank.com/login](https://x7k9mz2q.fake-bank.com/login)
* [http://192.168.1.1/secure-banking](http://192.168.1.1/secure-banking)
* [https://bit.ly/fake-link](https://bit.ly/fake-link)
* [http://my.bank-login.buzz/](http://my.bank-login.buzz/)

## Risk Levels

* **Legitimate (0-3 points)**: Low risk, likely safe to visit
* **Suspicious (4-7 points)**: Medium risk, exercise caution
* **Phishing (8+ points)**: High risk, likely malicious

## Technical Details

* **Framework**: Flask (Python web framework)
* **Frontend**: Vanilla JavaScript + FontAwesome + custom CSS
* **Analysis Engine**: Heuristic-based scoring system with visual breakdown
* **UI Theme**: Modern dark theme with gradient highlights and glassmorphism
* **AJAX Integration**: Dynamic updates via JSON API (no page refresh)
* **Responsive**: Fully functional on desktop and mobile devices

## License

This project is for educational purposes. Use responsibly and always verify suspicious URLs through official channels.
