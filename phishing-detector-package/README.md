# Phishing URL Detector

A web-based application that analyses URLs for potential phishing characteristics and provides instant risk assessments.

## Features

- **Real-time URL Analysis**: Instant detection of suspicious URL patterns
- **Comprehensive Detection**: Multiple heuristics including IP addresses, suspicious keywords, random sequences, and more
- **User-friendly Interface**: Clean, responsive web interface with dark theme
- **Detailed Reporting**: Visual risk assessment with explanations for each detection

## Detection Methods
- IP‑literal host instead of a domain name

- @ symbol anywhere in the URL

- Excessive overall length ( > 75 characters )

- Plain HTTP (no HTTPS)

- ≥ 3 sub‑domains in the hostname

- Presence of high‑risk phishing keywords (e.g. login, verify, paypal, webmail…)

- Hyphens inside the registered domain

- Use of a known URL‑shortener (bit.ly, t.co, …)

- Random / high‑entropy character sequences in host, path or query

- Top‑level domain on the high‑abuse list (e.g. .icu, .top, .click, .win…)

- Double slashes // inside the path

- Percent‑encoded characters in path or query (%2e, %40, …)

- Non‑standard port (anything other than 80 or 443)

- Free‑hosting root domain (*.weebly.com, *.000webhostapp.com, *.wixsite.com, …)

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
3. Click "Analyse" to get instant results
4. Review the risk assessment and detailed analysis

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
Currently Deployed using Render. Due to free account, may take some time to load.
Link: https://phishing-website-detector-6v4t.onrender.com/

## License

This project is for educational purposes. Use responsibly and always verify suspicious URLs through official channels.