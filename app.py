import os
import logging
from flask import Flask, render_template, request, flash
from phishing_detector import PhishingDetector

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "fallback_secret_key_for_development")

# Initialize the phishing detector
detector = PhishingDetector()

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        
        if not url:
            flash('Please enter a URL to analyze.', 'warning')
            return render_template('index.html')
        
        try:
            # Analyze the URL
            result = detector.analyze_url(url)
            return render_template('index.html', 
                                 url=url, 
                                 result=result)
        except Exception as e:
            logging.error(f"Error analyzing URL {url}: {str(e)}")
            flash(f'Error analyzing URL: {str(e)}', 'danger')
            return render_template('index.html', url=url)
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
