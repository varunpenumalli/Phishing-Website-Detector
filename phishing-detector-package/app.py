import os
import logging
from flask import Flask, render_template, request, jsonify, flash
from phishing_detector import PhishingDetector

# Configure logging
logging.basicConfig(level=logging.DEBUG)

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "fallback_secret_key_for_development")

# Initialize the phishing detector
detector = PhishingDetector()

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    url = data.get('url', '').strip()

    if not url:
        return jsonify({"error": "Missing URL"}), 400

    try:
        result = detector.analyze_url(url)

        # Ensure the result is JSON serializable
        return jsonify({
            "verdict": result.get("verdict"),
            "score": result.get("score"),
            "risk_level": result.get("risk_level"),
            "details": result.get("details", [])
        })
    except Exception as e:
        logging.error(f"Error analyzing URL {url}: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
