# Phishing URL Detector

## Overview

This is a Flask-based web application that analyzes URLs for potential phishing characteristics. The application provides a simple web interface where users can input URLs and receive risk assessments based on various heuristic checks. The system uses pattern matching and URL analysis techniques to identify suspicious characteristics commonly found in phishing attempts.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

The application follows a simple monolithic architecture with the following structure:

- **Frontend**: Server-side rendered HTML templates using Jinja2 with Bootstrap for styling
- **Backend**: Flask web framework handling HTTP requests and responses
- **Analysis Engine**: Custom PhishingDetector class that implements heuristic-based URL analysis
- **Static Assets**: CSS stylesheets and potentially JavaScript files served directly by Flask

The architecture prioritizes simplicity and ease of deployment, making it suitable for demonstration purposes or small-scale usage.

## Key Components

### Web Application Layer (`app.py`)
- Flask application with session management
- Single route handling both GET and POST requests
- Error handling and user feedback through flash messages
- Integration with the phishing detection engine

### Phishing Detection Engine (`phishing_detector.py`)
- Custom heuristic-based analysis system
- Scoring mechanism that evaluates URLs against multiple criteria
- Detailed reporting of analysis results with explanations
- Currently implements checks for IP addresses and special characters

### Frontend Interface
- **Templates**: HTML templates with Bootstrap dark theme integration
- **Styling**: Custom CSS for dark theme consistency and modern UI
- **User Experience**: Single-page interface with immediate feedback

### Static Assets
- Custom CSS styling with dark theme support
- Bootstrap integration for responsive design
- Font Awesome icons for enhanced visual appeal

## Data Flow

1. **User Input**: User submits a URL through the web form
2. **Request Processing**: Flask receives POST request and extracts URL
3. **Validation**: Basic input validation (non-empty URL)
4. **Analysis**: PhishingDetector analyzes the URL using heuristic rules
5. **Scoring**: System calculates risk score and generates detailed report
6. **Response**: Results are rendered back to the user with visual indicators
7. **Error Handling**: Any errors are caught and displayed as user-friendly messages

## External Dependencies

### Python Packages
- **Flask**: Web framework for handling HTTP requests and rendering templates
- **urllib.parse**: Built-in Python module for URL parsing and validation

### Frontend Dependencies
- **Bootstrap**: CSS framework loaded from CDN for responsive design
- **Font Awesome**: Icon library loaded from CDN for visual enhancements
- **Custom CSS**: Additional styling for dark theme and application-specific design

### Runtime Environment
- Python 3.x environment
- Environment variables for session secret configuration
- No database dependencies (stateless application)

## Deployment Strategy

The application is designed for simple deployment with minimal configuration:

### Development Mode
- Flask development server with debug mode enabled
- Automatic reloading for code changes
- Detailed error logging for troubleshooting

### Production Considerations
- Environment variable for session secret key
- Host configuration set to accept external connections (0.0.0.0)
- Port 5000 as default with flexibility for environment override
- Logging configuration for monitoring and debugging

### Architecture Decisions

**Framework Choice**: Flask was chosen for its simplicity and minimal overhead, making it ideal for a focused single-purpose application.

**Heuristic Approach**: The detection system uses rule-based heuristics rather than machine learning, providing transparent and explainable results while avoiding the complexity of model training and maintenance.

**Stateless Design**: No database or persistent storage is used, keeping the application simple and easily scalable horizontally.

**Frontend Approach**: Server-side rendering was chosen over a separate frontend framework to maintain simplicity and reduce the number of moving parts.

**Styling Strategy**: Bootstrap provides rapid development capabilities while custom CSS ensures consistent theming and user experience.