import re
import urllib.parse
from typing import Dict, List, Any

class PhishingDetector:
    """A class to detect phishing URLs based on various heuristics."""
    
    def __init__(self):
        # Suspicious keywords that are commonly used in phishing attempts
        self.suspicious_keywords = [
            'login', 'verify', 'account', 'secure', 'update', 'ebay', 
            'paypal', 'banking', 'signin', 'confirm', 'suspended',
            'validation', 'authenticate', 'verification'
        ]
    
    def score_url(self, url: str) -> Dict[str, Any]:
        """
        Score a URL based on various phishing heuristics.
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            Dict containing score, verdict, and details of checks
        """
        score = 0
        details = []
        
        try:
            parsed_url = urllib.parse.urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid URL format: {str(e)}")
        
        # 1. Check if uses IP address instead of domain
        if self._uses_ip_address(parsed_url.hostname):
            score += 5
            details.append({
                'check': 'IP Address Usage',
                'points': 5,
                'description': 'URL uses IP address instead of domain name',
                'severity': 'high'
            })
        
        # 2. Check for '@' symbol
        if '@' in url:
            score += 3
            details.append({
                'check': '@ Symbol Detected',
                'points': 3,
                'description': 'URL contains @ symbol which can hide the real destination',
                'severity': 'medium'
            })
        
        # 3. Check URL length
        if len(url) > 75:
            score += 2
            details.append({
                'check': 'Long URL',
                'points': 2,
                'description': f'URL is {len(url)} characters long (suspicious if >75)',
                'severity': 'low'
            })
        
        # 4. Check HTTPS usage
        if parsed_url.scheme != 'https':
            score += 2
            details.append({
                'check': 'No HTTPS',
                'points': 2,
                'description': 'URL does not use secure HTTPS protocol',
                'severity': 'medium'
            })
        
        # 5. Check for too many subdomains
        subdomain_score = self._check_subdomains(parsed_url.hostname)
        if subdomain_score > 0:
            score += subdomain_score
            dot_count = parsed_url.hostname.count('.') if parsed_url.hostname else 0
            details.append({
                'check': 'Multiple Subdomains',
                'points': subdomain_score,
                'description': f'Domain has {dot_count} dots (suspicious if >3)',
                'severity': 'medium'
            })
        
        # 6. Check for suspicious keywords
        keyword_score, found_keywords = self._check_suspicious_keywords(url)
        if keyword_score > 0:
            score += keyword_score
            details.append({
                'check': 'Suspicious Keywords',
                'points': keyword_score,
                'description': f'Contains suspicious keywords: {", ".join(found_keywords)}',
                'severity': 'medium'
            })
        
        # 7. Check for hyphens in domain
        if parsed_url.hostname and '-' in parsed_url.hostname:
            score += 1
            details.append({
                'check': 'Hyphens in Domain',
                'points': 1,
                'description': 'Domain contains hyphens which can be used to mimic legitimate sites',
                'severity': 'low'
            })
        
        # 8. Check for URL shorteners (additional check)
        if self._is_url_shortener(parsed_url.hostname):
            score += 3
            details.append({
                'check': 'URL Shortener',
                'points': 3,
                'description': 'Uses URL shortener service which can hide malicious destinations',
                'severity': 'medium'
            })
        
        verdict = self._classify_score(score)
        
        return {
            'score': score,
            'verdict': verdict,
            'details': details,
            'risk_level': self._get_risk_level(score)
        }
    
    def _uses_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address."""
        if not hostname:
            return False
        return re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname) is not None
    
    def _check_subdomains(self, hostname: str) -> int:
        """Check for excessive subdomains."""
        if not hostname:
            return 0
        dot_count = hostname.count('.')
        return 2 if dot_count > 3 else 0
    
    def _check_suspicious_keywords(self, url: str) -> tuple:
        """Check for suspicious keywords in URL."""
        found_keywords = []
        for keyword in self.suspicious_keywords:
            if keyword in url.lower():
                found_keywords.append(keyword)
        
        # 2 points per keyword found
        return len(found_keywords) * 2, found_keywords
    
    def _is_url_shortener(self, hostname: str) -> bool:
        """Check if the domain is a known URL shortener."""
        if not hostname:
            return False
        
        shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in'
        ]
        
        return hostname.lower() in shorteners
    
    def _classify_score(self, score: int) -> str:
        """Classify the risk based on score."""
        if score >= 8:
            return "Phishing (High Risk)"
        elif score >= 4:
            return "Suspicious (Medium Risk)"
        else:
            return "Likely Legitimate"
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level for UI styling."""
        if score >= 8:
            return "danger"
        elif score >= 4:
            return "warning"
        else:
            return "success"
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Public method to analyze a URL.
        
        Args:
            url (str): The URL to analyze
            
        Returns:
            Dict containing analysis results
        """
        # Basic URL validation
        if not url:
            raise ValueError("URL cannot be empty")
        
        # Add protocol if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        return self.score_url(url)
