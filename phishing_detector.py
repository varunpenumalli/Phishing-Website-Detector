import re
import urllib.parse
import random
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
        
        # 9. Check for random character sequences
        random_score, random_parts = self._check_random_sequences(url)
        if random_score > 0:
            score += random_score
            details.append({
                'check': 'Random Character Sequences',
                'points': random_score,
                'description': f'Contains suspicious random sequences: {", ".join(random_parts)}',
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
    
    def _check_random_sequences(self, url: str) -> tuple:
        """Check for random character sequences that might indicate phishing."""
        random_parts = []
        
        # Parse URL to check different parts
        parsed_url = urllib.parse.urlparse(url)
        
        # Check hostname parts (subdomains and domain)
        if parsed_url.hostname:
            hostname_parts = parsed_url.hostname.split('.')
            for part in hostname_parts:
                if self._is_random_sequence(part):
                    random_parts.append(part)
        
        # Check path parts
        if parsed_url.path:
            path_parts = parsed_url.path.split('/')
            for part in path_parts:
                if len(part) > 6 and self._is_random_sequence(part):
                    random_parts.append(part)
        
        # Check query parameters
        if parsed_url.query:
            query_parts = parsed_url.query.split('&')
            for part in query_parts:
                if '=' in part:
                    key, value = part.split('=', 1)
                    if len(value) > 8 and self._is_random_sequence(value):
                        random_parts.append(value[:15] + '...' if len(value) > 15 else value)
        
        # Score based on number of random sequences found
        score = min(len(random_parts) * 2, 6)  # Max 6 points for this check
        
        return score, random_parts[:3]  # Return max 3 examples to avoid clutter
    
    def _is_random_sequence(self, text: str) -> bool:
        """
        Determine if a text string appears to be a random sequence.
        Uses multiple heuristics to identify random-looking strings.
        """
        if not text or len(text) < 6:
            return False
        
        # Remove common extensions and known patterns
        text_lower = text.lower()
        
        # Skip common legitimate patterns
        common_patterns = [
            'www', 'mail', 'blog', 'shop', 'news', 'admin', 'user', 'test',
            'dev', 'api', 'cdn', 'static', 'assets', 'media', 'images',
            'index', 'home', 'about', 'contact', 'login', 'register',
            'google', 'facebook', 'amazon', 'microsoft', 'apple'
        ]
        
        if any(pattern in text_lower for pattern in common_patterns):
            return False
        
        # Check for excessive consonants or vowels in a row
        vowels = 'aeiou'
        consonant_streak = 0
        vowel_streak = 0
        max_consonant_streak = 0
        max_vowel_streak = 0
        
        for char in text_lower:
            if char.isalpha():
                if char in vowels:
                    vowel_streak += 1
                    consonant_streak = 0
                    max_vowel_streak = max(max_vowel_streak, vowel_streak)
                else:
                    consonant_streak += 1
                    vowel_streak = 0
                    max_consonant_streak = max(max_consonant_streak, consonant_streak)
        
        # Random sequences often have long consonant or vowel streaks
        if max_consonant_streak >= 4 or max_vowel_streak >= 3:
            return True
        
        # Check for lack of common letter patterns
        common_bigrams = ['th', 'he', 'in', 'er', 'an', 're', 'ed', 'nd', 'ha', 'to']
        bigram_count = 0
        
        for i in range(len(text_lower) - 1):
            if text_lower[i:i+2] in common_bigrams:
                bigram_count += 1
        
        # If very few common bigrams, likely random
        if len(text_lower) > 8 and bigram_count < len(text_lower) * 0.15:
            return True
        
        # Check for alternating character types (letter-number-letter pattern)
        alternating_count = 0
        for i in range(len(text) - 1):
            if text[i].isalpha() and text[i+1].isdigit():
                alternating_count += 1
            elif text[i].isdigit() and text[i+1].isalpha():
                alternating_count += 1
        
        # High alternating pattern suggests random generation
        if alternating_count >= len(text) * 0.4:
            return True
        
        return False
    
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
