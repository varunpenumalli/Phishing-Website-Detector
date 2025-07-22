import re
import urllib.parse
from typing import Dict, Any

class PhishingDetector:
    """A class to detect phishing URLs based on various heuristics."""

    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'account', 'secure', 'update', 'ebay',
            'paypal', 'banking', 'signin', 'confirm', 'suspended',
            'validation', 'authenticate', 'verification'
        ]

    def score_url(self, url: str) -> Dict[str, Any]:
        score = 0
        details = []

        try:
            parsed_url = urllib.parse.urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid URL format: {str(e)}")

        # 1. IP address
        if self._uses_ip_address(parsed_url.hostname):
            score += 5
            details.append({
                'check': 'IP Address Usage',
                'points': 5,
                'description': 'URL uses IP address instead of domain name',
                'severity': 'high'
            })

        # 2. @ symbol
        if '@' in url:
            score += 3
            details.append({
                'check': '@ Symbol Detected',
                'points': 3,
                'description': 'URL contains @ symbol which can hide the real destination',
                'severity': 'medium'
            })

        # 3. URL length
        if len(url) > 75:
            score += 2
            details.append({
                'check': 'Long URL',
                'points': 2,
                'description': f'URL is {len(url)} characters long (suspicious if >75)',
                'severity': 'low'
            })

        # 4. Protocol
        if parsed_url.scheme != 'https':
            score += 2
            details.append({
                'check': 'No HTTPS',
                'points': 2,
                'description': 'URL does not use secure HTTPS protocol',
                'severity': 'medium'
            })

        # 5. Subdomains
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

        # 6. Keywords
        keyword_score, found_keywords = self._check_suspicious_keywords(url)
        if keyword_score > 0:
            score += keyword_score
            details.append({
                'check': 'Suspicious Keywords',
                'points': keyword_score,
                'description': f'Contains suspicious keywords: {", ".join(found_keywords)}',
                'severity': 'medium'
            })

        # 7. Hyphens
        if parsed_url.hostname and '-' in parsed_url.hostname:
            score += 1
            details.append({
                'check': 'Hyphens in Domain',
                'points': 1,
                'description': 'Domain contains hyphens which can mimic legitimate sites',
                'severity': 'low'
            })

        # 8. URL Shorteners
        if self._is_url_shortener(parsed_url.hostname):
            score += 3
            details.append({
                'check': 'URL Shortener',
                'points': 3,
                'description': 'Uses URL shortener which can hide malicious destinations',
                'severity': 'medium'
            })

        # 9. Random sequences
        random_score, random_parts = self._check_random_sequences(url)
        if random_score > 0:
            score += random_score
            details.append({
                'check': 'Random Character Sequences',
                'points': random_score,
                'description': f'Contains suspicious random sequences: {", ".join(random_parts)}',
                'severity': 'medium'
            })

        # 10. TLD Risk
        tld_score, tld = self._check_tld_risk(parsed_url.hostname)
        if tld_score > 0:
            score += tld_score
            details.append({
                'check': 'Suspicious TLD',
                'points': tld_score,
                'description': f'TLD ".{tld}" has high historical phishing rates',
                'severity': 'high' if tld_score >= 4 else 'medium'
            })

        # 11. Double slashes in path
        if '//' in parsed_url.path:
            score += 2
            details.append({
                'check': 'Double Slash in Path',
                'points': 2,
                'description': 'Path contains "//" which may indicate redirection or obfuscation',
                'severity': 'medium'
            })

        # 12. Encoded characters
        if re.search(r'%[0-9a-fA-F]{2}', parsed_url.path + parsed_url.query):
            score += 1
            details.append({
                'check': 'Encoded Characters',
                'points': 1,
                'description': 'URL contains encoded characters like %2e or %40 which may hide intent',
                'severity': 'low'
            })

        # 13. Non-standard port
        if parsed_url.port and parsed_url.port not in [80, 443]:
            score += 2
            details.append({
                'check': 'Non-Standard Port',
                'points': 2,
                'description': f'Uses uncommon port {parsed_url.port}, which may indicate malicious intent',
                'severity': 'medium'
            })

        verdict = self._classify_score(score)
        return {
            'score': score,
            'verdict': verdict,
            'details': details,
            'risk_level': self._get_risk_level(score),
            'score_percentage': min(100, round((score / 20) * 100))
        }

    def _uses_ip_address(self, hostname: str) -> bool:
        return bool(hostname and re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname))

    def _check_subdomains(self, hostname: str) -> int:
        return 2 if hostname and hostname.count('.') > 3 else 0

    def _check_suspicious_keywords(self, url: str) -> tuple:
        found = [kw for kw in self.suspicious_keywords if kw in url.lower()]
        return len(found) * 2, found

    def _is_url_shortener(self, hostname: str) -> bool:
        shorteners = [
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in'
        ]
        return bool(hostname and hostname.lower() in shorteners)

    def _check_random_sequences(self, url: str) -> tuple:
        parsed_url = urllib.parse.urlparse(url)
        random_parts = []

        if parsed_url.hostname:
            for part in parsed_url.hostname.split('.'):
                if self._is_random_sequence(part):
                    random_parts.append(part)

        if parsed_url.path:
            for part in parsed_url.path.split('/'):
                if len(part) > 6 and self._is_random_sequence(part):
                    random_parts.append(part)

        if parsed_url.query:
            for part in parsed_url.query.split('&'):
                if '=' in part:
                    key, value = part.split('=', 1)
                    if len(value) > 8 and self._is_random_sequence(value):
                        random_parts.append(value[:15] + '...' if len(value) > 15 else value)

        return min(len(random_parts) * 2, 6), random_parts[:3]

    def _check_tld_risk(self, hostname: str) -> tuple:
        tld_risks = {
            'buzz': 5, 'wang': 5, 'host': 5, 'icu': 5, 'live': 5,
            'tk': 4, 'gq': 4, 'cf': 4, 'ga': 4, 'ml': 4,
            'top': 4, 'info': 4,
            'xyz': 3, 'online': 3, 'cn': 3, 'us': 3,
            'net': 2,
            'org': 1, 'ru': 1
        }
        if not hostname:
            return 0, None
        tld = hostname.split('.')[-1].lower()
        return tld_risks.get(tld, 0), tld if tld in tld_risks else None

    def _is_random_sequence(self, text: str) -> bool:
        if not text or len(text) < 6:
            return False

        text_lower = text.lower()
        if any(p in text_lower for p in [
            'www', 'mail', 'blog', 'shop', 'news', 'admin', 'user', 'test',
            'dev', 'api', 'cdn', 'static', 'assets', 'media', 'images',
            'index', 'home', 'about', 'contact', 'login', 'register',
            'google', 'facebook', 'amazon', 'microsoft', 'apple'
        ]):
            return False

        vowels = 'aeiou'
        vowel_streak = consonant_streak = max_v = max_c = 0
        for c in text_lower:
            if c.isalpha():
                if c in vowels:
                    vowel_streak += 1
                    consonant_streak = 0
                    max_v = max(max_v, vowel_streak)
                else:
                    consonant_streak += 1
                    vowel_streak = 0
                    max_c = max(max_c, consonant_streak)

        if max_c >= 4 or max_v >= 3:
            return True

        bigrams = ['th', 'he', 'in', 'er', 'an', 're', 'ed', 'nd', 'ha', 'to']
        bigram_count = sum(text_lower[i:i+2] in bigrams for i in range(len(text_lower)-1))
        if len(text_lower) > 8 and bigram_count < len(text_lower) * 0.15:
            return True

        alternating = sum(
            (text[i].isalpha() and text[i+1].isdigit()) or
            (text[i].isdigit() and text[i+1].isalpha())
            for i in range(len(text) - 1)
        )
        return alternating >= len(text) * 0.4

    def _classify_score(self, score: int) -> str:
        if score >= 8:
            return "Phishing (High Risk)"
        elif score >= 4:
            return "Suspicious (Medium Risk)"
        return "Likely Legitimate"

    def _get_risk_level(self, score: int) -> str:
        return "danger" if score >= 8 else "warning" if score >= 4 else "success"

    def analyze_url(self, url: str) -> Dict[str, Any]:
        if not url:
            raise ValueError("URL cannot be empty")
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return self.score_url(url)
