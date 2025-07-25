import re
import urllib.parse
from typing import Dict, Any


class PhishingDetector:
    """A class to detect phishing URLs based on various heuristics."""

    # ❶  FREE‑HOSTING PLATFORMS OFTEN ABUSED FOR PHISHING
    FREE_HOSTS = (
        'weebly.com', 'wixsite.com', 'blogspot.com',
        '000webhostapp.com', 'webnode.page'
    )

    def __init__(self):
        # ❷  EXPANDED KEYWORD SET  (duplicates automatically ignored at runtime)
        self.suspicious_keywords = [
            # finance / access
            'account', 'myaccount', 'banking', 'paypal', 'ebay', 'ebayisapi',
            'alibaba', 'dropbox',
            # auth / session
            'login', 'signin', 'signout', 'logout', 'verify', 'verification',
            'validate', 'validation', 'authenticate', 'secure', 'secured',
            'securewebsession', 'server', 'client', 'password', 'mfa',
            # urgency
            'confirm', 'suspended', 'suspend', 'recovery', 'restore',
            'required', 'update', 'resolution', 'submit', 'limited',
            # prizes / scams
            'lucky', 'bonus', 'reward', 'giveaway', 'refund', 'billing',
            # web platform abuse
            'wordpress', 'wp', 'themes', 'plugins', 'admin', 'includes',
            'webscr', 'webservis', 'webspace', 'webnode', '000webhostapp',
            # misc tech
            'redirectme', 'click', 'browser', 'content', 'images', 'js',
            'css', 'site', 'view',
            # mail & cloud
            'mailbox', 'outlook', 'webmail',
        ]

    # ──────────────────────────────────────────────────────────────
    #                           MAIN
    # ──────────────────────────────────────────────────────────────
    def score_url(self, url: str) -> Dict[str, Any]:
        score = 0
        details = []

        try:
            parsed_url = urllib.parse.urlparse(url)
        except Exception as e:
            raise ValueError(f"Invalid URL format: {str(e)}")

        # 1. IP‑literal host
        if self._uses_ip_address(parsed_url.hostname):
            score += 5
            details.append(self._d('IP Address Usage', 5,
                                   'URL uses IP address instead of domain name', 'high'))

        # 2. @ symbol
        if '@' in url:
            score += 3
            details.append(self._d('@ Symbol Detected', 3,
                                   'URL contains @ symbol which can hide the real destination', 'medium'))

        # 3. URL length
        if len(url) > 75:
            score += 2
            details.append(self._d('Long URL', 2,
                                   f'URL is {len(url)} characters long (suspicious if >75)', 'low'))

        # 4. Protocol
        if parsed_url.scheme != 'https':
            score += 2
            details.append(self._d('No HTTPS', 2,
                                   'URL does not use secure HTTPS protocol', 'medium'))

        # 5. Sub‑domain depth  (≥ 3 dots)
        if parsed_url.hostname and parsed_url.hostname.count('.') >= 3:
            score += 2
            dot_count = parsed_url.hostname.count('.')
            details.append(self._d('Multiple Subdomains', 2,
                                   f'Domain has {dot_count} dots (suspicious if ≥3)', 'medium'))

        # 6. Suspicious keywords  (hyphens stripped)
        kw_score, kw_found = self._check_suspicious_keywords(url)
        if kw_score:
            score += kw_score
            details.append(self._d('Suspicious Keywords', kw_score,
                                   'Contains suspicious keywords: ' + ', '.join(kw_found), 'medium'))

        # 7. Hyphens
        if parsed_url.hostname and '-' in parsed_url.hostname:
            score += 1
            details.append(self._d('Hyphens in Domain', 1,
                                   'Domain contains hyphens which can mimic legitimate sites', 'low'))

        # 8. URL shortener
        if self._is_url_shortener(parsed_url.hostname):
            score += 3
            details.append(self._d('URL Shortener', 3,
                                   'Uses URL shortener which can hide malicious destinations', 'medium'))

        # 9. Random sequences
        rnd_score, rnd_parts = self._check_random_sequences(url)
        if rnd_score:
            score += rnd_score
            details.append(self._d('Random Character Sequences', rnd_score,
                                   'Contains suspicious random sequences: ' + ', '.join(rnd_parts), 'medium'))

        # 10. TLD risk
        tld_score, tld = self._check_tld_risk(parsed_url.hostname)
        if tld_score:
            score += tld_score
            details.append(self._d('Suspicious TLD', tld_score,
                                   f'TLD ".{tld}" has high historical phishing rates',
                                   'high' if tld_score >= 4 else 'medium'))

        # 11. Double slashes in path
        if '//' in parsed_url.path:
            score += 2
            details.append(self._d('Double Slash in Path', 2,
                                   'Path contains "//" which may indicate redirection or obfuscation', 'medium'))

        # 12. Encoded characters
        if re.search(r'%[0-9a-fA-F]{2}', parsed_url.path + parsed_url.query):
            score += 1
            details.append(self._d('Encoded Characters', 1,
                                   'URL contains encoded characters like %2e or %40 which may hide intent', 'low'))

        # 13. Non‑standard port
        if parsed_url.port and parsed_url.port not in (80, 443):
            score += 2
            details.append(self._d('Non-Standard Port', 2,
                                   f'Uses uncommon port {parsed_url.port}, which may indicate malicious intent', 'medium'))

        # 14. Free‑hosting bonus
        if parsed_url.hostname and parsed_url.hostname.endswith(self.FREE_HOSTS):
            score += 2
            details.append(self._d('Free‑Hosting Domain', 2,
                                   'Hosted on a free platform often abused for phishing', 'medium'))

        # Final verdict
        verdict = self._classify_score(score)
        return {
            'score': score,
            'verdict': verdict,
            'details': details,
            'risk_level': self._get_risk_level(score),
            'score_percentage': min(100, round(score / 20 * 100))
        }

    # ──────────────────────────────────────────────────────────────
    #                       HELPERS
    # ──────────────────────────────────────────────────────────────
    @staticmethod
    def _d(check, pts, desc, sev):  # detail formatter
        return {'check': check, 'points': pts, 'description': desc, 'severity': sev}

    @staticmethod
    def _uses_ip_address(hostname):
        return bool(hostname and re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname))

    # keyword matching with hyphen stripping
    def _check_suspicious_keywords(self, url):
        clean = url.lower().replace('-', '')
        found = [kw for kw in self.suspicious_keywords if kw in clean]
        return len(found) * 2, found

    def _is_url_shortener(self, hostname):
        return hostname and hostname.lower() in {
            'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in'
        }


    def _check_random_sequences(self, url: str):
        parsed_url = urllib.parse.urlparse(url)
        random_parts = []

        def maybe_add(part: str):
            if len(part) > 6 and self._is_random_sequence(part):
                random_parts.append(part)

        if parsed_url.hostname:
            for segment in parsed_url.hostname.split('.'):
                maybe_add(segment)

        if parsed_url.path:
            for segment in parsed_url.path.split('/'):
                maybe_add(segment)

        if parsed_url.query:
            for pair in parsed_url.query.split('&'):
                if '=' in pair:
                    _, value = pair.split('=', 1)
                    maybe_add(value[:15] + '...' if len(value) > 15 else value)

        return min(len(random_parts) * 2, 6), random_parts[:3]

    def _check_tld_risk(self, hostname: str):
        """
        Return (weight, tld) where weight is the risk score for the TLD.
        """
        tld_risks = {
            'buzz': 5, 'wang': 5, 'host': 5, 'icu': 5, 'live': 5, 'cfd': 5,
            'win': 5, 'pw': 5,

            'tk': 4, 'gq': 4, 'cf': 4, 'ga': 4, 'ml': 4,
            'top': 4, 'info': 4, 'cyou': 4, 'click': 4,
            'fun': 4, 'vip': 4, 'work': 4, 'page': 4,
            'app': 4, 'mx': 4, 'shop': 4, 'cloud': 4,

            'xyz': 3, 'online': 3, 'cn': 3, 'us': 3,
            'gp': 3, 'gy': 3, 'gd': 3,
            'link': 3, 'ng': 3, 'ws': 3,
            'network': 3, 'io': 3, 'id': 3, 'dev': 3, 'club': 3, 'site': 3,

            'net': 2, 'ug': 2,
            'bz': 2, 'li': 2, 'do': 2, 'py': 2,
            'ly': 2, 'ph': 2, 'za': 2, 'it': 2, 'cc': 2,

            'org': 1, 'ru': 1
        }
        if not hostname:
            return 0, None
        tld = hostname.split('.')[-1].lower()
        return tld_risks.get(tld, 0), tld if tld in tld_risks else None


    # unchanged randomness heuristic
    def _is_random_sequence(self, text: str) -> bool:
        if not text or len(text) < 6:
            return False

        txt = text.lower()
        if any(p in txt for p in [
            'www', 'blog', 'shop', 'news', 'admin', 'user', 'test', 'dev', 'api',
            'cdn', 'static', 'assets', 'media', 'images', 'index', 'home', 'about',
            'contact', 'login', 'register', 'google', 'facebook', 'amazon',
            'microsoft', 'apple'
        ]):
            return False

        vowels = 'aeiou'
        v_streak = c_streak = max_v = max_c = 0
        for ch in txt:
            if ch.isalpha():
                if ch in vowels:
                    v_streak += 1; c_streak = 0; max_v = max(max_v, v_streak)
                else:
                    c_streak += 1; v_streak = 0; max_c = max(max_c, c_streak)

        if max_c >= 4 or max_v >= 3:
            return True

        bigrams = ['th', 'he', 'in', 'er', 'an', 're', 'ed', 'nd', 'ha', 'to']
        count_bi = sum(txt[i:i + 2] in bigrams for i in range(len(txt) - 1))
        if len(txt) > 8 and count_bi < len(txt) * 0.15:
            return True

        altern = sum(
            (text[i].isalpha() and text[i + 1].isdigit()) or
            (text[i].isdigit() and text[i + 1].isalpha())
            for i in range(len(text) - 1)
        )
        return altern >= len(text) * 0.4

    # verdict helpers
    @staticmethod
    def _classify_score(score: int) -> str:
        if score >= 8:
            return "Phishing (High Risk)"
        elif score >= 4:
            return "Suspicious (Medium Risk)"
        return "Likely Legitimate"

    @staticmethod
    def _get_risk_level(score: int) -> str:
        return "danger" if score >= 8 else "warning" if score >= 4 else "success"

    # public wrapper
    def analyze_url(self, url: str) -> Dict[str, Any]:
        if not url:
            raise ValueError("URL cannot be empty")
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return self.score_url(url)

