import ipaddress
import re
import requests
from bs4 import BeautifulSoup
import whois
from urllib.parse import urlparse


class FeatureExtraction:
    def __init__(self, url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = None
        self.urlparse = ""
        self.response = None
        self.soup = None

        self.trusted_domains = ["student.geu.ac.in", "geu.ac.in"]

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        # If the domain is whitelisted, skip feature extraction and mark it as safe
        if self.domain in self.trusted_domains:
            self.features = [1] * 30  # All features set to legitimate (Safe)
        else:
            # Extract features for non-whitelisted domains
            self.features.append(self.UsingIp())
            self.features.append(self.longUrl())
            self.features.append(self.shortUrl())
            self.features.append(self.symbol())
            self.features.append(self.redirecting())
            self.features.append(self.prefixSuffix())
            self.features.append(self.SubDomains())
            self.features.append(self.Hppts())
            self.features.append(self.DomainRegLen())
            self.features.append(self.Favicon())
            self.features.append(self.NonStdPort())
            self.features.append(self.HTTPSDomainURL())
            # Add placeholders for remaining features (to ensure 30 total features)
            self.features.extend([0] * (30 - len(self.features)))

    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if 54 <= len(self.url) <= 75:
            return 0
        return -1

    def shortUrl(self):
        match = re.search(
            r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
            r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
            r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
            r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|db\.tt|qr\.ae|'
            r'adf\.ly|cur\.lv|ow\.ly|ity\.im|q\.gs|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|'
            r'cutt\.us|u\.bb|yourls\.org|x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|'
            r'1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        return 1

    def symbol(self):
        return -1 if "@" in self.url else 1

    def redirecting(self):
        return -1 if self.url.rfind('//') > 6 else 1

    def prefixSuffix(self):
        return -1 if "-" in self.domain else 1

    def SubDomains(self):
        dot_count = self.url.count('.')
        return 1 if dot_count == 1 else (0 if dot_count == 2 else -1)

    def Hppts(self):
        return 1 if self.urlparse.scheme == "https" else -1

    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            age = (expiration_date.year - creation_date.year) * 12 + (expiration_date.month - creation_date.month)
            return 1 if age >= 12 else -1
        except:
            return -1

    def Favicon(self):
        try:
            for link in self.soup.find_all('link', href=True):
                if self.url in link['href'] or self.domain in link['href']:
                    return 1
            return -1
        except:
            return -1

    def NonStdPort(self):
        return -1 if self.urlparse.port not in [80, 443, None] else 1

    def HTTPSDomainURL(self):
        return 1 if self.urlparse.scheme == "https" and self.domain in self.url else -1

    def getFeaturesList(self):
        return self.features
