from urllib.parse import urlparse
from bs4 import BeautifulSoup
from PIL import Image
from io import BytesIO
import dns.resolver
import datetime
import requests
import argparse
import certifi
import socket
import whois
import ssl

def get_page_title(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        title = soup.title.string if soup.title else None
        return title
    except requests.exceptions.RequestException:
        return None

def get_last_modified(url):
    try:
        response = requests.head(url)
        last_modified = response.headers.get('Last-Modified')
        return last_modified
    except requests.exceptions.RequestException:
        return None

def get_creation_date(domain):
    try:
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return creation_date
    except whois.parser.PywhoisError:
        return None

def get_dns_info(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_addresses = [rdata.address for rdata in answers]
        return ip_addresses
    except dns.resolver.NXDOMAIN:
        return []

def get_subdomains(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        subdomains = []
        for answer in answers:
            subdomain = str(answer).split('.')[0]
            if subdomain != domain:
                subdomains.append(subdomain)
        return subdomains
    except dns.resolver.NXDOMAIN:
        return []

def get_firewall_info(url):
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'})
        firewall_headers = response.headers.get('X-Firewall')
        if firewall_headers:
            firewall_names = firewall_headers.split(',')
            return firewall_names
        return []
    except requests.exceptions.RequestException:
        return None

def get_technologies(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        # Look for technology clues from HTML tags
        html_technologies = []
        html_tags = soup.find_all()
        for tag in html_tags:
            class_attr = tag.get('class', [])
            id_attr = tag.get('id', [])
            if class_attr:
                html_technologies.extend(class_attr)
            if id_attr:
                html_technologies.extend(id_attr)
        # Look for technology clues in JavaScript files
        script_technologies = []
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            script_url = script['src']
            if not script_url.startswith('http'):
                script_url = urlparse(url).scheme + '://' + urlparse(url).netloc + script_url
            try:
                script_response = requests.get(script_url)
                script_content = script_response.content.decode('utf-8')
                script_technologies.extend(['wordpress', 'joomla', 'drupal', 'laravel', 'django', 'angular', 'react', 'vue','jquery','html','php','css','sqlite','javascript','mysql','oracle','python','c+','c#'])
            except requests.exceptions.RequestException:
                pass
        # Look for technology clues from HTTP response headers
        headers = response.headers
        header_technologies = []
        for header in headers.values():
            header_technologies.extend(['wordpress', 'joomla', 'drupal', 'laravel', 'django', 'angular', 'react', 'vue','jquery','html','php','css','sqlite','javascript','mysql','oracle','python','c+','c#'])
        # Merge technology titles and list only unique titles
        technologies = list(set(html_technologies + script_technologies + header_technologies))
        # Clear technology headings and list only programming languages
        programming_languages = [tech for tech in technologies if tech in ['wordpress', 'joomla', 'drupal', 'laravel', 'django', 'angular', 'react', 'vue','jquery','html','php','css','sqlite','javascript','mysql','oracle','python','c+','c#']]
        return programming_languages
    except requests.exceptions.RequestException:
        return None

def get_certificate_info(url):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context(cafile=certifi.where())
        with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            certificate = s.getpeercert()
            issuer = certificate['issuer'][0][0][1]
            start_date = datetime.datetime.strptime(certificate['notBefore'], "%b %d %H:%M:%S %Y %Z")
            expiration_date = datetime.datetime.strptime(certificate['notAfter'], "%b %d %H:%M:%S %Y %Z")
            validity_period = (expiration_date - start_date).days
            certificate_info = {
                'Certificate Issuer': issuer,
                'Certificate Start Date': start_date,
                'Certificate Expiration Date': expiration_date,
                'Certificate Validity Period (Days)': validity_period
            }
            return certificate_info
    except (ssl.SSLError, ConnectionError, socket.gaierror):
        return None

def bypass_captcha(captcha_url):
    try:
        captcha_image = requests.get(captcha_url, stream=True).content
        image = Image.open(BytesIO(captcha_image))
        captcha_text = pytesseract.image_to_string(image)
        return captcha_text
    except requests.exceptions.RequestException:
        return None

def bypass_javascript(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        dynamic_content_tag = soup.find(id='dynamic-content')
        dynamic_content = dynamic_content_tag.text if dynamic_content_tag else ""
        return dynamic_content
    except requests.exceptions.RequestException:
        return None

def get_site_info(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if not domain:
        return None
    dns_info = get_dns_info(domain)
    title = get_page_title(url)
    last_modified = get_last_modified(url)
    creation_date = get_creation_date(domain)
    subdomains = get_subdomains(domain)
    firewall_info = get_firewall_info(url)
    technologies = get_technologies(url)
    certificate_info = get_certificate_info(url)
    site_info = {
        'Title': title,
        'Last Updated Date': last_modified,
        'First Creation Date': creation_date,
        'DNS Information': dns_info,
        'Subdomains': subdomains,
        'Firewall Names': firewall_info,
        'Technologies Used': technologies,
        'Certificate Information': certificate_info
    }
    return site_info

def main(url):
    site_info = get_site_info(url)
    if not site_info:
        print("Invalid URL. Please enter a valid URL.")
        return
    print("Site Information:")
    for key, value in site_info.items():
        if key == 'Technologies Used':
            if value:
                print(key + ': ' + ', '.join(value))
            else:
                print(key + ': No technology identified.')
        elif key == 'Certificate Information':
            if value:
                print(key + ':')
                for cert_key, cert_value in value.items():
                    print(cert_key + ': ' + str(cert_value))
            else:
                print(key + ': No certificate detected.')
        else:
            print(key + ': ' + str(value))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Web Information Program')
    parser.add_argument('url', type=str, help='URL of the website')
    args = parser.parse_args()
    main(args.url)
