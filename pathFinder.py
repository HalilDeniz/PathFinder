from urllib.parse import *
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
import re


def get_page_title(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    title = soup.title.string if soup.title else None
    return title


def get_last_modified(url):
    response = requests.head(url)
    last_modified = response.headers.get('Last-Modified')
    return last_modified


def get_creation_date(domain):
    whois_info = whois.whois(domain)
    creation_date = whois_info.creation_date
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    return creation_date


def get_dns_info(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        ip_addresses = [rdata.address for rdata in answers]
        return ip_addresses
    except dns.resolver.NXDOMAIN:
        return []



def get_subdomains(url):
    domain = urlparse(url).netloc
    subdomains = []

    try:
        answers = dns.resolver.resolve(domain, 'A')
        for answer in answers:
            subdomain = str(answer).split('.')[0]
            if subdomain != domain:
                subdomains.append(subdomain)
    except dns.resolver.NXDOMAIN:
        pass
    return subdomains

def get_firewall_info(url):
    response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'})
    firewall_headers = response.headers.get('X-Firewall')
    if firewall_headers:
        firewall_names = firewall_headers.split(',')
        return firewall_names
    return []

def get_technologies(url):
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
            script_url = urljoin(url, script_url)
        try:
            script_response = requests.get(script_url)
            script_content = script_response.content.decode('utf-8')
            script_technologies.extend(re.findall(r'\b(wordpress|joomla|drupal|laravel|django|angular|react|vue|jquery|html|php|css|javascript|mysql|oracle|python|"c+"|C#|sqlite)\b', script_content))
        except requests.exceptions.RequestException:
            pass

    # Look for technology clues from HTTP response headers
    headers = response.headers
    header_technologies = []
    for header in headers.values():
        header_technologies.extend(re.findall(r'\b(wordpress|joomla|drupal|laravel|django|angular|react|vue|jquery|html|php|css|javascript|mysql|oracle|python|"c+"|C#|sqlite)\b', header.lower()))

    # Merge technology titles and list only unique titles
    technologies = list(set(html_technologies + script_technologies + header_technologies))

    # Clear technology headings and list only programming languages
    programming_languages = [tech for tech in technologies if tech in ['wordpress', 'joomla', 'drupal', 'laravel', 'django', 'angular', 'react', 'vue','jquery','html','php','css','sqlite','javascript','mysql','oracle','python','c+','c#']]

    return programming_languages


def get_sertifika_bilgisi(url):
    try:
        hostname = url.split('//')[1].split('/')[0]
        context = ssl.create_default_context(cafile=certifi.where())
        with context.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            sertifika = s.getpeercert()

            certificate_giver = sertifika['issuer'][0][0][1]
            certificate_beginning = datetime.datetime.strptime(sertifika['notBefore'], "%b %d %H:%M:%S %Y %Z")
            certificate_finish = datetime.datetime.strptime(sertifika['notAfter'], "%b %d %H:%M:%S %Y %Z")
            certificate_validity_duration = (certificate_finish - certificate_beginning).days

            sertifika_bilgisi = {
                'Certificate Issuer': certificate_giver,
                'Certificate Start Date': certificate_beginning,
                'Certificate Expiration Date': certificate_finish,
                'Certificate Validity Period (Days)': certificate_validity_duration
            }

            return sertifika_bilgisi

    except (ssl.CertificateError, ssl.SSLError, ConnectionError, socket.gaierror):
        return None


def bypass_captcha(captcha_url):
    captcha_image = requests.get(captcha_url, stream=True).content
    image = Image.open(BytesIO(captcha_image))
    captcha_text = pytesseract.image_to_string(image)
    return captcha_text


def bypass_javascript(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    dynamic_content_tag = soup.find(id='dynamic-content')
    dynamic_content = dynamic_content_tag.text if dynamic_content_tag else ""
    return dynamic_content


def main(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    if not domain:
        print("Invalid URL. Please enter a URL.")
        return

    dns_info = get_dns_info(domain)

    title = get_page_title(url)
    last_modified = get_last_modified(url)
    creation_date = get_creation_date(url)
    dns_info = get_dns_info(url)
    subdomains = get_subdomains(url)
    firewall_info = get_firewall_info(url)
    teknoloji = get_technologies(url)
    sertifika_bilgisi = get_sertifika_bilgisi(url)  # Sertifika bilgisini al

    print("Site Information:")
    print("Title: ", title)
    print("Last Updated Date: ", last_modified)
    print("First Creation Date: ", creation_date)
    print("Dns Information: ", dns_info)
    print("Sub Branches: ", subdomains)
    print("Firewall Names: ", firewall_info)

    # Check the technologies used
    if teknoloji:
        print("Technologies Used: ", ", ".join(teknoloji))
    else:
        print("Technologies Used: No technology identified.")

    # Check certificate information
    if sertifika_bilgisi:
        print("Certificate Information:")
        for key, value in sertifika_bilgisi.items():
            print(key + ":", value)
    else:
        print("Certificate Information: No certificate detected.")

    # Bypass operations
    if 'captcha' in teknoloji:
        captcha_url = input("Enter the Captcha URL: ")
        captcha_text = bypass_captcha(captcha_url)
        print("Bypassed Captcha: ", captcha_text)

    if 'javascript' in teknoloji:
        dynamic_content = bypass_javascript(url)
        print("Bypassed JavaScript content: ", dynamic_content)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Web Information Program')
    parser.add_argument('url', help='Enter the site URL')
    args = parser.parse_args()
    main(args.url)