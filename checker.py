import sys
import requests
import argparse
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

# Подавляем предупреждения о небезопасных SSL-соединениях
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class CustomAdapter(HTTPAdapter):
    """Адаптер для управления TLS-протоколами"""
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers='DEFAULT:@SECLEVEL=1')
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

def clean_domain(domain):
    """Очистка домена от схемы и пути"""
    try:
        parsed = urlparse(domain)
        if parsed.netloc:
            return parsed.netloc
        return domain.split('/')[0].strip()
    except Exception:
        return domain.strip()

def get_a_record(domain, api_key):
    """Получение A-записи из DNS History API"""
    url = "https://dns-history.whoisxmlapi.com/api/v1"
    payload = {
        "apiKey": api_key,
        "searchType": "forward",
        "recordType": "a",
        "domainName": domain
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if 'result' in data and data['result'] and 'after' in data['result'] and data['result']['after'] and 'ip' in data['result']['after']:
            ip = data['result']['after']['ip']
            return [ip] if ip else []
        return []
    except (requests.RequestException, ValueError):
        return []

def make_http_request(ip, domain):
    """Выполнение HTTP-запроса с указанным Host заголовком"""
    headers = {"Host": domain}
    session = requests.Session()
    session.mount('https://', CustomAdapter())
    
    # Пробуем HTTPS
    try:
        response = session.get(
            f"https://{ip}/",
            headers=headers,
            verify=False,
            allow_redirects=True,
            timeout=10
        )
        if response.status_code not in (200, 404):
            return None
            
        content_length = len(response.content)
        title = None
        if response.headers.get('content-type', '').startswith('text/html'):
            soup = BeautifulSoup(response.content, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                title = title_tag.text.strip().replace('\n', ' ').replace('\r', ' ')
                
        return {
            'status_code': response.status_code,
            'content_length': content_length,
            'title': title or 'No Title',
            'final_url': response.url
        }
    except requests.RequestException:
        pass
    
    # Пробуем HTTP
    try:
        response = session.get(
            f"http://{ip}/",
            headers=headers,
            allow_redirects=True,
            timeout=10
        )
        if response.status_code not in (200, 404):
            return None
            
        content_length = len(response.content)
        title = None
        if response.headers.get('content-type', '').startswith('text/html'):
            soup = BeautifulSoup(response.content, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                title = title_tag.text.strip().replace('\n', ' ').replace('\r', ' ')
                
        return {
            'status_code': response.status_code,
            'content_length': content_length,
            'title': title or 'No Title',
            'final_url': response.url
        }
    except requests.RequestException:
        return None

def main():
    parser = argparse.ArgumentParser(description='Check DNS A records and HTTP responses')
    parser.add_argument('input_file', help='File containing list of domains')
    parser.add_argument('--api-key', default='at_weMWy3Vmx51K1sBgUnNmvUICSJrr3', 
                       help='WhoisXML API key')
    args = parser.parse_args()
    
    try:
        with open(args.input_file, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Файл {args.input_file} не найден", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка при чтении файла: {e}", file=sys.stderr)
        sys.exit(1)
    
    for domain in domains:
        cleaned_domain = clean_domain(domain)
        ip_addresses = get_a_record(cleaned_domain, args.api_key)
        
        if not ip_addresses:
            continue
            
        for ip in ip_addresses:
            result = make_http_request(ip, cleaned_domain)
            if result:
                print(f"{ip} {cleaned_domain} {result['status_code']} {result['content_length']} {result['title']}")

if __name__ == "__main__":
    main()