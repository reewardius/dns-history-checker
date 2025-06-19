import sys
import requests
import argparse
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

# Suppress insecure SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class CustomAdapter(HTTPAdapter):
    """Adapter for managing TLS protocols"""
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers='DEFAULT:@SECLEVEL=1')
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

def clean_domain(domain):
    """Clean domain from scheme and path"""
    try:
        parsed = urlparse(domain)
        if parsed.netloc:
            return parsed.netloc
        return domain.split('/')[0].strip()
    except Exception as e:
        if args.verbose:
            print(f"  Error cleaning domain {domain}: {e}", file=sys.stderr)
        return domain.strip()

def get_a_record(domain, verbose=False):
    """Fetch A records by scraping DNS History website"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }
    
    # Try first page
    url = f"https://dnshistory.org/dns-records/{domain}"
    if verbose:
        print(f"  Sending GET request to {url}", file=sys.stderr)
    
    ip_addresses = []
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        if verbose:
            print(f"  Response status code: {response.status_code}", file=sys.stderr)
            print(f"  Response headers: {response.headers}", file=sys.stderr)
        
        soup = BeautifulSoup(response.content, 'html.parser')
        a_section = soup.find('h3', text='A')
        if a_section:
            if verbose:
                print(f"  Found A record section on first page", file=sys.stderr)
            next_elements = a_section.find_next_siblings()
            for element in next_elements:
                if element.name == 'h3':  # Stop if we hit the next section
                    break
                links = element.find_all('a', href=True)
                for link in links:
                    if link.text.strip().replace('.', '').isdigit():  # Check if the text is an IP address
                        ip_addresses.append(link.text.strip())
                        if verbose:
                            print(f"  Found IP on first page: {link.text.strip()}", file=sys.stderr)
    except (requests.RequestException, ValueError) as e:
        if verbose:
            print(f"  Error fetching A records from first page for {domain}: {e}", file=sys.stderr)
    
    # If no IPs found, try second page
    if not ip_addresses:
        url = f"https://dnshistory.org/historical-dns-records/a/{domain}"
        if verbose:
            print(f"  No IPs found on first page, trying second page: {url}", file=sys.stderr)
        
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            if verbose:
                print(f"  Response status code: {response.status_code}", file=sys.stderr)
                print(f"  Response headers: {response.headers}", file=sys.stderr)
            
            soup = BeautifulSoup(response.content, 'html.parser')
            # Look for <p> tags containing IP addresses
            p_tags = soup.find_all('p')
            for p in p_tags:
                links = p.find_all('a', href=True)
                for link in links:
                    if link.text.strip().replace('.', '').isdigit():  # Check if the text is an IP address
                        ip_addresses.append(link.text.strip())
                        if verbose:
                            print(f"  Found IP on second page: {link.text.strip()}", file=sys.stderr)
        except (requests.RequestException, ValueError) as e:
            if verbose:
                print(f"  Error fetching A records from second page for {domain}: {e}", file=sys.stderr)
    
    return ip_addresses

def make_http_request(ip, domain, verbose=False):
    """Make HTTP request with specified Host header"""
    headers = {"Host": domain}
    session = requests.Session()
    session.mount('https://', CustomAdapter())
    
    # Try HTTPS
    if verbose:
        print(f"  Attempting HTTPS request to https://{ip}/ with Host: {domain}", file=sys.stderr)
    try:
        response = session.get(
            f"https://{ip}/",
            headers=headers,
            verify=False,
            allow_redirects=True,
            timeout=10
        )
        if verbose:
            print(f"  HTTPS response status code: {response.status_code}", file=sys.stderr)
            print(f"  HTTPS response headers: {response.headers}", file=sys.stderr)
        
        if response.status_code not in (200, 404):
            if verbose:
                print(f"  Skipping HTTPS response due to status code {response.status_code}", file=sys.stderr)
            return None
            
        content_length = len(response.content)
        title = None
        if response.headers.get('content-type', '').startswith('text/html'):
            soup = BeautifulSoup(response.content, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                title = title_tag.text.strip().replace('\n', ' ').replace('\r', ' ')
                if verbose:
                    print(f"  Found title: {title}", file=sys.stderr)
                
        return {
            'status_code': response.status_code,
            'content_length': content_length,
            'title': title or 'No Title',
            'final_url': response.url
        }
    except requests.RequestException as e:
        if verbose:
            print(f"  HTTPS request failed: {e}", file=sys.stderr)
    
    # Try HTTP
    if verbose:
        print(f"  Attempting HTTP request to http://{ip}/ with Host: {domain}", file=sys.stderr)
    try:
        response = session.get(
            f"http://{ip}/",
            headers=headers,
            allow_redirects=True,
            timeout=10
        )
        if verbose:
            print(f"  HTTP response status code: {response.status_code}", file=sys.stderr)
            print(f"  HTTP response headers: {response.headers}", file=sys.stderr)
        
        if response.status_code not in (200, 404):
            if verbose:
                print(f"  Skipping HTTP response due to status code {response.status_code}", file=sys.stderr)
            return None
            
        content_length = len(response.content)
        title = None
        if response.headers.get('content-type', '').startswith('text/html'):
            soup = BeautifulSoup(response.content, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                title = title_tag.text.strip().replace('\n', ' ').replace('\r', ' ')
                if verbose:
                    print(f"  Found title: {title}", file=sys.stderr)
                
        return {
            'status_code': response.status_code,
            'content_length': content_length,
            'title': title or 'No Title',
            'final_url': response.url
        }
    except requests.RequestException as e:
        if verbose:
            print(f"  HTTP request failed: {e}", file=sys.stderr)
        return None

def main():
    parser = argparse.ArgumentParser(description='Check DNS A records and HTTP responses using DNS History website')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='Single domain to check')
    group.add_argument('-f', '--file', help='File containing list of domains')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed debug output')
    args = parser.parse_args()
    
    # Determine domains to process
    domains = []
    if args.domain:
        domains = [args.domain]
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                domains = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"File {args.file} not found", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    
    for domain in domains:
        cleaned_domain = clean_domain(domain)
        
        if args.verbose:
            print(f"Checking domain: {cleaned_domain}", file=sys.stderr)
        
        ip_addresses = get_a_record(cleaned_domain, args.verbose)
        
        if not ip_addresses:
            if args.verbose:
                print(f"  No A records found for {cleaned_domain}", file=sys.stderr)
            continue
            
        if args.verbose:
            print(f"  Found {len(ip_addresses)} IP addresses", file=sys.stderr)
            
        for ip in ip_addresses:
            if args.verbose:
                print(f"  Checking IP: {ip}", file=sys.stderr)
                
            result = make_http_request(ip, cleaned_domain, args.verbose)
            if result:
                print(f"{ip} {cleaned_domain} {result['status_code']} {result['content_length']} {result['title']}")
            elif args.verbose:
                print(f"  No response from {ip}", file=sys.stderr)

if __name__ == "__main__":
    main()