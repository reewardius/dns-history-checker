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

SECURITYTRAILS_API_BASE = "https://api.securitytrails.com/v1"


class CustomAdapter(HTTPAdapter):
    """Adapter for managing TLS protocols — disables hostname/cert checks so
    it works with verify=False against bare IPs that have mismatched certs."""
    def init_poolmanager(self, *args, **kwargs):
        context = create_urllib3_context(ciphers='DEFAULT:@SECLEVEL=1')
        context.check_hostname = False
        context.verify_mode = __import__('ssl').CERT_NONE
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        context = create_urllib3_context(ciphers='DEFAULT:@SECLEVEL=1')
        context.check_hostname = False
        context.verify_mode = __import__('ssl').CERT_NONE
        proxy_kwargs['ssl_context'] = context
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def clean_domain(domain):
    """Clean domain from scheme and path"""
    try:
        parsed = urlparse(domain)
        if parsed.netloc:
            return parsed.netloc
        return domain.split('/')[0].strip()
    except Exception as e:
        return domain.strip()


def get_a_record(domain, api_key, verbose=False):
    """
    Fetch unique A records via SecurityTrails API.

    Uses two endpoints:
      1. /domain/{domain}/dns/history/a  — historical A records
      2. /domain/{domain}                — current DNS records (fallback)
    """
    headers = {
        "APIKEY": api_key,
        "Accept": "application/json",
    }
    ip_addresses = set()

    # ── 1. Historical A records ──────────────────────────────────────────────
    url = f"{SECURITYTRAILS_API_BASE}/history/{domain}/dns/a"
    if verbose:
        print(f"  GET {url}", file=sys.stderr)

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if verbose:
            print(f"  Status: {resp.status_code}", file=sys.stderr)

        if resp.status_code == 200:
            data = resp.json()
            # Response structure:
            # { "records": [ { "values": [ { "ip": "1.2.3.4", ... } ], ... } ] }
            for record in data.get("records", []):
                for val in record.get("values", []):
                    ip = val.get("ip")
                    if ip:
                        ip_addresses.add(ip)
                        if verbose:
                            print(f"  Historical IP: {ip}", file=sys.stderr)
        elif resp.status_code == 401:
            print("  [ERROR] Invalid or missing SecurityTrails API key.", file=sys.stderr)
            sys.exit(1)
        elif resp.status_code == 429:
            print("  [WARN] Rate limit exceeded for SecurityTrails API.", file=sys.stderr)
        else:
            if verbose:
                print(f"  History endpoint returned {resp.status_code}: {resp.text[:200]}", file=sys.stderr)

    except requests.RequestException as e:
        if verbose:
            print(f"  Error fetching historical A records: {e}", file=sys.stderr)

    # ── 2. Current DNS records (fallback / supplement) ────────────────────────
    url_current = f"{SECURITYTRAILS_API_BASE}/domain/{domain}/dns/a"
    if verbose:
        print(f"  GET {url_current}", file=sys.stderr)

    try:
        resp = requests.get(url_current, headers=headers, timeout=15)
        if verbose:
            print(f"  Status: {resp.status_code}", file=sys.stderr)

        if resp.status_code == 200:
            data = resp.json()
            # Response structure:
            # { "type": "a", "records": [ { "values": [ { "ip": "..." } ] } ] }
            for record in data.get("records", []):
                for val in record.get("values", []):
                    ip = val.get("ip")
                    if ip:
                        ip_addresses.add(ip)
                        if verbose:
                            print(f"  Current IP: {ip}", file=sys.stderr)
        elif resp.status_code == 401:
            print("  [ERROR] Invalid or missing SecurityTrails API key.", file=sys.stderr)
            sys.exit(1)
        elif resp.status_code == 429:
            print("  [WARN] Rate limit exceeded for SecurityTrails API.", file=sys.stderr)
        else:
            if verbose:
                print(f"  Current endpoint returned {resp.status_code}: {resp.text[:200]}", file=sys.stderr)

    except requests.RequestException as e:
        if verbose:
            print(f"  Error fetching current A records: {e}", file=sys.stderr)

    return list(ip_addresses)


def make_http_request(ip, domain, verbose=False):
    """Make HTTP/HTTPS request with Host header and check for Cloudflare"""
    headers = {"Host": domain}
    session = requests.Session()
    session.mount('https://', CustomAdapter())

    # ── Try HTTPS first ───────────────────────────────────────────────────────
    if verbose:
        print(f"  HTTPS → https://{ip}/ (Host: {domain})", file=sys.stderr)
    try:
        response = session.get(
            f"https://{ip}/",
            headers=headers,
            verify=False,
            allow_redirects=True,
            timeout=10,
        )
        if verbose:
            print(f"  Status: {response.status_code}", file=sys.stderr)

        if response.status_code in (200, 404):
            return _parse_response(response, 'https', verbose)
        elif verbose:
            print(f"  Skipping HTTPS — status {response.status_code}", file=sys.stderr)

    except requests.RequestException as e:
        if verbose:
            print(f"  HTTPS failed: {e}", file=sys.stderr)

    # ── Fallback to HTTP ──────────────────────────────────────────────────────
    if verbose:
        print(f"  HTTP  → http://{ip}/ (Host: {domain})", file=sys.stderr)
    try:
        response = session.get(
            f"http://{ip}/",
            headers=headers,
            allow_redirects=True,
            timeout=10,
        )
        if verbose:
            print(f"  Status: {response.status_code}", file=sys.stderr)

        if response.status_code in (200, 404):
            return _parse_response(response, 'http', verbose)
        elif verbose:
            print(f"  Skipping HTTP — status {response.status_code}", file=sys.stderr)

    except requests.RequestException as e:
        if verbose:
            print(f"  HTTP failed: {e}", file=sys.stderr)

    return None


def _parse_response(response, protocol, verbose=False):
    """Extract metadata from an HTTP response object"""
    content_length = len(response.content)
    title = 'No Title'

    if response.headers.get('content-type', '').startswith('text/html'):
        soup = BeautifulSoup(response.content, 'html.parser')
        tag = soup.find('title')
        if tag:
            title = tag.text.strip().replace('\n', ' ').replace('\r', ' ')
            if verbose:
                print(f"  Title: {title}", file=sys.stderr)

    server_header = response.headers.get('Server', '').lower()
    cloudflare = 'YES' if 'cloudflare' in server_header else 'NO'
    if verbose:
        print(f"  Cloudflare: {cloudflare}", file=sys.stderr)

    return {
        'status_code': response.status_code,
        'content_length': content_length,
        'title': title,
        'final_url': response.url,
        'cloudflare': cloudflare,
        'protocol': protocol,
    }


def generate_advanced_commands(ip, domain, protocol):
    """Generate nuclei and ffuf commands for a discovered origin IP"""
    return [
        f'nuclei -u {protocol}://{ip} -H "Host: {domain}" -rl 100 -c 25 -es unknown',
        f'ffuf -u {protocol}://{ip}/FUZZ -H "Host: {domain}" -mc 200 -w top.txt -ac -fs 0',
    ]


def main():
    parser = argparse.ArgumentParser(
        description='Find origin IPs behind CDN using SecurityTrails API and probe HTTP responses'
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='Single domain to check')
    group.add_argument('-f', '--file', help='File containing list of domains (one per line)')
    parser.add_argument('-k', '--api-key', required=True,
                        help='SecurityTrails API key (https://securitytrails.com/app/account/credentials)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed debug output on stderr')
    parser.add_argument('-a', '--advanced', action='store_true',
                        help='Print nuclei / ffuf commands for each finding')
    parser.add_argument('-o', '--output', help='File to save results')
    args = parser.parse_args()

    # ── Collect domains ───────────────────────────────────────────────────────
    domains = []
    if args.domain:
        domains = [args.domain]
    else:
        try:
            with open(args.file, 'r', encoding='utf-8') as fh:
                domains = [line.strip() for line in fh if line.strip()]
        except FileNotFoundError:
            print(f"File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)

    # ── Open optional output file ─────────────────────────────────────────────
    output_file = None
    if args.output:
        try:
            output_file = open(args.output, 'w', encoding='utf-8')
        except Exception as e:
            print(f"Error opening output file: {e}", file=sys.stderr)
            sys.exit(1)

    finding_count = 0
    seen_results = set()

    # ── Main loop ─────────────────────────────────────────────────────────────
    for domain in domains:
        cleaned = clean_domain(domain)
        if args.verbose:
            print(f"\n[*] Domain: {cleaned}", file=sys.stderr)

        ip_addresses = get_a_record(cleaned, args.api_key, args.verbose)

        if not ip_addresses:
            if args.verbose:
                print(f"  No A records found for {cleaned}", file=sys.stderr)
            continue

        if args.verbose:
            print(f"  {len(ip_addresses)} unique IP(s) found", file=sys.stderr)

        for ip in ip_addresses:
            if args.verbose:
                print(f"\n  [>] Probing {ip}", file=sys.stderr)

            result = make_http_request(ip, cleaned, args.verbose)
            if not result:
                if args.verbose:
                    print(f"  No usable response from {ip}", file=sys.stderr)
                continue

            # Deduplicate
            key = (ip, cleaned, result['status_code'], result['content_length'],
                   result['title'], result['cloudflare'])
            if key in seen_results:
                if args.verbose:
                    print(f"  Duplicate — skipping", file=sys.stderr)
                continue
            seen_results.add(key)

            finding_count += 1
            lines = [
                f"\nFinding №{finding_count} {cleaned}",
                f"{ip} {cleaned} {result['status_code']} {result['content_length']} "
                f"{result['title']} (Cloudflare: {result['cloudflare']})",
            ]

            if args.advanced:
                lines.append("Advanced Commands:")
                lines.extend(generate_advanced_commands(ip, cleaned, result['protocol']))

            lines.append("######")

            for line in lines:
                print(line)
                if output_file:
                    output_file.write(line + '\n')

    if output_file:
        output_file.close()


if __name__ == "__main__":
    main()
