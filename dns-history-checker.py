import sys
import time
import requests
import argparse
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

ST_REQUEST_DELAY = 0.25
SECURITYTRAILS_API_BASE = "https://api.securitytrails.com/v1"


class CustomAdapter(HTTPAdapter):
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
    try:
        parsed = urlparse(domain)
        if parsed.netloc:
            return parsed.netloc
        return domain.split('/')[0].strip()
    except Exception:
        return domain.strip()


def _st_get(url, api_key, label, verbose=False):
    headers = {"APIKEY": api_key, "Accept": "application/json"}
    for attempt in range(2):
        try:
            if verbose:
                print(f"  GET {url}", file=sys.stderr)
            resp = requests.get(url, headers=headers, timeout=15)
            if verbose:
                print(f"  Status: {resp.status_code}", file=sys.stderr)

            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 401:
                print("  [ERROR] Invalid or missing SecurityTrails API key.", file=sys.stderr)
                sys.exit(1)
            elif resp.status_code == 429:
                wait = 10 * (attempt + 1)
                print(f"  [WARN] Rate limit hit on {label} — retrying in {wait}s...", file=sys.stderr)
                time.sleep(wait)
            else:
                if verbose:
                    print(f"  {label} returned {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
                return None
        except requests.RequestException as e:
            if verbose:
                print(f"  Error on {label}: {e}", file=sys.stderr)
            return None
    print(f"  [ERROR] Giving up on {label} after rate limit retries.", file=sys.stderr)
    return None


def get_a_record(domain, api_key, verbose=False):
    ip_addresses = set()

    data = _st_get(
        f"{SECURITYTRAILS_API_BASE}/history/{domain}/dns/a",
        api_key, "history", verbose
    )
    if data:
        for record in data.get("records", []):
            for val in record.get("values", []):
                ip = val.get("ip")
                if ip:
                    ip_addresses.add(ip)
                    if verbose:
                        print(f"  Historical IP: {ip}", file=sys.stderr)

    time.sleep(ST_REQUEST_DELAY)

    data = _st_get(
        f"{SECURITYTRAILS_API_BASE}/domain/{domain}/dns/a",
        api_key, "current", verbose
    )
    if data:
        for record in data.get("records", []):
            for val in record.get("values", []):
                ip = val.get("ip")
                if ip:
                    ip_addresses.add(ip)
                    if verbose:
                        print(f"  Current IP: {ip}", file=sys.stderr)

    return list(ip_addresses)


VALID_STATUSES = (200, 301, 302, 303, 307, 308, 404)


def _parse_response(response, protocol, verbose=False):
    content_length = len(response.content)

    if response.status_code in (301, 302, 303, 307, 308):
        location = response.headers.get('Location', 'No Location')
        title = f"-> {location}"
        if verbose:
            print(f"  Redirect: {location}", file=sys.stderr)
    else:
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


def make_http_request(ip, domain, follow_redirects=False, verbose=False):
    """Request WITH Host header — targeted probe."""
    headers = {"Host": domain}
    session = requests.Session()
    session.mount('https://', CustomAdapter())

    if verbose:
        print(f"  HTTPS → https://{ip}/ (Host: {domain})", file=sys.stderr)
    try:
        response = session.get(
            f"https://{ip}/",
            headers=headers,
            verify=False,
            allow_redirects=follow_redirects,
            timeout=10,
        )
        if verbose:
            print(f"  Status: {response.status_code}", file=sys.stderr)
        if response.status_code in VALID_STATUSES:
            return _parse_response(response, 'https', verbose)
        elif verbose:
            print(f"  Skipping HTTPS — status {response.status_code}", file=sys.stderr)
    except requests.RequestException as e:
        if verbose:
            print(f"  HTTPS failed: {e}", file=sys.stderr)

    if verbose:
        print(f"  HTTP  → http://{ip}/ (Host: {domain})", file=sys.stderr)
    try:
        response = session.get(
            f"http://{ip}/",
            headers=headers,
            allow_redirects=follow_redirects,
            timeout=10,
        )
        if verbose:
            print(f"  Status: {response.status_code}", file=sys.stderr)
        if response.status_code in VALID_STATUSES:
            return _parse_response(response, 'http', verbose)
        elif verbose:
            print(f"  Skipping HTTP — status {response.status_code}", file=sys.stderr)
    except requests.RequestException as e:
        if verbose:
            print(f"  HTTP failed: {e}", file=sys.stderr)

    return None


def make_http_request_no_host(ip, protocol, follow_redirects=False, verbose=False):
    """Request WITHOUT Host header — used for false positive detection."""
    session = requests.Session()
    session.mount('https://', CustomAdapter())

    if verbose:
        print(f"  FP-check {protocol}://{ip}/ (no Host header)", file=sys.stderr)
    try:
        response = session.get(
            f"{protocol}://{ip}/",
            verify=False,
            allow_redirects=follow_redirects,
            timeout=10,
        )
        if verbose:
            print(f"  FP-check status: {response.status_code}", file=sys.stderr)
        if response.status_code in VALID_STATUSES:
            return _parse_response(response, protocol, verbose)
    except requests.RequestException as e:
        if verbose:
            print(f"  FP-check failed: {e}", file=sys.stderr)

    return None


def is_false_positive(result, ip, follow_redirects=False, verbose=False):
    """
    Returns True if the IP responds identically without a Host header —
    meaning it's likely a default vhost, not the real origin for this domain.
    Compares: status_code + content_length + title.
    """
    baseline = make_http_request_no_host(ip, result['protocol'], follow_redirects, verbose)
    if baseline is None:
        return False

    match = (
        baseline['status_code'] == result['status_code']
        and baseline['content_length'] == result['content_length']
        and baseline['title'] == result['title']
    )

    if match and verbose:
        print(f"  False positive — identical response without Host header", file=sys.stderr)

    return match


def generate_advanced_commands(ip, domain, protocol, cloudflare):
    nuclei_cmd = f'nuclei -u {protocol}://{ip} -H "Host: {domain}" -rl 100 -c 25 -es unknown'
    if cloudflare == 'YES':
        nuclei_cmd += ' -itags config,exposure'
    return [
        nuclei_cmd,
        f'ffuf -u {protocol}://{ip}/FUZZ -H "Host: {domain}" -mc 200 -w top.txt -ac -fs 0',
    ]


def write_line(line, output_file=None):
    print(line)
    if output_file:
        output_file.write(line + '\n')
        output_file.flush()


def main():
    parser = argparse.ArgumentParser(
        description='Find origin IPs behind CDN using SecurityTrails API and probe HTTP responses'
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d', '--domain', help='Single domain to check')
    group.add_argument('-f', '--file', help='File containing list of domains (one per line)')
    parser.add_argument('-k', '--api-key', required=True,
                        help='SecurityTrails API key')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Show detailed debug output on stderr')
    parser.add_argument('-a', '--advanced', action='store_true',
                        help='Print nuclei / ffuf commands for each finding')
    parser.add_argument('-o', '--output', help='File to save results')
    parser.add_argument('--skip-cloudflare', action='store_true',
                        help='Skip targets where Cloudflare is detected')
    parser.add_argument('--redirect', action='store_true',
                        help='Follow HTTP redirects (default: disabled)')
    args = parser.parse_args()

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

    output_file = None
    if args.output:
        try:
            output_file = open(args.output, 'w', encoding='utf-8', buffering=1)
        except Exception as e:
            print(f"Error opening output file: {e}", file=sys.stderr)
            sys.exit(1)

    finding_count = 0
    seen_results = set()

    try:
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

                result = make_http_request(ip, cleaned, args.redirect, args.verbose)
                if not result:
                    if args.verbose:
                        print(f"  No usable response from {ip}", file=sys.stderr)
                    continue

                key = (ip, cleaned, result['status_code'], result['content_length'],
                       result['title'], result['cloudflare'])
                if key in seen_results:
                    if args.verbose:
                        print(f"  Duplicate — skipping", file=sys.stderr)
                    continue
                seen_results.add(key)

                if args.skip_cloudflare and result['cloudflare'] == 'YES':
                    if args.verbose:
                        print(f"  Skipping {ip} — Cloudflare detected", file=sys.stderr)
                    continue

                if is_false_positive(result, ip, args.redirect, args.verbose):
                    if args.verbose:
                        print(f"  Skipping {ip} — false positive", file=sys.stderr)
                    continue

                finding_count += 1
                lines = [
                    f"\nFinding №{finding_count} {cleaned}",
                    f"{ip} {cleaned} [{result['status_code']}] {result['content_length']} "
                    f"{result['title']} (Cloudflare: {result['cloudflare']})",
                ]

                if args.advanced:
                    lines.append("Advanced Commands:")
                    lines.extend(generate_advanced_commands(
                        ip, cleaned, result['protocol'], result['cloudflare']
                    ))

                lines.append("######")

                for line in lines:
                    write_line(line, output_file)

    finally:
        if output_file:
            output_file.close()


if __name__ == "__main__":
    main()
