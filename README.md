# dns-history-checker
A simple utility for identifying inactive or misconfigured domains. It helps extract failed domain resolutions and then verifies their DNS A records and HTTP responses using the DNS History website.

#### Features
- Extract failed HTTP probes from a list of subdomains.
- Check DNS A records and HTTP responses for each domain.
- Optional verbose mode for detailed inspection.
- Suitable for recon workflows and domain hygiene.

#### Requirements
- Python 3.6+
- `requests`, `bs4`, `argparse`
---

**Step 1:** Get Failed Resolve Domains

Use `httpx` to probe subdomains and extract those that failed to resolve:
```
httpx -l subs.txt -probe | grep FAILED | awk '{gsub(/^https?:\/\//, "", $1); split($1, a, "/"); print a[1]}' > failed.txt
```
This will create a `failed.txt` file containing domains that failed to respond.

**Step 2:** Check DNS A Records and HTTP Responses

Run the `dns-history-checker.py` script to verify the domains against the DNS History database and test HTTP response codes.
```
usage: dns-history-checker.py [-h] (-d DOMAIN | -f FILE) [-v] [-a] [-o OUTPUT]

Check DNS A records and HTTP responses using DNS History website

optional arguments:
  -h, --help                      # Show this help message and exit
  -d DOMAIN, --domain DOMAIN      # Single domain to check
  -f FILE, --file FILE            # File containing list of domains
  -v, --verbose                   # Show detailed debug output
  -a, --advanced                  # Generate nuclei and ffuf commands for successful results
  -o OUTPUT, --output OUTPUT      # Output file to save results
```
### Examples

**Check a single domain:**
```
python3 dns-history-checker.py -d example.com -a -v
```
**Check multiple domains from a file:**
```
python3 dns-history-checker.py -f failed.txt -a -o results.txt
```
**Output Format:**
```
Finding №1 example.com
123.123.123.123 example.com 404 969 No Title (Cloudflare: NO)

Advanced Commands:
nuclei -u https://123.123.123.123 -H "Host: example.com" -rl 100 -c 25 -es unknown
ffuf -u https://123.123.123.123/FUZZ -H "Host: example.com" -mc 200 -w top.txt -ac -fs 0
```
- `123.123.123.123`: Resolved IP address
- `example.com:` Domain name
- `404:` HTTP response code
- `969:` Response length (in bytes)
- `No Title:` HTML page title (if any)

### License
MIT License
