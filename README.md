# dns-history-checker

Discovers real origin IPs hidden behind Cloudflare and other CDNs using historical DNS data from the [SecurityTrails API](https://securitytrails.com). Probes each IP directly with a spoofed `Host` header to confirm accessibility.

## Requirements

- Python 3.8+
- [SecurityTrails API key](https://securitytrails.com/app/account/credentials) (free tier: 50 queries/month)

```bash
pip install requests beautifulsoup4
```

## Workflow

**Step 1:** Get failed resolve domains  
Use `httpx` to probe subdomains and extract those that failed to resolve:
```bash
httpx -l subs.txt -probe | grep FAILED | awk '{gsub(/^https?:\/\//, "", $1); split($1, a, "/"); print a[1]}' > failed.txt
```
This creates a `failed.txt` file with domains that failed to respond.

**Step 2:** Run dns-history-checker against the failed domains:
```bash
python dns-history-checker.py -f failed.txt -k YOUR_API_KEY -o results.txt
```

---

## Usage

```
python dns-history-checker.py (-d DOMAIN | -f FILE) -k API_KEY [-v] [-a] [-o OUTPUT]
```

| Flag | Description |
|------|-------------|
| `-d DOMAIN` | Single domain to check |
| `-f FILE` | File with domains, one per line |
| `-k API_KEY` | SecurityTrails API key (required) |
| `-v` | Verbose output — shows all requests and FP-check comparisons |
| `-a` | Advanced mode — print nuclei + ffuf commands for each finding |
| `-o FILE` | Save results to file (writes immediately, no buffering) |
| `--skip-cloudflare` | Skip findings where Cloudflare is detected |
| `--redirect` | Follow HTTP redirects (default: disabled) |

**Examples:**
```bash
# Single domain
python dns-history-checker.py -d example.com -k YOUR_API_KEY

# Bulk + save output
python dns-history-checker.py -f domains.txt -k YOUR_API_KEY -o results.txt

# Full recon mode
python dns-history-checker.py -f domains.txt -k YOUR_API_KEY -a -v -o results.txt
```

## Output

```
Finding №1 example.com
1.2.3.4 example.com 200 54321 Homepage Title (Cloudflare: NO)
######
```

With `-a`:
```
Advanced Commands:
nuclei -u https://1.2.3.4 -H "Host: example.com" -rl 100 -c 25 -es unknown
ffuf -u https://1.2.3.4/FUZZ -H "Host: example.com" -mc 200 -w top.txt -ac -fs 0
```

## False positive filter
 
Every finding is verified by making a second request to the same IP **without** a Host header and comparing:
- Status code
- Content length
- Page title

If all three match → the server responds identically to everyone → not a real origin for this domain → skipped.

---
 
## Examples
 
Single domain, save to file, advanced commands:
```bash
python dns-history-checker.py -d target.com -k API_KEY -a -o results.txt
```
 
Bulk scan, skip Cloudflare IPs, verbose:
```bash
python dns-history-checker.py -f domains.txt -k API_KEY --skip-cloudflare -v
```
 
Follow redirects to get final page titles:
```bash
python dns-history-checker.py -d target.com -k API_KEY --redirect
```


## Disclaimer

For authorized security testing only. The authors assume no liability for misuse.
