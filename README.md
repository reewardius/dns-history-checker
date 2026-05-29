# dns-history-checker

Discovers real origin IPs hidden behind Cloudflare and other CDNs using historical DNS data from the [SecurityTrails API](https://securitytrails.com). Probes each IP directly with a spoofed `Host` header to confirm accessibility.

## Requirements

- Python 3.8+
- [SecurityTrails API key](https://securitytrails.com/app/account/credentials) (free tier: 50 queries/month)

```bash
pip install requests beautifulsoup4
```

## Usage

```
python dns-history-checker.py (-d DOMAIN | -f FILE) -k API_KEY [-v] [-a] [-o OUTPUT]
```

| Flag | Description |
|------|-------------|
| `-d` | Single domain |
| `-f` | File with one domain per line |
| `-k` | SecurityTrails API key **(required)** |
| `-v` | Verbose debug output |
| `-a` | Append `nuclei` / `ffuf` commands to findings |
| `-o` | Save results to file |

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

## Notes

- Each domain uses 2 API requests (historical + current A records)
- Only responds to status `200` / `404` — redirects and WAF blocks are skipped
- Certificate verification is disabled — origin servers behind CDNs often have mismatched certs

## Disclaimer

For authorized security testing only. The authors assume no liability for misuse.
