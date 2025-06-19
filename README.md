# inactive-hosts-whoisxml

```
httpx -l subs.txt -probe | grep FAILED | awk '{print $1}' > failed.txt
```

```
python3 checker.py failed.txt --api-key <whoisxml_api_key>

IP DOMAIN STATUS_CODE CONTENT_LENGTH TITLE
123.123.123.123 example.com 404 969 No Title
```
