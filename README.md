# http-sniffer
sniff and parse HTTP requests using libpcap.

steps (linux only):
- `gcc readfile_ex.c -o capture -lpcap`
- `sudo ./capture`

sample output:
```
1635868251:106629 ee:ee:ee:ee:ee:ee --> 5a:5a:5a:ee:ee:ee 172.16.160.40 --> 54.156.165.4 TCP 80 --> 41284
GET /anything HTTP/1.1
Host: httpbin.org
User-Agent: curl/7.65.3
Accept: */*
```
