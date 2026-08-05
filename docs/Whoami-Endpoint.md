# Whoami Endpoint

<!-- cSpell:disable -->

URI Path: `/endocyst-regardable-unstrictured-mullenize-coup/whoami`

Behavior:
  - validate an existing homelab auth cookie, and then return request information in as JSON

Goal:
  - hidden, authenticed endpoint that SPAs can use to extract the cookie data needed to build XHR requests.
  - randomly named, such that a Traefik `Path()` rule can expose the endpoint for all sites behind traefik

Example:

```bash
curl -sH 'Cookie: pecan_sandy_2608=testuser.anFJlg.EGa4RS8Htyhhyher1JFNI-zJXnM' \
  http://127.0.0.1:55000/endocyst-regardable-unstrictured-mullenize-coup/whoami  | jq
{
  "cookie": "testuser.anFJlg.EGa4RS8Htyhhyher1JFNI-zJXnM",
  "cookie_domain": ".0.0.1:55000",
  "cookie_name": "pecan_sandy_2608",
  "headers": {
    "Accept": "*/*",
    "Cookie": "pecan_sandy_2608=testuser.anFJlg.EGa4RS8Htyhhyher1JFNI-zJXnM",
    "Host": "127.0.0.1:55000",
    "User-Agent": "curl/8.7.1"
  },
  "remote_addr": "192.168.65.1",
  "user_agent": "curl/8.7.1",
  "username": "testuser"
}
```
