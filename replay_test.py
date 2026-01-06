import json
import requests

BASE = "http://localhost:8000"

#protection is enforced at the server boundary via:

#Single-use challenge (popped from session on first verify), and

#Challenge TTL (so even unused challenges expire).

#Copied it from the browser cookie
SESSION_COOKIE_VALUE = "eyJhdXRoX3VzZXJuYW1lIjogIm11amlidXIiLCAidXNlciI6IHsidXNlcm5hbWUiOiAibXVqaWJ1ciJ9fQ==.aV0B3A.AEbOdIIiG6Dxvv869NTarLukZ6s"

with open("assertion.json", "r", encoding="utf-8") as f:
    assertion = json.load(f)

s = requests.Session()
s.cookies.set("session", SESSION_COOKIE_VALUE, domain="localhost", path="/")

r = s.post(f"{BASE}/api/login/verify", json={"credential": assertion})
print("Status:", r.status_code)
print("Body:", r.text)

#The result of the test would be failed
#python replay_test.py
#Status: 400
#Body: {"detail":"login expired (start over)"}
