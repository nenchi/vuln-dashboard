#!/usr/bin/env python3
"""End-to-end check against a running dashboard (stdlib only). CI runs it against the built image
with tests/fixture/state mounted; feeds are switched off, so no internet is needed.

  python3 tests/smoke_test.py http://127.0.0.1:8080 [expected-version]
"""
import http.cookiejar
import json
import re
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8080"
VERSION = sys.argv[2] if len(sys.argv) > 2 else re.search(r'VERSION = "([^"]+)"', open("app/app.py").read())[1]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def client():
    """a browser: own cookie jar, redirects not followed so we can see them"""
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), NoRedirect)


def call(c, path, method="GET", body=None):
    req = urllib.request.Request(BASE + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"} if body is not None else {})
    try:
        with c.open(req, timeout=10) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


def ok(cond, what):
    if not cond:
        sys.exit(f"FAIL: {what}")
    print(f"ok   {what}")


def main():
    a, b = client(), client()
    for _ in range(30):  # container start
        try:
            if call(a, "/healthz")[0] == 200:
                break
        except OSError:
            pass
        time.sleep(1)
    ok(call(a, "/healthz")[0] == 200, "healthz")
    v = json.loads(call(a, "/api/version")[1])["version"]
    ok(v == VERSION, f"version {v} == {VERSION}")
    code, body, _ = call(a, "/")
    ok(code == 200 and b"Vulnerability Dashboard" in body, "dashboard page")
    listing = [f["name"] for f in json.loads(call(a, "/state/")[1])]
    ok("demo.json" in listing, "state/ JSON listing")
    ok("demo.json" in [f["name"] for f in json.loads(call(a, "/state/packages/")[1])], "state/packages/ listing")
    ok(json.loads(call(a, "/state/demo.json")[1])["repo"] == "demo", "scan file served")

    # Settings: feeds off (no internet in CI), watch a CVE and a package, run now
    code, body, _ = call(a, "/api/sources", "PUT", {"schedule": "manual", "feeds": [
        {"name": "CISA KEV", "type": "kev", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "enabled": False}],
        "watch": [{"cve": "CVE-2021-44228", "note": "smoke"}, {"pkg": "php8.2-cli", "note": "smoke"}], "keep_days": 90, "stale_days": 3})
    ok(code == 200, "save settings")
    ok(json.loads(call(a, "/api/keep")[1]) == {"days": 90, "env": False, "stale": 3}, "keep history and stale days saved")
    ok(call(a, "/api/sources", "PUT", {"schedule": "every 1m"})[0] == 400, "reject too frequent schedule")
    hot = {}
    for _ in range(20):
        code, body, _ = call(a, "/state/hot/exploited.json")
        hot = json.loads(body) if code == 200 else {}
        if "CVE-2021-44228" in hot.get("cves", {}) and "php8.2-cli" in hot.get("pkgs", {}):
            break
        time.sleep(0.5)
    ok("CVE-2021-44228" in hot.get("cves", {}) and "php8.2-cli" in hot.get("pkgs", {}), "scheduler wrote watchlist marks")
    ok(hot.get("schedule") == "manual" and hot.get("next") is None, "manual mode: no next run")
    ok(call(a, "/api/run", "POST", {})[0] == 202, "check now")
    ok(call(a, "/api/sources", "PUT", {})[0] in (400, 415) and call(a, "/api/sources", "POST", {})[0] == 404, "bad requests refused")
    ok(call(a, "/api/sources", "PUT", None)[0] == 415, "non-JSON refused (cross-site guard)")

    # login: lock everything; a has the session (it set the login), b is a new browser
    code, _, hdr = call(a, "/api/auth", "PUT", {"lock": "all", "user": "admin", "password": "smoke-pass-123"})
    ok(code == 200 and "HttpOnly" in hdr.get("Set-Cookie", ""), "set login, session cookie")
    ok(call(a, "/")[0] == 200 and json.loads(call(a, "/api/auth")[1])["logged_in"], "owner stays logged in")
    code, _, hdr = call(b, "/")
    ok(code == 302 and hdr.get("Location", "").startswith("/login.html"), "locked page redirects to login")
    ok(call(b, "/state/demo.json")[0] == 401 and call(b, "/api/sources")[0] == 401, "locked data and API")
    ok(call(b, "/healthz")[0] == 200 and call(b, "/login.html")[0] == 200 and call(b, "/reset.html")[0] == 200, "open pages stay open")
    for path in ("/state/hot/auth.json", "/state/hot/auth.json?x", "/state//hot/./auth.json", "/state/hot/auth%2ejson"):
        ok(call(a, path)[0] == 404, f"auth file never served: {path}")
    ok("auth.json" not in [f["name"] for f in json.loads(call(a, "/state/hot/")[1])], "auth file not listed")
    ok(call(b, "/api/login", "POST", {"user": "admin", "password": "wrong"})[0] == 403, "wrong password refused")
    ok(call(b, "/api/login", "POST", {"user": "admin", "password": "smoke-pass-123"})[0] == 200, "login")
    ok(call(b, "/")[0] == 200, "logged in sees dashboard")
    ok(call(b, "/api/logout", "POST", {})[0] == 200 and call(b, "/")[0] == 302, "logout")
    # every change needs the login (GET /api/auth is open, PUT must not be)
    ok(call(b, "/api/auth", "PUT", {"lock": "off"})[0] == 401, "can't remove the login without it")
    ok(call(b, "/api/auth", "PUT", {"lock": "edit", "user": "evil", "password": "12345678"})[0] == 401, "can't replace the login without it")
    ok(call(b, "/api/sources", "PUT", {"schedule": "off"})[0] == 401, "can't change settings without it")
    ok(call(b, "/api/run", "POST", {})[0] == 401, "can't start a check without it")
    ok(json.loads(call(b, "/api/auth")[1]) == {"lock": "all", "logged_in": False, "user": ""}, "lock status open, no username")
    ok(call(b, "/api/keep")[0] == 200, "keep history open (the Range list needs it)")
    ok(call(b, "/api/reset", "PUT", {"code": "AAAA-BBBB", "user": "x", "password": "12345678"})[0] == 400, "reset needs a requested code")
    ok(call(a, "/api/auth", "PUT", {"lock": "off"})[0] == 200 and call(b, "/")[0] == 200, "login removed, open again")
    print("smoke test passed")


if __name__ == "__main__":
    main()
