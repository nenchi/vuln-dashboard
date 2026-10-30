"""python3 app/test_app.py — checks feeds, watchlist, broken-feed fallback, schedules and validation in app.py."""
import datetime as dt
import json

import app as hot

kev = json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228", "vulnerabilityName": "Log4Shell"}]})
cfg = {"feeds": [{"name": "KEV", "type": "kev", "url": "k"}, {"name": "blog", "url": "b"}],
       "watch": [{"cve": "cve-2021-44228", "note": "patch now"}, {"pkg": "PHP", "note": "zero-day"}]}
pages = {"k": kev, "b": "see cve-2025-55182 and CVE-2024-4577."}

r = hot.build(cfg, pages.__getitem__, {})
assert set(r["cves"]) == {"CVE-2021-44228", "CVE-2025-55182", "CVE-2024-4577"}
assert r["cves"]["CVE-2021-44228"] == {"src": "watchlist", "note": "patch now"}  # watchlist note wins
assert r["cves"]["CVE-2024-4577"]["src"] == "blog"
assert r["pkgs"] == {"php": {"src": "watchlist", "note": "zero-day"}} and r["errors"] == []

# blog down: its CVEs survive from the previous run, KEV still refreshes
def down(url):
    if url == "b":
        raise OSError("timeout")
    return pages[url]
r2 = hot.build(cfg, down, r)
assert "CVE-2025-55182" in r2["cves"] and r2["errors"] == ["blog: timeout"]

# schedules: last run Wed 2026-10-21 10:00
t = dt.datetime(2026, 10, 21, 10, 0)
assert hot.next_run("every 1h", t) == dt.datetime(2026, 10, 21, 11, 0)
assert hot.next_run("Every 30m", t) == dt.datetime(2026, 10, 21, 10, 30)
assert hot.next_run("daily 06:00", t) == dt.datetime(2026, 10, 22, 6, 0)
assert hot.next_run("daily 18:30", t) == dt.datetime(2026, 10, 21, 18, 30)
assert hot.next_run("weekly mon 06:00", t) == dt.datetime(2026, 10, 26, 6, 0)
assert hot.next_run("weekly wed 10:00", t) == dt.datetime(2026, 10, 28, 10, 0)  # same moment = next week
assert hot.next_run("weekly wed 11:00", t) == dt.datetime(2026, 10, 21, 11, 0)
for bad in ["hourly", "every 0h", "daily 25:00", "weekly xyz 06:00"]:
    try:
        hot.next_run(bad, t)
        raise AssertionError(bad)
    except ValueError:
        pass

# switched-off feed: skipped, no fetch, no leftovers from the last run
off = {**cfg, "feeds": [{**cfg["feeds"][0], "enabled": False}, cfg["feeds"][1]]}
r3 = hot.build(off, pages.__getitem__, r)
assert "CVE-2025-55182" in r3["cves"] and r3["cves"]["CVE-2021-44228"]["src"] == "watchlist"
r4 = hot.build({**off, "watch": []}, pages.__getitem__, r)
assert "CVE-2021-44228" not in r4["cves"]
assert hot.validate({"schedule": "every 1h", "feeds": [{"name": "a", "url": "https://x", "enabled": False}]})["feeds"][0]["enabled"] is False
print("ok")

# validation of what the Settings page sends
ok = hot.validate({"schedule": " daily 06:00 ", "feeds": [{"name": "KEV", "type": "kev", "url": "https://x"}],
                   "watch": [{"cve": "cve-2024-4577", "note": " php "}, {"pkg": "php8.2-cli"}]})
assert ok == {"schedule": "daily 06:00", "feeds": [{"name": "KEV", "type": "kev", "url": "https://x", "enabled": True}],
              "watch": [{"cve": "CVE-2024-4577", "note": "php"}, {"pkg": "php8.2-cli", "note": ""}], "keep_days": 1460, "stale_days": 8}
assert hot.validate({"schedule": "manual", "keep_days": 7})["keep_days"] == 7
assert hot.validate({"schedule": "manual", "stale_days": 0})["stale_days"] == 0
for bad in [{"schedule": "hourly"}, {"schedule": "every 5m"},
            {"schedule": "every 1h", "feeds": [{"name": "a", "url": "file:///etc/passwd"}]},
            {"schedule": "every 1h", "feeds": [{"name": "a", "url": "https://x"}, {"name": "a", "url": "https://y"}]},
            {"schedule": "every 1h", "watch": [{"cve": "nope"}]},
            {"schedule": "every 1h", "watch": [{"note": "empty"}]},
            {"schedule": "manual", "keep_days": 45}, {"schedule": "manual", "keep_days": "90"},
            {"schedule": "manual", "stale_days": -1}, {"schedule": "manual", "stale_days": 366}, {"schedule": "manual", "stale_days": "8"}, {"schedule": "manual", "stale_days": True}]:
    try:
        hot.validate(bad)
        raise AssertionError(bad)
    except ValueError:
        pass
print("ok validate")
assert hot.validate({"schedule": "every 15m"})["schedule"] == "every 15m"
assert hot.validate({"schedule": "daily %s" % (dt.datetime.now() + dt.timedelta(minutes=2)).strftime("%H:%M")})  # soon is fine
assert hot.next_run("manual", t) is None and hot.next_run(" Off ", t) is None
assert hot.validate({"schedule": "manual"})["schedule"] == "manual" and hot.validate({"schedule": "off"})
print("ok min interval, modes")

# login: own username/password, salted hash, lock level change keeps the password
lg = hot.new_login({"lock": "edit", "user": "admin", "password": "s3cret-pass"}, None)
assert lg["lock"] == "edit" and "s3cret-pass" not in json.dumps(lg)
assert hot.password_ok("admin", "s3cret-pass", lg) and hot.password_ok(" admin ", "s3cret-pass", lg)
assert not hot.password_ok("admin", "wrong", lg) and not hot.password_ok("other", "s3cret-pass", lg)
assert hot.new_login({"lock": "all", "user": "admin"}, lg)["hash"] == lg["hash"]
assert hot.new_login({"lock": "off"}, lg) is None
for bad in [{"lock": "maybe"}, {"lock": "edit", "user": "", "password": "12345678"},
            {"lock": "edit", "user": "a:b", "password": "12345678"}, {"lock": "edit", "user": "x", "password": "short"},
            {"lock": "edit", "user": "renamed"}]:
    try:
        hot.new_login(bad, lg)
        raise AssertionError(bad)
    except ValueError:
        pass

# sessions: idle timeout slides, a new password (web or shell) ends old sessions
tok = hot.new_session(lg, 1000.0)
assert hot.session_ok(tok, lg, 1000.0 + 11 * 3600)                      # used after 11 h: still in, timer reset
assert hot.session_ok(tok, lg, 1000.0 + 22 * 3600)                      # 11 h after last use
assert not hot.session_ok(tok, lg, 1000.0 + 22 * 3600 + 12 * 3600 + 1)  # idle > 12 h
tok = hot.new_session(lg, 1000.0)
lg2 = hot.new_login({"lock": "edit", "user": "admin", "password": "another-pass"}, None)
assert not hot.session_ok(tok, lg2, 1001.0) and not hot.session_ok(tok, lg, 1002.0)  # gone, even back on old hash
assert not hot.session_ok(None, lg, 1000.0) and not hot.session_ok("forged", lg, 1000.0)
print("ok login")

# reset code: one at a time, one use, expires, dies after 5 wrong tries
hot.reset.update(code=None)
assert hot.request_reset_code(1000.0) and not hot.request_reset_code(1001.0)  # active code is kept
code = hot.reset["code"]
assert len(code) == 9 and code[4] == "-"
assert hot.use_reset_code("nope", 1002.0) is False
assert hot.use_reset_code(code.lower(), 1003.0) is True  # case-insensitive
try:
    hot.use_reset_code(code, 1004.0); raise AssertionError("reused")
except ValueError:
    pass
hot.request_reset_code(2000.0)
try:
    hot.use_reset_code(hot.reset["code"], 2000.0 + 15 * 60); raise AssertionError("expired")
except ValueError:
    pass
hot.request_reset_code(5000.0)
good = hot.reset["code"]
for _ in range(4):
    assert hot.use_reset_code("WRONG-ONE", 5001.0) is False
try:
    hot.use_reset_code("WRONG-ONE", 5001.0); raise AssertionError("5th")
except ValueError:
    pass
try:
    hot.use_reset_code(good, 5002.0); raise AssertionError("dead after 5 tries")
except ValueError:
    pass
print("ok reset code")
