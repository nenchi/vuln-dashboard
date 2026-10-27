#!/usr/bin/env python3
"""vuln-dashboard server (stdlib only): serves site/ + state/, and fetches "exploited in the wild"
feeds on a schedule into state/hot/exploited.json, which the dashboard uses to mark findings red.

Sources and schedule are edited on the dashboard's Settings page (PUT /api/sources) and saved to
state/hot/sources.json (gitignored, so git pull on the server never conflicts); until the first save
app/sources.default.json is used. Optional login (own username/password, set in Settings): login form
(/login.html) + session cookie, salted hash in state/hot/auth.json (never served). Forgot it: from a shell on the server,
  docker exec -it vuln-dashboard python3 /app/app.py passwd       (new username/password, keeps the lock level)
  docker exec -it vuln-dashboard python3 /app/app.py reset-login  (removes the login)
or on /reset.html with a one-time code the server prints to its log (docker logs vuln-dashboard): reading the log
proves access to the container, same as the shell.
Format:
  "schedule": "every 1h" | "every 30m" | "daily 06:00" | "weekly mon 06:00"  (server local time)
              | "manual" (only "Check now") | "off" (no checks, nothing marked)
  "feeds": [{"name", "type", "url", "enabled"}]  type kev = CISA KEV JSON, text = any page/RSS/list (every CVE ID in it counts)
  "watch": [{"cve": "...", "note": "..."} or {"pkg": "...", "note": "..."}]  (package name, all versions)
  "keep_days": one of KEEP_CHOICES, the longest dashboard range; KEEP_DAYS in the container env overrides it
"""
import datetime as dt
import hashlib
import hmac
import http.cookies
import io
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

VERSION = "0.3.3"  # bump on release (shown in the dashboard footer and the log)
WEB = os.environ.get("WEB_ROOT", "/srv")  # site/ here, state/ at /srv/state
HOT = os.path.join(WEB, "state", "hot")
OUT = os.path.join(HOT, "exploited.json")
SOURCES = os.path.join(HOT, "sources.json")
AUTH = os.path.join(HOT, "auth.json")
LOCKS = ("off", "edit", "all")  # no login / login to change Settings / login for everything
DEFAULT_SOURCES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sources.default.json")
DEFAULT_SCHEDULE = "every 6h"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
MODES = ("manual", "off")  # schedules without automatic runs
KEEP_CHOICES = (7, 30, 60, 90, 180, 365, 730, 1095, 1460)  # Settings "Keep history" = the dashboard's ranges
# set in compose.yml: Settings shows it greyed out. Display only: what's stored is publish.py's KEEP_DAYS (4 years)
KEEP_ENV = int(os.environ["KEEP_DAYS"]) if os.environ.get("KEEP_DAYS", "").strip() else None
wake = threading.Event()  # set by a save or "Check now": fetch right away


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "vuln-dashboard-hot"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def build(cfg, get, old):
    cves, errors = {}, []
    for feed in cfg.get("feeds", []):
        if not feed.get("enabled", True):  # switched off in Settings: its CVEs drop out
            continue
        try:
            body = get(feed["url"])
            if feed.get("type", "text") == "kev":
                ids = {v["cveID"]: v.get("vulnerabilityName", "") for v in json.loads(body)["vulnerabilities"]}
            else:
                ids = dict.fromkeys(CVE_RE.findall(body), "")
        except Exception as e:  # one broken source must not wipe the others: keep its last known list
            errors.append(f"{feed['name']}: {e}")
            ids = {k: v["note"] for k, v in old.get("cves", {}).items() if v["src"] == feed["name"]}
        for cid, note in ids.items():
            cves.setdefault(cid.upper(), {"src": feed["name"], "note": note})
    watch = cfg.get("watch", [])
    for w in watch:
        if w.get("cve"):
            cves[w["cve"].upper()] = {"src": "watchlist", "note": w.get("note", "")}
    pkgs = {w["pkg"].lower(): {"src": "watchlist", "note": w.get("note", "")} for w in watch if w.get("pkg")}
    return {"cves": cves, "pkgs": pkgs, "errors": errors}


def next_run(spec, last):
    """first run time after `last` for a schedule string, None for manual/off; ValueError if it doesn't parse"""
    s = spec.strip().lower()
    if s in MODES:
        return None
    m = re.fullmatch(r"every (\d+) ?([mh])", s)
    if m and int(m[1]):
        return last + dt.timedelta(minutes=int(m[1]) * (60 if m[2] == "h" else 1))
    m = re.fullmatch(r"(?:daily|weekly (mon|tue|wed|thu|fri|sat|sun)) (\d{1,2}):(\d{2})", s)
    if not m or int(m[2]) > 23 or int(m[3]) > 59:
        raise ValueError(f"bad schedule {spec!r}, use e.g. 'every 1h', 'daily 06:00', 'weekly mon 06:00'")
    t = last.replace(hour=int(m[2]), minute=int(m[3]), second=0, microsecond=0)
    if m[1]:
        t += dt.timedelta(days=(DAYS.index(m[1]) - t.weekday()) % 7)
    while t <= last:
        t += dt.timedelta(days=7 if m[1] else 1)
    return t


def validate(cfg):
    """clean copy of a sources config from the browser; ValueError with a readable message"""
    if not isinstance(cfg, dict):
        raise ValueError("expected a JSON object")
    schedule = str(cfg.get("schedule", "")).strip()
    now = dt.datetime.now()
    nxt = next_run(schedule, now)  # raises on a bad schedule
    if schedule.lower().startswith("every") and nxt - now < dt.timedelta(minutes=15):
        raise ValueError("check at most every 15 minutes, feed sites rate-limit")
    feeds, watch, names = [], [], set()
    for f in cfg.get("feeds", []):
        name, url, typ = str(f.get("name", "")).strip(), str(f.get("url", "")).strip(), f.get("type", "text")
        if not name or name in names or name == "watchlist":
            raise ValueError(f"feed name {name!r} is empty, used twice or reserved")
        if not re.match(r"https?://", url):
            raise ValueError(f"feed {name!r}: URL must start with http:// or https://")
        if typ not in ("kev", "text"):
            raise ValueError(f"feed {name!r}: type must be kev or text")
        names.add(name)
        feeds.append({"name": name, "type": typ, "url": url, "enabled": f.get("enabled", True) is not False})
    for w in cfg.get("watch", []):
        cve, pkg, note = str(w.get("cve", "")).strip(), str(w.get("pkg", "")).strip(), str(w.get("note", "")).strip()
        if cve and not CVE_RE.fullmatch(cve):
            raise ValueError(f"{cve!r} is not a CVE ID like CVE-2024-4577")
        if bool(cve) == bool(pkg):
            raise ValueError("each watch entry needs either a CVE or a package name")
        watch.append({"cve": cve.upper(), "note": note} if cve else {"pkg": pkg, "note": note})
    keep = cfg.get("keep_days", KEEP_CHOICES[-1])
    if keep not in KEEP_CHOICES:
        raise ValueError(f"keep history must be one of {', '.join(map(str, KEEP_CHOICES))} days")
    return {"schedule": schedule, "feeds": feeds, "watch": watch, "keep_days": keep}


def pw_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


def new_login(body, old):
    """login to save from the Settings page: None = no login; ValueError with a readable message"""
    lock = body.get("lock")
    if lock not in LOCKS:
        raise ValueError("lock must be off, edit or all")
    if lock == "off":
        return None
    user, pw = str(body.get("user", "")).strip(), str(body.get("password", ""))
    if not user or ":" in user:
        raise ValueError("username is required and can't contain ':'")
    if not pw:  # only the lock level changed: keep the password
        if not old or old["user"] != user:
            raise ValueError("set a password")
        return {**old, "lock": lock}
    if len(pw) < 8:
        raise ValueError("password needs at least 8 characters")
    salt = os.urandom(16)
    return {"lock": lock, "user": user, "salt": salt.hex(), "hash": pw_hash(pw, salt)}


def password_ok(user, pw, login):
    return hmac.compare_digest(str(user).strip().encode(), login["user"].encode()) & \
        hmac.compare_digest(pw_hash(str(pw), bytes.fromhex(login["salt"])).encode(), login["hash"].encode())


SESSION_HOURS = 12  # idle timeout
sessions = {}  # token -> [expires, login hash]. In memory: a restart logs everyone out
sessions_lock, fail_lock = threading.Lock(), threading.Lock()


def new_session(login, now=None):
    now = now or time.time()
    token = secrets.token_urlsafe(32)
    with sessions_lock:
        for t in [t for t, (exp, _) in sessions.items() if exp <= now]:
            del sessions[t]
        sessions[token] = [now + SESSION_HOURS * 3600, login["hash"]]
    return token


def session_ok(token, login, now=None):
    """valid, not idle too long, and made with the current password (a change from the shell ends it at once)"""
    now = now or time.time()
    with sessions_lock:
        s = sessions.get(token or "")
        if not s or s[0] <= now or s[1] != login["hash"]:
            sessions.pop(token or "", None)
            return False
        s[0] = now + SESSION_HOURS * 3600
        return True


def save_login(login):
    if login:
        write_json(AUTH, login)
        os.chmod(AUTH, 0o600)
    elif os.path.exists(AUTH):
        os.remove(AUTH)


def cli(cmd):
    """forgot password: only from a shell on the server, never from the web page"""
    import getpass
    old = read_json(AUTH, None)
    if cmd == "reset-login":
        save_login(None)
        return print("Login removed: the dashboard is open again. Set a new one in Settings.")
    user = input(f"Username [{old['user'] if old else ''}]: ").strip() or (old["user"] if old else "")
    pw = getpass.getpass("New password: ")
    if pw != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords don't match, nothing changed")
    try:
        login = new_login({"lock": old["lock"] if old else "edit", "user": user, "password": pw}, None)
    except ValueError as e:
        raise SystemExit(f"{e}, nothing changed")
    save_login(login)
    print(f"Saved login for {user!r} (lock: {login['lock']}). The old password stops working right away.")


RESET_MINUTES, RESET_TRIES = 15, 5
reset = {"code": None, "until": 0.0, "tries": 0}  # one active code at a time, in memory only
reset_lock = threading.Lock()


def request_reset_code(now=None):
    """print a one-time code to the log; an active code is kept (so nobody can rotate it away while you type)"""
    now = now or time.time()
    with reset_lock:
        if reset["code"] and now < reset["until"]:
            return False
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I
        code = "".join(secrets.choice(alphabet) for _ in range(8))
        reset.update(code=f"{code[:4]}-{code[4:]}", until=now + RESET_MINUTES * 60, tries=0)
    print(f"LOGIN RESET CODE: {reset['code']}  (valid {RESET_MINUTES} min, one use; requested on /reset.html)", flush=True)
    return True


def use_reset_code(code, now=None):
    """True once for the right code; wrong tries count, the code dies after RESET_TRIES"""
    now = now or time.time()
    with reset_lock:
        if not reset["code"] or now >= reset["until"]:
            raise ValueError("no valid code: request a new one")
        if hmac.compare_digest(str(code).strip().upper().encode(), reset["code"].encode()):
            reset["code"] = None
            return True
        reset["tries"] += 1
        if reset["tries"] >= RESET_TRIES:
            reset["code"] = None
            print("LOGIN RESET CODE cancelled after too many wrong tries", flush=True)
            raise ValueError("too many wrong tries: request a new code")
        return False


def read_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data):
    with open(path + ".tmp", "w") as f:
        json.dump(data, f, separators=(",", ":"))
    os.replace(path + ".tmp", path)  # never serve a half-written file


def load_sources():
    return read_json(SOURCES, None) or read_json(DEFAULT_SOURCES, {})


def keep_days():
    """longest range the dashboard offers: KEEP_DAYS env, else the Settings value, else 4 years"""
    keep = load_sources().get("keep_days")
    return KEEP_ENV or (keep if keep in KEEP_CHOICES else KEEP_CHOICES[-1])


def schedule_of(cfg):
    try:
        next_run(cfg.get("schedule", ""), dt.datetime.now())
        return cfg["schedule"]
    except (KeyError, ValueError):
        return DEFAULT_SCHEDULE


def scheduler():
    last = None
    while True:
        cfg = load_sources()
        now = dt.datetime.now()
        sched = schedule_of(cfg).lower()
        auto = sched not in MODES and (last is None or now >= next_run(sched, last))
        if wake.is_set() or auto:  # wake: a save or "Check now"
            wake.clear()
            try:
                new = {"cves": {}, "pkgs": {}, "errors": []} if sched == "off" else build(cfg, fetch, read_json(OUT, {}))
                nxt = next_run(sched, now)
                new.update(updated=now.astimezone().replace(microsecond=0).isoformat(), schedule=sched,
                           next=nxt.astimezone().replace(microsecond=0).isoformat() if nxt else None)
                write_json(OUT, new)
                print(f"{new['updated']}: {len(new['cves'])} CVEs, {len(new['pkgs'])} watched packages"
                      + "".join(f"\n  FAILED {e}" for e in new["errors"]), flush=True)
            except Exception as e:  # keep scheduling; the next run tries again
                print(f"feed run failed: {e}", flush=True)
            last = now
        wake.wait(60)


# reachable without the login, per method: login + forgot-login pages and their API calls.
# Per method on purpose: GET /api/auth (lock status) is open, PUT /api/auth (change the login) never is.
OPEN = {"GET": ("/login.html", "/reset.html", "/api/version", "/api/auth", "/api/keep"),
        "POST": ("/api/login", "/api/logout", "/api/reset-code"),
        "PUT": ("/api/reset",)}
COOKIE = "vd_session"


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **k):
        super().__init__(*a, directory=WEB, **k)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache")  # always revalidate, so a deploy shows up on the next reload
        super().end_headers()

    def log_request(self, code="-", size="-"):
        if str(code) >= "400" or self.command != "GET":  # no line per page load / health check
            super().log_request(code, size)

    def list_directory(self, path):
        # JSON listing like caddy's browse: index.html uses it to find state/*.json
        items = [{"name": n + "/" if os.path.isdir(os.path.join(path, n)) else n} for n in sorted(os.listdir(path))
                 if not os.path.join(path, n).startswith(AUTH)]
        body = json.dumps(items).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        return io.BytesIO(body)

    @property
    def route(self):
        return urllib.parse.urlsplit(self.path).path

    def send_json(self, code, data, cookie=None):
        body = json.dumps(data).encode()
        self.send_response(code)
        if cookie is not None:  # "" = log out
            secure = "; Secure" if self.headers.get("X-Forwarded-Proto") == "https" else ""  # TLS ends at the reverse proxy
            self.send_header("Set-Cookie", f"{COOKIE}={cookie}; Path=/; HttpOnly; SameSite=Strict; "
                             f"Max-Age={SESSION_HOURS * 3600 if cookie else 0}{secure}")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def token(self):
        c = http.cookies.SimpleCookie()
        try:
            c.load(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return None
        return c[COOKIE].value if COOKIE in c else None

    def logged_in(self, login):
        return bool(login) and session_ok(self.token(), login)

    def allowed(self, edit):
        """False after answering (redirect to the login page, or 401) when this request needs the saved login.
        edit: /api/ calls and changes, locked with "edit"; with "all" everything is."""
        login = read_json(AUTH, None)
        if not login or (login["lock"] == "edit" and not edit) or self.route in OPEN.get(self.command, ()) or self.logged_in(login):
            return True
        if self.command == "GET" and not self.route.startswith(("/api/", "/state/")):  # a page: show the login form
            self.send_response(302)
            self.send_header("Location", "/login.html?next=" + urllib.parse.quote(self.path, safe=""))
            self.send_header("Content-Length", "0")
            self.end_headers()
            return False
        self.send_json(401, {"error": "login required"})
        return False

    def do_GET(self):
        if self.route == "/healthz":
            return self.send_json(200, {"ok": True})
        if os.path.realpath(self.translate_path(self.path)).startswith(os.path.realpath(AUTH)):  # also auth.json.tmp
            return self.send_json(404, {"error": "not found"})
        if not self.allowed(self.route.startswith("/api/")):
            return
        if self.route == "/api/version":
            return self.send_json(200, {"version": VERSION})
        if self.route == "/api/sources":
            return self.send_json(200, load_sources())
        if self.route == "/api/keep":  # open: the dashboard's Range list needs it even with "Login to change Settings"
            return self.send_json(200, {"days": keep_days(), "env": KEEP_ENV is not None})
        if self.route == "/api/auth":  # open: the page needs it to show Log out; the username only when logged in
            login = read_json(AUTH, None)
            me = self.logged_in(login)
            return self.send_json(200, {"lock": login["lock"] if login else "off", "logged_in": me,
                                        "user": login["user"] if me else ""})
        super().do_GET()

    def do_HEAD(self):  # the parent's HEAD would skip the login and auth.json checks above
        self.send_json(405, {"error": "use GET"})

    def json_body(self):
        """parsed JSON body, or None after sending an error. Requiring a JSON content type blocks other websites
        from posting here: cross-origin JSON needs a CORS preflight we never answer."""
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            return self.send_json(415, {"error": "expected application/json"})
        n = int(self.headers.get("Content-Length") or 0)
        if not 0 < n <= 65536:
            return self.send_json(413, {"error": "body missing or too large"})
        try:
            body = json.loads(self.rfile.read(n))
        except ValueError:
            return self.send_json(400, {"error": "invalid JSON"})
        if not isinstance(body, dict):
            return self.send_json(400, {"error": "expected a JSON object"})
        return body

    def do_PUT(self):
        if self.route == "/api/reset":
            return self.reset_login()
        if self.route not in ("/api/sources", "/api/auth"):
            return self.send_json(404, {"error": "not found"})
        if not self.allowed(True) or (body := self.json_body()) is None:
            return
        try:
            if self.route == "/api/auth":
                login = new_login(body, read_json(AUTH, None))
            else:
                cfg = validate(body)
        except ValueError as e:
            return self.send_json(400, {"error": str(e)})
        if self.route == "/api/sources":
            write_json(SOURCES, cfg)
            wake.set()
            return self.send_json(200, cfg)
        save_login(login)  # a new password ends all other sessions (they carry the old hash); this browser stays in
        self.send_json(200, {"lock": login["lock"] if login else "off", "user": login["user"] if login else ""},
                       cookie=new_session(login) if login else "")

    def reset_login(self):
        if (body := self.json_body()) is None:
            return
        old = read_json(AUTH, None)
        if not old:
            return self.send_json(409, {"error": "no login is set"})
        try:
            login = new_login({"lock": old["lock"], "user": body.get("user", ""), "password": body.get("password", "")}, None)
            if not login.get("hash"):
                raise ValueError("set a password")
            if not use_reset_code(body.get("code", "")):
                time.sleep(1)
                return self.send_json(403, {"error": "wrong code"})
        except ValueError as e:
            return self.send_json(400, {"error": str(e)})
        save_login(login)
        print(f"Login reset with a code from the log, user {login['user']!r}", flush=True)
        self.send_json(200, {"lock": login["lock"], "user": login["user"]}, cookie=new_session(login))

    def do_POST(self):
        if self.route == "/api/login":
            if (body := self.json_body()) is None:
                return
            login = read_json(AUTH, None)
            if not login:
                return self.send_json(409, {"error": "no login is set"})
            if not password_ok(body.get("user", ""), body.get("password", ""), login):
                with fail_lock:  # one wrong guess per second, across all connections
                    time.sleep(1)
                return self.send_json(403, {"error": "wrong username or password"})
            return self.send_json(200, {"ok": True}, cookie=new_session(login))
        if self.route == "/api/logout":
            with sessions_lock:
                sessions.pop(self.token() or "", None)
            return self.send_json(200, {"ok": True}, cookie="")
        if self.route == "/api/reset-code":
            if self.json_body() is None:
                return
            if not read_json(AUTH, None):
                return self.send_json(409, {"error": "no login is set"})
            fresh = request_reset_code()
            return self.send_json(202, {"msg": "Code printed to the server log." if fresh else
                                        "A code is already in the server log and still valid. Use that one."})
        if self.route != "/api/run":
            return self.send_json(404, {"error": "not found"})
        if not self.allowed(True) or self.json_body() is None:
            return
        if schedule_of(load_sources()).lower() == "off":
            return self.send_json(409, {"error": "checks are disabled: choose Scheduled or Manual only and save first"})
        wake.set()
        self.send_json(202, {"ok": True})


if __name__ == "__main__":
    import sys
    os.makedirs(HOT, exist_ok=True)
    if sys.argv[1:]:
        if sys.argv[1] not in ("passwd", "reset-login"):
            raise SystemExit("usage: app.py [passwd | reset-login]   (no argument: run the server)")
        raise SystemExit(cli(sys.argv[1]))
    print(f"vuln-dashboard {VERSION}", flush=True)
    threading.Thread(target=scheduler, daemon=True).start()
    ThreadingHTTPServer(("", int(os.environ.get("PORT", "80"))), Handler).serve_forever()
