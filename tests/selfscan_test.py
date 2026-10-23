#!/usr/bin/env python3
"""The dashboard checks itself, for real (CI, after smoke_test.py): publish.py has scanned the freshly built
image with Trivy into the mounted state folder; this checks the dashboard serves that scan and its package list,
then switches on the real CISA KEV feed and checks the download. Writes a summary for the GitHub job page.

  python3 tests/selfscan_test.py http://127.0.0.1:8080 vuln-dashboard
"""
import json
import os
import sys
import time
import urllib.request

BASE = sys.argv[1].rstrip("/")
PROJECT = sys.argv[2] if len(sys.argv) > 2 else "vuln-dashboard"
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def get(path):
    with urllib.request.urlopen(BASE + path, timeout=30) as r:
        return json.load(r)


def send(method, path, body):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status


def ok(cond, what):
    if not cond:
        sys.exit(f"FAIL: {what}")
    print(f"ok   {what}")


def main():
    # 1. the real Trivy scan of our own image, as the dashboard serves it
    ok(f"{PROJECT}.json" in [f["name"] for f in get("/state/")], f"own scan listed ({PROJECT}.json)")
    scan = get(f"/state/{PROJECT}.json")
    last = scan["scans"][-1]
    ok(last["images"] and not last["failed"], f"Trivy scanned {', '.join(last['images'])}")
    inv = get(f"/state/packages/{PROJECT}.json")
    pkgs = [p for img in inv["images"].values() for p in img["pkgs"]]
    ok(len(pkgs) >= 10 and any(p[0] == "musl" for p in pkgs), f"package inventory (SBOM): {len(pkgs)} packages")

    # 2. the real CISA KEV feed
    status = send("PUT", "/api/sources", {"schedule": "manual", "watch": [],
                                          "feeds": [{"name": "CISA KEV", "type": "kev", "url": KEV, "enabled": True}]})
    ok(status == 200, "switch on the real CISA KEV feed")
    hot = {}
    for _ in range(60):
        try:
            hot = get("/state/hot/exploited.json")
        except OSError:
            hot = {}
        if len(hot.get("cves", {})) > 1000 or hot.get("errors"):
            break
        time.sleep(1)
    ok(not hot.get("errors"), f"KEV download without errors {hot.get('errors') or ''}")
    ok(len(hot.get("cves", {})) > 1000, f"KEV lists {len(hot.get('cves', {}))} exploited CVEs")
    ok(hot["cves"].get("CVE-2021-44228", {}).get("src") == "CISA KEV", "Log4Shell is in it (sanity check)")

    # 3. our own findings against KEV: reported, not failing (a fix may not exist yet)
    findings = list(scan["open"].values())
    exploited = sorted({f["id"] for f in findings if f["id"] in hot["cves"]})
    counts = {s: sum(f["sev"] == s for f in findings) for s in SEVS}
    fixable = sum(1 for f in findings if f["fix"])
    line = ", ".join(f"{s.title()} {counts[s]}" for s in SEVS)
    print(f"own image: {line}; fixable {fixable}; actively exploited (KEV): {', '.join(exploited) or 'none'}")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(f"### Own image scan ({', '.join(last['images'])})\n\n| " + " | ".join(SEVS) + " | Fixable | Exploited (KEV) |\n"
                    f"|{'---|' * (len(SEVS) + 2)}\n| " + " | ".join(str(counts[s]) for s in SEVS)
                    + f" | {fixable} | {', '.join(exploited) or 'none'} |\n\n{len(pkgs)} packages, KEV: {len(hot['cves'])} CVEs\n")
    print("self-scan test passed")


if __name__ == "__main__":
    main()
