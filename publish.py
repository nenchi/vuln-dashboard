#!/usr/bin/env python3
"""Scan images with Trivy (vulnerabilities + full package list, the SBOM behind the Packages tab) and merge the
result into the dashboard's state/<repo>.json (open findings, closed findings, history) and
state/packages/<repo>.json. Stdlib only; needs docker (Trivy runs as a container).

Two ways to deliver (see README):
  Gitea Actions:  commits to a data repo through the Gitea API. Env: VULN_TOKEN (write access), DASH_REPO
                  (owner/name of the data repo); GITHUB_REPOSITORY, GITHUB_REF, GITHUB_SERVER_URL are set by Gitea.
  Local / cron:   writes straight into the dashboard's state folder. Env: STATE_DIR, REPO_NAME.
Images: every compose.y(a)ml below the current folder, or IMAGES="img1 img2" (e.g. from docker ps).
Optional: TRIVY_IMAGE, TRIVY_CACHE_DIR, TRIVY_DOCKER_SOCKET (default /var/run/docker.sock, "" = always pull).
"""
import base64
import datetime as dt
import glob
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

DASH_REPO = os.environ.get("DASH_REPO", "")  # Gitea mode: owner/name of the data repo
STATE_DIR = os.environ.get("STATE_DIR", "")  # local mode: the dashboard's state folder
KEEP_DAYS = 90  # ponytail: history + closed findings pruned at 90 days; raise if you want a longer window
SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

TRIVY = os.environ.get("TRIVY_IMAGE") or "aquasec/trivy:latest"
CACHE = os.environ.get("TRIVY_CACHE_DIR") or "/tmp/trivy-cache"
# Trivy reads images from the local Docker daemon through this socket first (locally built images, no re-pull);
# a path on the Docker host. Set it empty to make Trivy always pull from the registry (rootless Docker: its socket)
SOCKET = os.environ.get("TRIVY_DOCKER_SOCKET", "/var/run/docker.sock")
API = os.environ.get("GITHUB_SERVER_URL", "").rstrip("/") + "/api/v1"
TOKEN = os.environ.get("VULN_TOKEN", "")
REPO = os.environ.get("REPO_NAME") or os.environ.get("GITHUB_REPOSITORY", "").split("/")[-1]
STATE_PATH = f"state/{REPO}.json"
PKGS_PATH = f"state/packages/{REPO}.json"  # latest full package inventory, no history


def compose_images():
    if os.environ.get("IMAGES"):
        return sorted(set(os.environ["IMAGES"].split()))
    imgs = set()
    for f in sorted(glob.glob("**/compose.y*ml", recursive=True)):
        r = subprocess.run(["docker", "compose", "-f", f, "config", "--images"], capture_output=True, text=True)
        if r.returncode:
            print(f"WARN: cannot resolve images in {f}: {r.stderr.strip()[:200]}")
            continue
        imgs |= {line.strip() for line in r.stdout.splitlines() if line.strip()}
    return sorted(imgs)


def image_name(img):
    """repo path without tag/digest, so a findings key survives a version bump."""
    img = img.split("@")[0]
    head, _, last = img.rpartition("/")
    return f"{head}/{last.split(':')[0]}" if head else last.split(":")[0]


def trivy_scan(img):
    # JSON on stdout: the job container and the docker daemon may not share paths, so no output volume
    r = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{CACHE}:/root/.cache/trivy", *(["-v", f"{SOCKET}:/var/run/docker.sock:ro"] if SOCKET else []),
         TRIVY, "image",
         "--quiet", "--scanners", "vuln", "--list-all-pkgs", "--format", "json", img],
        capture_output=True, text=True)
    if r.returncode:
        print(f"WARN: trivy failed for {img}: {r.stderr.strip()[-300:]}")
        return None
    found, pkgs = {}, set()
    for res in json.loads(r.stdout).get("Results") or []:
        for p in res.get("Packages") or []:
            pkgs.add((p["Name"], p.get("Version", ""), res.get("Type", "")))
        for v in res.get("Vulnerabilities") or []:
            key = f"{image_name(img)}|{v['PkgName']}|{v['VulnerabilityID']}"
            found[key] = {
                "img": image_name(img),
                "pkg": v["PkgName"],
                "id": v["VulnerabilityID"],
                "sev": v.get("Severity", "UNKNOWN"),
                "ver": v.get("InstalledVersion", ""),
                "fix": v.get("FixedVersion", ""),
                "title": (v.get("Title") or "")[:160],
            }
    return found, sorted(pkgs)


def api(method, path, body=None):
    req = urllib.request.Request(
        f"{API}/repos/{DASH_REPO}/{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        # some proxies (e.g. Cloudflare) return 403 for the default Python-urllib user agent
        headers={"Authorization": f"token {TOKEN}", "Content-Type": "application/json",
                 "User-Agent": "vuln-dashboard-publish"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def local(path):
    return os.path.join(STATE_DIR, path.removeprefix("state/"))


def load(path, empty):
    if STATE_DIR:
        try:
            with open(local(path)) as f:
                return json.load(f), "local"
        except FileNotFoundError:
            return empty, None
    try:
        f = api("GET", f"contents/{path}?ref=main")
        return json.loads(base64.b64decode(f["content"])), f["sha"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return empty, None
        raise


def merge_packages(inv, packages, images, now):
    """replace inventory of scanned images, keep failed ones' last known list, drop images gone from compose"""
    current = {image_name(i) for i in images}
    inv["images"] = {n: v for n, v in inv.get("images", {}).items() if n in current}
    for img, pkgs in packages.items():
        inv["images"][image_name(img)] = {"ref": img, "pkgs": [list(p) for p in pkgs]}
    inv.update(repo=REPO, updated=now)
    return inv


def merge(state, scanned, images, failed, now):
    ok_names = {image_name(i) for i in images if i not in failed}
    current = {image_name(i) for i in images}
    for key, f in list(state["open"].items()):
        if f["img"] in ok_names and key not in scanned:
            state["closed"].append({**f, "key": key, "closed": now})
        elif f["img"] not in current:  # image dropped from compose: not a patch, kept out of time-to-patch
            state["closed"].append({**f, "key": key, "closed": now, "removed": True})
        else:
            continue
        del state["open"][key]
    for key, f in scanned.items():
        old = state["open"].get(key)
        if old:
            old.update(sev=f["sev"], ver=f["ver"], fix=f["fix"], title=f["title"])
            if f["fix"] and not old.get("fix_first"):
                old["fix_first"] = now
        else:
            state["open"][key] = {**f, "first": now, "fix_first": now if f["fix"] else None}

    counts = {s: 0 for s in SEVS}
    fixable = {s: 0 for s in SEVS}
    for f in state["open"].values():
        counts[f["sev"]] = counts.get(f["sev"], 0) + 1
        if f["fix"]:
            fixable[f["sev"]] = fixable.get(f["sev"], 0) + 1
    state["scans"].append({"t": now, "counts": counts, "fixable": fixable,
                           "images": sorted(images), "failed": sorted(failed)})

    cutoff = (dt.datetime.fromisoformat(now) - dt.timedelta(days=KEEP_DAYS)).isoformat()
    state["scans"] = [s for s in state["scans"] if s["t"] >= cutoff]
    state["closed"] = [c for c in state["closed"] if c["closed"] >= cutoff]
    state["updated"] = now
    return state


def main():
    ref = os.environ.get("GITHUB_REF", "")
    if ref and ref not in ("refs/heads/main", "refs/heads/master"):
        print(f"Not on the default branch ({ref}), skipping dashboard publish")
        return
    if not REPO:
        sys.exit("set REPO_NAME (or GITHUB_REPOSITORY, set by Gitea Actions): the project name on the dashboard")
    if not STATE_DIR and not (TOKEN and DASH_REPO and API != "/api/v1"):
        sys.exit("set STATE_DIR (local mode) or VULN_TOKEN + DASH_REPO + GITHUB_SERVER_URL (Gitea mode)")

    images = compose_images()
    if not images:
        print("No compose images found, nothing to publish")
        return

    scanned, packages, failed = {}, {}, set()
    for img in images:
        print(f"Scanning {img}")
        res = trivy_scan(img)
        if res is None:
            failed.add(img)
        else:
            scanned.update(res[0])
            packages[img] = res[1]
    if len(failed) == len(images):
        sys.exit("All image scans failed, not publishing")

    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    if STATE_DIR:
        state, _ = load(STATE_PATH, {"repo": REPO, "scans": [], "open": {}, "closed": []})
        inv, _ = load(PKGS_PATH, {})
        for path, data in [(STATE_PATH, merge(state, scanned, images, failed, now)),
                           (PKGS_PATH, merge_packages(inv, packages, images, now))]:
            os.makedirs(os.path.dirname(local(path)), exist_ok=True)
            with open(local(path) + ".tmp", "w") as f:
                json.dump(data, f, separators=(",", ":"))
            os.replace(local(path) + ".tmp", local(path))  # the dashboard never reads a half-written file
        c = state["scans"][-1]["counts"]
        return print(f"Wrote {local(STATE_PATH)}: " + ", ".join(f"{s} {c[s]}" for s in SEVS[:4]))
    for attempt in range(3):  # another run may have updated the same file in between: reload and re-merge
        state, sha = load(STATE_PATH, {"repo": REPO, "scans": [], "open": {}, "closed": []})
        state = merge(state, scanned, images, failed, now)
        inv, inv_sha = load(PKGS_PATH, {})
        inv = merge_packages(inv, packages, images, now)
        files = [{"operation": "update" if h else "create", "path": path, **({"sha": h} if h else {}),
                  "content": base64.b64encode(json.dumps(data, separators=(",", ":")).encode()).decode()}
                 for path, data, h in [(STATE_PATH, state, sha), (PKGS_PATH, inv, inv_sha)]]
        try:
            api("POST", "contents", {"branch": "main", "message": f"{REPO}: scan {now}", "files": files})
            c = state["scans"][-1]["counts"]
            n = sum(len(v["pkgs"]) for v in inv["images"].values())
            print(f"Published {STATE_PATH}: " + ", ".join(f"{s} {c[s]}" for s in SEVS[:4]) + f"; {n} packages")
            return
        except urllib.error.HTTPError as e:
            print(f"WARN: publish attempt {attempt + 1} failed: {e.code} {e.read().decode()[:200]}")
    sys.exit("Could not publish state after 3 attempts")


if __name__ == "__main__":
    main()
