"""python3 test_publish.py — checks open/close/time-to-patch bookkeeping in publish.merge."""
import publish

f = lambda img, pkg, cve, fix="": {"img": img, "pkg": pkg, "id": cve, "sev": "HIGH", "ver": "1", "fix": fix, "title": ""}
k = lambda v: f"{v['img']}|{v['pkg']}|{v['id']}"
a, b, c = f("app", "openssl", "CVE-1"), f("app", "zlib", "CVE-2", "1.3"), f("db", "glibc", "CVE-3")
st = {"repo": "x", "scans": [], "open": {}, "closed": []}

st = publish.merge(st, {k(a): a, k(b): b, k(c): c}, ["app:1", "db:1"], set(), "2026-10-01T00:00:00+00:00")
assert len(st["open"]) == 3 and st["open"][k(b)]["fix_first"] == "2026-10-01T00:00:00+00:00"

# week 2: fix appears for a; db scan failed -> c must stay open
a2 = {**a, "fix": "3.0"}
st = publish.merge(st, {k(a2): a2, k(b): b}, ["app:2", "db:1"], {"db:1"}, "2026-10-08T00:00:00+00:00")
assert k(c) in st["open"] and st["open"][k(a)]["fix_first"] == "2026-10-08T00:00:00+00:00"
assert st["open"][k(a)]["first"] == "2026-10-01T00:00:00+00:00"  # tag bump keeps the finding's history

# week 3: a patched, db removed from compose
st = publish.merge(st, {k(b): b}, ["app:3"], set(), "2026-10-15T00:00:00+00:00")
closed = {x["key"]: x for x in st["closed"]}
assert set(st["open"]) == {k(b)}
assert closed[k(a)]["closed"] == "2026-10-15T00:00:00+00:00" and "removed" not in closed[k(a)]
assert closed[k(c)]["removed"] is True
assert st["scans"][-1]["counts"]["HIGH"] == 1 and st["scans"][-1]["fixable"]["HIGH"] == 1

# retention: 100 days later old scans and closed findings are pruned
st = publish.merge(st, {k(b): b}, ["app:3"], set(), "2027-01-23T00:00:00+00:00")
assert len(st["scans"]) == 1 and st["closed"] == []
assert publish.image_name("ghcr.io/org/app:1.2@sha256:ab") == "ghcr.io/org/app"
assert publish.image_name("localhost:5000/app:1") == "localhost:5000/app"
print("ok")

# package inventory: failed image keeps its last list, removed image is dropped
inv = publish.merge_packages({}, {"app:1": [("openssl", "3.0", "debian")], "db:1": [("glibc", "2.36", "debian")]}, ["app:1", "db:1"], "t1")
inv = publish.merge_packages(inv, {"app:2": [("openssl", "3.1", "debian")]}, ["app:2", "db:1"], "t2")
assert inv["images"]["app"] == {"ref": "app:2", "pkgs": [["openssl", "3.1", "debian"]]}
assert inv["images"]["db"]["pkgs"] == [["glibc", "2.36", "debian"]]
inv = publish.merge_packages(inv, {"app:2": []}, ["app:2"], "t3")
assert set(inv["images"]) == {"app"}
print("ok packages")
