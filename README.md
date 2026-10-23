# vuln-dashboard

**Vulnerability Dashboard for Home Labs**

A small, self-hosted dashboard for the vulnerabilities in your container images. Trivy scans each project's images,
and the dashboard shows open findings by severity with 90 days of history, new vs. patched per week, time to patch,
and a searchable package inventory (SBOM) across all projects. Findings that are **actively exploited in the wild**
(CISA KEV, your own feeds or a watchlist) are marked red and sorted first.

> **Made for home labs, not for production.** It's a hobby project: one container, one optional user, no high
> availability, no audit trail. Use it to keep an eye on your own setup. For anything business-critical, use a
> dedicated product. It is provided as is, without warranty (see [License](#license)).

- **One container:** Python standard library only, no database. Data is plain JSON files.
- **Exploited marks:** CISA KEV out of the box, extra feeds (any page or RSS listing CVE IDs), and a watchlist for
  day 0, before any feed has it.
- **Settings page:** feeds on/off, watchlist, schedule (every N hours/minutes, daily, weekly, manual only, disabled),
  optional login.
- **Optional login:** your own username and password, lock only Settings or the whole dashboard. If you run Authentik
  or a similar tool (Authelia, oauth2-proxy), prefer that.

## Run it

```yaml
# compose.yml
services:
  vuln-dashboard:
    image: ghcr.io/nenchi/vuln-dashboard:0.1.1
    container_name: vuln-dashboard
    ports:
      - "8080:80"            # or put it behind your reverse proxy
    volumes:
      - ./state:/srv/state   # scan data (written by publish.py) + the app's own files in state/hot/
      - /etc/localtime:/etc/localtime:ro   # schedule times in your local time
    restart: unless-stopped
```

Open http://localhost:8080. The page stays empty until the first scan writes data into `./state`, see below.
Behind a reverse proxy over HTTPS, pass `X-Forwarded-Proto` (Traefik and most others do) so the login cookie gets
the `Secure` flag. Compression is left to the proxy.

## Getting scan data in

`publish.py` (standard library only, needs Docker) finds the images, runs Trivy on each, and merges the result into
two files per project:

| File | What's in it | Shown as |
|---|---|---|
| `state/<project>.json` | open findings (with first seen, first fix available), closed findings, a count per scan | dashboard, trend charts, time to patch |
| `state/packages/<project>.json` | the latest full package list of every image (Trivy `--list-all-pkgs`) | Packages tab: the SBOM, searchable across projects |

A finding that disappears from the next scan counts as patched. An image that leaves the compose file counts as
removed, not patched, so it stays out of the time-to-patch numbers.

Images come from every `compose.yml` / `compose.yaml` below the current folder, or from `IMAGES="img1 img2"`.

### Option 1: on the Docker host, with cron

No Git needed. Trivy scans and the result goes straight into the dashboard's `state` folder:

```bash
# a released version, not main: you're running it as code on your host
curl -fsSL -o /opt/vuln-dashboard/publish.py https://raw.githubusercontent.com/nenchi/vuln-dashboard/v0.1.1/publish.py

# scan the images of one compose project
cd /opt/stacks/immich
STATE_DIR=/opt/vuln-dashboard/state REPO_NAME=immich python3 /opt/vuln-dashboard/publish.py

# or everything running on this host, as one project
IMAGES="$(docker ps --format '{{.Image}}')" STATE_DIR=/opt/vuln-dashboard/state REPO_NAME=$(hostname) \
  python3 /opt/vuln-dashboard/publish.py
```

Weekly from cron, Monday 04:00:

```cron
0 4 * * 1  cd /opt/stacks/immich && STATE_DIR=/opt/vuln-dashboard/state REPO_NAME=immich python3 /opt/vuln-dashboard/publish.py >> /var/log/vuln-scan.log 2>&1
```

### Option 2: Gitea Actions, one data repo for all projects

Each project's workflow scans its own compose images and commits the result to a **private** data repo (e.g.
`you/vuln-data`) through the Gitea API. The dashboard server keeps a checkout of that repo and mounts its `state/`
folder. Keep the data repo private: it lists every image, package version and open vulnerability you run.

1. Create the data repo with an empty `state/` folder, and a token with write access to it. Add the token as an
   Actions secret `VULN_DASHBOARD_TOKEN` (user or org level, so every repo sees it).
2. On the server: `git clone` the data repo, mount its `state/` as above, and `git pull` after every scan (a cron job
   every few minutes, or a workflow on the data repo that pulls over SSH on push).
3. In each project repo, `.gitea/workflows/security-scan.yml`:

```yaml
name: Security scan
on:
  schedule:
    - cron: "0 4 * * 1"   # weekly
  workflow_dispatch:

jobs:
  scan:
    runs-on: ubuntu-latest      # needs docker on the runner
    steps:
      - uses: actions/checkout@v4

      - name: Pull images (so Trivy scans what compose runs)
        run: for f in $(find . -name 'compose.y*ml'); do docker compose -f "$f" pull --quiet; done

      - name: Publish to vulnerability dashboard
        if: ${{ github.ref == 'refs/heads/main' }}
        env:
          VULN_TOKEN: ${{ secrets.VULN_DASHBOARD_TOKEN }}
          DASH_REPO: you/vuln-data                 # the private data repo
          TRIVY_IMAGE: aquasec/trivy:0.69.3        # pin it; Renovate can bump it
        run: |
          curl -fsSL https://raw.githubusercontent.com/nenchi/vuln-dashboard/v0.1.1/publish.py | python3 -
```

`GITHUB_SERVER_URL`, `GITHUB_REPOSITORY` (the project name on the dashboard) and `GITHUB_REF` are set by Gitea.
Concurrent scans of different repos are fine: each run reloads and retries if another one committed in between.

### Trivy and SBOM by hand

The Packages tab is the dashboard's own SBOM view. To get a standard SBOM file for an image, or to check one later
without pulling the image again, use Trivy directly:

```bash
# vulnerabilities of one image, the same scan publish.py runs
docker run --rm -v trivy-cache:/root/.cache/trivy aquasec/trivy:0.69.3 image --scanners vuln --severity HIGH,CRITICAL nginx:1.27

# a CycloneDX SBOM of the image (all packages, versions, licenses)
docker run --rm -v trivy-cache:/root/.cache/trivy -v "$PWD:/out" aquasec/trivy:0.69.3 \
  image --format cyclonedx --output /out/nginx.cdx.json nginx:1.27

# scan that SBOM later for new vulnerabilities, no image needed
docker run --rm -v trivy-cache:/root/.cache/trivy -v "$PWD:/out" aquasec/trivy:0.69.3 sbom /out/nginx.cdx.json
```

## Exploited in the wild (red marks)

Set on the **Settings** page. Matching findings and packages get a red **EXPLOITED** badge (hover shows source and
note) and sort first. The severity stays what Trivy reports, so an exploited LOW is red too.

- **Feeds:** *CISA KEV JSON* (default) or *Page / RSS*: any URL, and every CVE ID in it counts, so pick pages that
  only list exploited CVEs. Each feed has an on/off switch. A failing feed keeps its last known entries and shows as
  failing.
- **Watchlist:** for day 0. A CVE ID, or a package name (exact name as on the Packages tab, e.g. `php8.2-cli`)
  that matches every version in every project, even with no finding yet. Remove it once patched.
- **Schedule:** every N hours/minutes (15 min or more), daily at, weekly on, *Manual only* (just **Check now**), or
  *Disabled* (no checks, marks cleared). Saving runs a check right away.

Saved to `state/hot/sources.json`; results in `state/hot/exploited.json`.

## Login (optional)

On the Settings page, **Login** card: *No login* (default), *Login to change Settings* (viewing stays open), or
*Login for the whole dashboard*. Choose your own username and password (8+ characters). Only a salted PBKDF2-SHA256
hash is stored, in `state/hot/auth.json` (mode 600, never served). Sessions are an HttpOnly, SameSite=Strict cookie.
They end on **Log out**, after 12 hours without use, on a password change, and on a container restart. Wrong
passwords: one guess per second.

Once set, the login can only be changed or removed while logged in. **Forgot it?** Only someone with access to the
server can reset it:

- On `/reset.html` (linked from the login page), click *Send code to server log*, read the one-time code with
  `docker logs vuln-dashboard | tail`, and enter it with a new username and password. Valid 15 minutes, one use,
  cancelled after 5 wrong tries.
- Or in a shell on the server:

```bash
docker exec -it vuln-dashboard python3 /app/app.py passwd       # new username/password, keeps the lock level
docker exec -it vuln-dashboard python3 /app/app.py reset-login  # remove the login
```

This is a simple single-user lock. If you run Authentik or a similar tool (Authelia, oauth2-proxy), put that in
front of the dashboard instead (per-user accounts, 2FA, audit log) and leave this on *No login*. Do that for
anything reachable from the internet.

## Development

```bash
python3 app/test_app.py && python3 test_publish.py   # unit tests

# run locally against the sample data, then the end-to-end test
mkdir -p /tmp/vd && cp -r site/. /tmp/vd/ && cp -r tests/fixture/state /tmp/vd/state
WEB_ROOT=/tmp/vd PORT=8080 python3 app/app.py &
python3 tests/smoke_test.py http://127.0.0.1:8080
```

CI (`.github/workflows/docker-publish.yml`) runs the unit tests, builds the image, starts it with the sample data and
runs the end-to-end test on every pull request and push. Only when that passes does it publish to
`ghcr.io/nenchi/vuln-dashboard`: `latest` on pushes to main, `x.y.z` + `latest` on a `vx.y.z` tag. Renovate opens
PRs for the Python base image and the GitHub Actions, and the same tests run on each of them.

**Automatic patch releases:** Renovate merges a Python **patch** update (e.g. 3.13.8 → 3.13.9) by itself, but only
after the tests passed on its PR. The merge then bumps the version (0.1.1 → 0.1.2), tags it, publishes the image and
writes a GitHub Release ("Bump Python 3.13.8 → 3.13.9"). Python **minor/major** updates (3.13 → 3.14) stay a normal PR
to merge by hand. Action updates are merged after the tests too, without a release (the image doesn't change).

**Manual release:** bump `VERSION` in `app/app.py`, commit, tag `vX.Y.Z` (CI checks that the tag matches) and push
the tag.

## License

[MIT](LICENSE): free to use, copy, change and share, including in your own projects. Provided as is, without
warranty of any kind. Intended for home labs (see the note at the top).
