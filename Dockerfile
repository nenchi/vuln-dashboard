# syntax=docker/dockerfile:1
# stdlib only: no pip install, the base image is the only dependency. Pinned by digest: Renovate also
# picks up rebuilds of the same tag (Alpine security fixes), each one an automatic patch release
FROM python:3.15.2-alpine@sha256:1656b7eaf309cadf99069ea9de335c7f67a8355789cfc6f1835a05818996f081

COPY app/ /app/
COPY site/ /srv/

ENV PYTHONUNBUFFERED=1 PORT=80 WEB_ROOT=/srv
EXPOSE 80
# scan data in, exploited-feed results + Settings + login out (state/hot/)
VOLUME ["/srv/state"]

# 127.0.0.1, not localhost: alpine resolves localhost to ::1 first, the app listens on IPv4
HEALTHCHECK --interval=1m --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO /dev/null http://127.0.0.1/healthz || exit 1

CMD ["python3", "/app/app.py"]
