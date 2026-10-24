# syntax=docker/dockerfile:1
# stdlib only: no pip install, the base image is the only dependency. Pinned by digest: Renovate also
# picks up rebuilds of the same tag (Alpine security fixes), each one an automatic patch release
FROM python:3.13.17-alpine@sha256:fa0bb0d0cd7c7d6cef30a69094d32ac2b71c7304c87c6107fec100e1ee4eda02

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
