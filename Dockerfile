# syntax=docker/dockerfile:1
# stdlib only: no pip install, the base image is the only dependency (Renovate keeps it current)
FROM python:3.13.8-alpine

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
