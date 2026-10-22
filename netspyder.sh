#!/usr/bin/env bash
cd "$(dirname "$(readlink -f "$0")")" || exit 1
docker compose up -d
until curl -sf http://127.0.0.1:3000/api >/dev/null; do sleep 1; done
xdg-open http://127.0.0.1:3000 >/dev/null 2>&1 &
exec sudo ./venv/bin/python sniffer_analyse.py
