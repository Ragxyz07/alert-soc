#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if [ ! -f ml/model.joblib ]; then python ml/train.py; fi
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
