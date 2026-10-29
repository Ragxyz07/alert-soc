@echo off
cd /d %~dp0
if not exist ml\model.joblib (
  echo Training model from data\ CSV files...
  python ml\train.py
  if errorlevel 1 exit /b 1
)
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
