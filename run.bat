@echo off
cd /d %~dp0
if not exist frontend\dist\index.html (
  echo Frontend build is missing. Rebuild it with npm ci and npm run build from the frontend folder.
  exit /b 1
)
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
