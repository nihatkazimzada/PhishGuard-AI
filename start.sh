#!/bin/bash
set -e

cd "$(dirname "$0")"

if [ ! -f .env ]; then
  echo "No .env file found — copying from .env.example"
  cp .env.example .env
fi

echo "Installing dependencies..."
pip install -r requirements.txt

echo "Initializing database..."
python3 -c "from backend.database import init_db; init_db()"

echo "Starting PhishGuard AI on http://localhost:8001 ..."
exec uvicorn backend.main:app --host 0.0.0.0 --port 8001 --reload
