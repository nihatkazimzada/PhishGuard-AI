import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from backend.database import init_db
from backend.routes import auth_routes, scan_routes, user_routes

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="PhishGuard AI",
    description="AI-enriched phishing email detection.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router)
app.include_router(scan_routes.router)
app.include_router(user_routes.router)


@app.on_event("startup")
def on_startup():
    init_db()


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


def _serve(filename: str) -> FileResponse:
    path = FRONTEND_DIR / filename
    return FileResponse(str(path))


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
def landing_page():
    return _serve("index.html")


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page():
    return _serve("login.html")


@app.get("/register", response_class=HTMLResponse, include_in_schema=False)
def register_page():
    return _serve("register.html")


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard_page():
    return _serve("dashboard.html")


@app.get("/settings", response_class=HTMLResponse, include_in_schema=False)
def settings_page():
    return _serve("settings.html")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "PhishGuard AI",
        "ai_model": os.getenv("AI_MODEL", "minimax-m3"),
    }
