# PhishGuardAI 🛡️

An AI-powered phishing email detection platform. Paste a suspicious email, get an instant verdict — **SAFE**, **SUSPICIOUS**, or **PHISHING** — with a risk score, confidence level, and detailed breakdown of threat indicators.

Built with FastAPI + SQLite on the backend and plain HTML/CSS/JS on the frontend. AI analysis is powered by the **OpenAI-compatible API** (default model: `minimax-m3`). If no API key is configured, the system falls back to a local heuristic engine automatically.

---

## Features

- 📧 **Email scan** — paste subject + body, get an AI verdict in seconds
- 🤖 **AI analysis** — 7 phishing indicators checked (urgency language, suspicious links, impersonation, credential requests, etc.)
- 🔄 **Heuristic fallback** — works even without an API key (reduced accuracy, labelled as fallback)
- 📊 **Dashboard** — scan history with risk scores, monthly breakdowns, verdict statistics
- 👤 **User accounts** — register, login, JWT auth, change password, update profile
- 🗄️ **SQLite database** — zero-config, file-based, ready to run locally

---

## Project Structure

```
PhishGuard-AI/
│
├── .env.example              # Environment variable template
├── requirements.txt          # Python dependencies
├── start.sh                  # One-command startup script
│
├── backend/
│   ├── main.py               # FastAPI app, route mounting, static file serving
│   ├── ai_engine.py          # OpenAI API integration + heuristic fallback engine
│   ├── auth.py               # JWT token creation & validation, bcrypt password hashing
│   ├── database.py           # SQLAlchemy setup, DB init, session factory
│   ├── models.py             # User and ScanResult ORM models
│   └── routes/
│       ├── auth_routes.py    # /api/auth — register, login, me, change-password
│       ├── scan_routes.py    # /api/scan — create scan, history, get by ID
│       └── user_routes.py    # /api/user — settings (get/update), stats
│
├── frontend/
│   ├── index.html            # Main scan page
│   ├── login.html            # Login page
│   ├── register.html         # Registration page
│   ├── dashboard.html        # Scan history & statistics
│   └── settings.html         # User profile settings
│
└── static/
    ├── app.js                # Scan form submission, results rendering
    ├── dashboard.js          # Dashboard charts and history table
    ├── settings.js           # Settings form, password change
    └── style.css             # Global styles
```

---

## Tech Stack

| Layer     | Technology                                      |
|-----------|-------------------------------------------------|
| Backend   | Python 3.10+, FastAPI, Uvicorn                  |
| Database  | SQLite (via SQLAlchemy 2.0)                     |
| Auth      | JWT (python-jose), bcrypt (passlib)             |
| AI Engine | OpenAI-compatible API (default: `minimax-m3`)   |
| Frontend  | Vanilla HTML / CSS / JavaScript                 |

---

## Getting Started

### 1. Clone and set up

```bash
git clone https://github.com/nihatkazimzada/PhishGuard-AI.git
cd PhishGuard-AI

python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and set your values:

```env
# Required for AI analysis
OPENAI_API_KEY=your_api_key_here
OPENAI_BASE_URL=https://api.openai.com/v1   # or your provider's URL
AI_MODEL=minimax-m3                          # or gpt-4o-mini, etc.

# JWT settings
SECRET_KEY=change-this-to-a-long-random-string
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Database (SQLite, auto-created)
DATABASE_URL=sqlite:///phishguard.db
```

> **No API key?** The system will still run using the built-in heuristic fallback. Results will be labelled `(Heuristic fallback used)` and accuracy will be lower.

### 3. Start the server

```bash
bash start.sh
```

Or manually:

```bash
uvicorn backend.main:app --host 0.0.0.0 --port 8001 --reload
```

App is available at **http://localhost:8001**  
API docs at **http://localhost:8001/docs**

---

## How It Works

```
User pastes email
       ↓
POST /api/scan
       ↓
ai_engine.analyze_email(subject, body)
       ↓
  [API key set?]
  YES → OpenAI-compatible API call → parse JSON response
  NO  → Local heuristic engine (keyword/pattern matching)
       ↓
Result saved to DB (ScanResult)
       ↓
Verdict returned: SAFE / SUSPICIOUS / PHISHING
  + risk_score (0–100)
  + confidence (0–100)
  + summary, recommendation, technical_details
  + 7 indicator flags
```

### AI Response Format

The AI engine prompts the model to return structured JSON:

```json
{
  "verdict": "PHISHING",
  "risk_score": 87,
  "confidence": 92,
  "summary": "This email impersonates a bank and requests login credentials urgently.",
  "indicators": {
    "urgency_language": true,
    "suspicious_links": true,
    "impersonation_attempt": true,
    "grammar_errors": false,
    "unusual_sender_patterns": true,
    "credential_request": true,
    "financial_pressure": false
  },
  "recommendation": "Do not click any links. Report to your IT team.",
  "technical_details": "..."
}
```

---

## API Endpoints

### Auth — `/api/auth`

| Method | Path                       | Description                        | Auth required |
|--------|----------------------------|------------------------------------|:-------------:|
| POST   | `/api/auth/register`       | Create new account, returns JWT    | ✗ |
| POST   | `/api/auth/login`          | Login, returns JWT                 | ✗ |
| GET    | `/api/auth/me`             | Get current user info              | ✓ |
| PUT    | `/api/auth/change-password`| Change password                    | ✓ |

### Scan — `/api/scan`

| Method | Path                    | Description                         | Auth required |
|--------|-------------------------|-------------------------------------|:-------------:|
| POST   | `/api/scan`             | Submit email for analysis           | ✓ |
| GET    | `/api/scan/history`     | Paginated scan history              | ✓ |
| GET    | `/api/scan/{id}`        | Get a single scan by ID             | ✓ |

### User — `/api/user`

| Method | Path                | Description                             | Auth required |
|--------|---------------------|-----------------------------------------|:-------------:|
| GET    | `/api/user/settings`| Get profile (email, username, etc.)     | ✓ |
| PUT    | `/api/user/settings`| Update email or username                | ✓ |
| GET    | `/api/user/stats`   | Scan statistics & monthly breakdown     | ✓ |

### Other

| Method | Path      | Description         |
|--------|-----------|---------------------|
| GET    | `/health` | Service health check (returns AI model name) |

---

## Notes & Limitations

- **SQLite** is used for simplicity. For production, migrate to PostgreSQL.
- The AI engine uses any **OpenAI-compatible API** (OpenAI, Azure, MiniMax, Groq, etc.) — just set `OPENAI_BASE_URL` and `AI_MODEL` accordingly.
- Email body is capped at **6000 characters** sent to the AI (20 000 stored in DB).
- JWT tokens expire after **24 hours** by default (`ACCESS_TOKEN_EXPIRE_MINUTES=1440`).
- CORS is currently set to `allow_origins=["*"]` — restrict this before any public deployment.

---

## Future Improvements

- [ ] Full `.eml` file upload support
- [ ] Email header parsing (SPF, DKIM, sender spoofing)
- [ ] Admin panel for global scan monitoring
- [ ] PostgreSQL support for production deployments
- [ ] Rate limiting per user
- [ ] Bulk scan / organization API access

---

## License

Developed as one of bootcamp projects. No license is currently applied — all rights reserved by the authors.

---
