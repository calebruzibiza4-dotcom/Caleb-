Dern-Support Repair Shop — Minimal Flask prototype

Overview
- Small Flask app to manage customers, support requests, spare parts and a knowledge base.
- Simple dashboard with lightweight analytics.

Quick start (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Notes
- App uses SQLite database stored in `instance/repairshop.db`.
- UI uses Bootstrap via CDN for a modern, clean look.
- This is a scaffold and can be extended with authentication, API tokens, and background jobs.
