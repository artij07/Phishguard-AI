# PhishGuard AI

PhishGuard AI is a cybersecurity web application for analyzing suspicious emails, malicious websites, and smishing SMS messages. It includes a dashboard, persistent scan history, report generation, and a Python/FastAPI backend.

## Quick start

### Windows (PowerShell)

1. Create and activate a virtual environment:
   ```powershell
   cd backend
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

2. Start the backend:
   ```powershell
   cd backend
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. Start the frontend in another terminal:
   ```powershell
   cd frontend
   npm install
   npm run dev -- --host 0.0.0.0 --port 5173
   ```

4. Open:
   - Frontend: http://localhost:5173
   - API docs: http://localhost:8000/docs

## Project structure

- backend/app: FastAPI backend, models, scanners, reporting, AI services
- backend/tests: validation tests for scanner logic
- frontend/src: React + Vite dashboard and scanner views
- reports: generated report output
- docs: documentation files

## Environment

Copy `.env.example` to `.env` and configure any secrets. AI providers are optional; the app continues to work without them.

## Notes

This project is intentionally designed to remain practical, safe, and maintainable. It uses deterministic rule-based analysis and optional AI explanations without exposing secrets to the frontend.
