# PhishGuard AI documentation

This project combines a cybersecurity dashboard with triage tools for email, website, and SMS analysis.

## Core features

- Dashboard with live statistics from database-backed scan history
- Email, URL, and SMS threat analysis modules
- PDF report generation
- Scan history and filtering
- WebSocket-based scan progress updates
- Safe detection logic with explicit AI unavailability messaging when no provider is configured

## Architecture

- Frontend: React + Vite + Tailwind-inspired styles
- Backend: FastAPI, Pydantic, SQLAlchemy, SQLite by default
- Reporting: ReportLab
- Safety: SSRF-safe URL checks, private-IP blocking, and explicit fetch-failure messaging
