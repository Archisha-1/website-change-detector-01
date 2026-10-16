# SignalWatch — Website Change Detector

A standalone local-first Python project that monitors public webpages, extracts text, hashes normalized content, and saves a new snapshot only when meaningful text changes.

## Run it
Requirements: Python 3.10+ and an internet connection. No third-party packages are required.

**Windows**
```powershell
py server.py
```
**macOS/Linux**
```bash
python3 server.py
```
Then open **http://127.0.0.1:8000**. Add a public HTTP(S) URL. Stop the app with Ctrl+C. Data is stored in `signalwatch.db`.

## Implemented
- Local dashboard to add/delete monitors and manually check a page.
- Scheduled checks from 15 minutes to 24 hours while the server is running.
- Public URL validation, request timeout and response-size cap.
- Basic HTML text extraction and timestamp noise filtering.
- SHA-256 hash-based change detection.
- SQLite baseline snapshots, history and local event log.
- Low/normal/high sensitivity settings.

## Not implemented yet
- Playwright/Puppeteer for JavaScript-rendered pages.
- CSS selector region picking and true keyword-only detection/alerts.
- Email, Telegram or Discord notifications.
- Screenshot and visual diffs, richer text diffs, distributed job queue or cloud deployment.
- Authentication/multi-user access. The server binds to localhost and is for local development.

## How it works
Browser dashboard → JSON API → Python HTTP server → scheduler/fetcher → text extraction/normalization → SHA-256 comparison → SQLite snapshots and events.

The first successful check establishes a baseline. A later successful check stores a snapshot only if its hash differs. The app does not bypass logins, CAPTCHAs or access controls. Respect website terms and rate limits.
