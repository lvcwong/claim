# EcoClaim – Mileage & Expenses Claim Form

Web app for LVC EcoPack staff to submit monthly mileage and expense claims and get them approved. Everyone signs in to the same server from any PC or phone.

## Features
- Sign in with username or email, plus password, department and role
- Roles: **Staff**, **HOD**, **Approver**, **Administrator**
- Privacy: you only see your own claims. An HOD or Approver can also open claims waiting for their approval and the ones they approved or returned. Nobody, not even the Administrator, sees other people's drafts.
- Approval restricted to the HOD of the claim's department, or an Approver assigned to that department (never your own claim). Enforced on the server.
- Mileage (km × rate), toll, parking and other expenses with live totals
- Receipt attachments: photos (JPG, PNG, WEBP) or PDF, up to 5 MB each and 10 per row. Photos are shrunk in the browser before upload. Every toll, parking or other amount needs a receipt before the claim can be submitted. Files are stored in the database, and only people who can see the claim can open them.
- Export a claim to **Excel** (with formulas) or **PDF**; export the claim list to Excel
- Email drafts (opened in Outlook / your mail app). An approval email goes to the approver with the claimant in CC.
- Demo accounts for trying it out (remove them before real use under Admin Configurations)

## How it's built
| File | What it does |
|---|---|
| `server.py` | Flask server: sign-in, permissions, and the API for claims, users and settings |
| `Mileage-Expenses-Claim-Form.html` | The whole user interface, served by `server.py` at `/` |
| `requirements.txt`, `railway.json`, `.python-version` | Deployment settings for Railway |

Data is stored in **PostgreSQL** when `DATABASE_URL` is set (Railway), otherwise in a local SQLite file `ecoclaim.db`.

## Deploy on Railway
1. In Railway, create a **New Project → Deploy from GitHub repo** and pick `lvcwong/claim`.
2. In the same project, click **+ Create → Database → PostgreSQL**.
3. Open the web service → **Variables** and add:
   - `DATABASE_URL` = `${{Postgres.DATABASE_URL}}` (a reference to the database)
   - `SETUP_KEY` = a long random secret. You type it once to create the first Administrator, which stops strangers from claiming the account.
4. Open the web service → **Settings → Networking → Generate Domain** to get the public link.
5. Open the link, enter the setup key and create your Administrator account, or click **Try with demo accounts**.

Each push to `main` on GitHub redeploys automatically.

## Run locally
```
python -m venv .venv
.venv\Scripts\pip install flask
.venv\Scripts\python server.py
```
Then open http://127.0.0.1:8000.

## Notes
- Sessions end after 30 minutes of inactivity, or 12 hours at most. Five wrong passwords lock that username for 5 minutes.
- **Admin Configurations → Download backup** saves users, settings and claims as JSON. Receipt files are not included; they stay in the database. **Restore** also imports backups made by the old browser-only version, and their passwords keep working.
- The Excel and PDF exports load their libraries from a CDN.
