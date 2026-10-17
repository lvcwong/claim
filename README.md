# EcoClaim – Mileage & Expenses Claim Form

Web app for LVC EcoPack staff to submit monthly mileage and expense claims and get them approved. Everyone signs in to the same server and sees the same claims from any PC or phone.

## Features
- Sign in with username or email, plus password, department and role
- Roles: **Staff**, **HOD**, **Approver**, **Administrator**
- Approval restricted to the HOD of the claim's department, or an Approver assigned to that department (never your own claim). Enforced on the server.
- Mileage (km × rate), toll, parking and other expenses with live totals
- Export a claim to **Excel** (with formulas) or **PDF**; export the claim list to Excel
- Email drafts (opened in Outlook / your mail app). An approval email goes to the approver with the claimant in CC.
- Demo accounts for trying it out (remove them before real use under Admin Configurations)

## How it's built
| File | What it does |
|---|---|
| `app.py` | Flask server: sign-in, permissions, and the API for claims, users and settings |
| `Mileage-Expenses-Claim-Form.html` | The whole user interface, served by `app.py` at `/` |
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
.venv\Scripts\python app.py
```
Then open http://127.0.0.1:8000.

## Notes
- Sessions end after 30 minutes of inactivity, or 12 hours at most. Five wrong passwords lock that username for 5 minutes.
- **Admin Configurations → Download backup** saves everything as JSON. **Restore** also imports backups made by the old browser-only version, and their passwords keep working.
- The Excel and PDF exports load their libraries from a CDN.
