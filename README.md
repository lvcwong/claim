# EcoClaim – Mileage & Expenses Claim Form

Single-file web app (`Mileage-Expenses-Claim-Form.html`) for LVC EcoPack staff to submit monthly mileage and expense claims for approval.

## Features
- Sign in with username or email, plus password, department and role
- Roles: **Staff**, **HOD**, **Approver**, **Administrator**
- Approval restricted to the HOD of the claim's department, or an Approver assigned to that department (never your own claim)
- Mileage (km × rate), toll, parking and other expenses with live totals
- Export a claim to **Excel** (with formulas) or **PDF**; export the claim list to Excel
- Email notification drafts to the approver / claimant
- Demo accounts for trying it out (remove them before real use under Admin Configurations)

## Usage
Open `Mileage-Expenses-Claim-Form.html` in Chrome or Edge. The first time, create the Administrator account or click **Try with demo accounts**.

## Automatic email (SMTP)
The page can't talk to an SMTP server directly, and putting a mail password in the page would expose it. A small relay, `mail-relay/mail_relay.py`, holds the SMTP login and sends the email. It uses only Python's standard library, so nothing needs installing beyond Python.

1. **Get a Google App Password** (lvc-ecopack.com uses Google Workspace). Sign in as the sending account (e.g. `claims@lvc-ecopack.com`). Turn on 2-Step Verification, then create an app password at https://myaccount.google.com/apppasswords.
2. **Configure the relay.** Copy `mail-relay/config.example.json` to `mail-relay/config.json` and fill in `smtp_user`, `from_email`, `smtp_password` (the app password) and a long random `relay_key`. `config.json` is git-ignored, so it never reaches GitHub.
3. **Start the relay.** Double-click `mail-relay/start-mail-relay.bat` and keep the window open.
4. **Connect the form.** Sign in as Administrator and open **Admin Configurations → Automatic email (SMTP)**. Enter the relay address (`http://127.0.0.1:8025`) and the `relay_key`, tick when to send, and click **Send test email to me**.

When a claim is approved, an email goes automatically to the approver, with the staff member who applied in CC. When a claim is returned, the claimant gets the email, with the approver in CC. You can also have approvers emailed when a claim is submitted. If the relay can't be reached, the form falls back to opening an email draft in your mail app.

**Using it from other PCs:** set `listen_host` to `0.0.0.0` in `config.json` and allow port 8025 in Windows Firewall. On the other PCs, set the relay address to `http://<relay-PC-IP>:8025`. Keep it inside the office network. The relay only sends to `allowed_domains`, needs the relay key, and limits how many emails it sends per minute.

## Notes
- Data (users and claims) is stored in the browser's local storage on each computer. Use **Backup / Restore** in Admin Configurations to move data between PCs.
- The Excel and PDF exports load their libraries from a CDN, so they need an internet connection.
- Sign-in runs in the browser, so it stops casual misuse but is not server-grade security.
