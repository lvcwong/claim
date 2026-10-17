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

## Notes
- Data (users and claims) is stored in the browser's local storage on each computer. Use **Backup / Restore** in Admin Configurations to move data between PCs.
- The Excel and PDF exports load their libraries from a CDN, so they need an internet connection.
- Sign-in runs in the browser, so it stops casual misuse but is not server-grade security.
