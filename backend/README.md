# ArmorCode local backend

The web app needs this API for account login, code ownership records, and email OTP delivery. Do not open `frontend\index.html` directly; run the API and use `http://127.0.0.1:8000`.

## Run on Windows

From the workspace root in PowerShell, install dependencies and create a private SMTP configuration file:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
Copy-Item backend\.env.example backend\.env
notepad backend\.env
python backend\server.py
```

Set the values in `backend\.env` to match your SMTP provider. For Gmail, use an app password (not your regular account password); app passwords require 2-Step Verification. Keep the file private; `.env` files are ignored by Git. For SMTP over implicit TLS (usually port 465), set `SMTP_PORT` to `465` and `SMTP_USE_SSL` to `true`. Port 587 uses STARTTLS. Restart the backend after changing the file.

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). If SMTP is missing or unavailable, OTP requests fail and signing remains blocked; the server does not expose OTPs in API responses or logs. Missing configuration and delivery failures produce different setup guidance in the app.

## Ownership and OTP behavior

- Accounts use server-side password hashes and expiring bearer sessions.
- Every signature assignment sends a one-time code to the signed-in account email.
- Reassigning code registered to another owner requires both the signed-in user's OTP and a separate OTP delivered to the original owner's email.
- OTPs expire after 10 minutes, allow at most five verification attempts, and are rate-limited per email and action.
- The database identifies an artifact by SHA-256 of its exact UTF-8 content after removing the app's zero-width watermark characters. Line endings and other whitespace are not normalized.
- SQLite stores the owner email, signature, hash, and a short code preview; it does not store the full source for new records.

The included server is intended for local development. Do not expose it to the public internet as-is; production deployment needs HTTPS, deployment-specific session/secret management, and operational hardening.
