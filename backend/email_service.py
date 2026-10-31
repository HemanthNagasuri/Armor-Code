import html
import os
import smtplib
import ssl
from pathlib import Path
from email.message import EmailMessage

from dotenv import load_dotenv


load_dotenv(Path(__file__).with_name(".env"), override=False)


class SMTPConfigurationError(RuntimeError):
    pass


def send_otp_email(to_email: str, otp_code: str, action: str) -> None:
    host = os.getenv("SMTP_HOST", "").strip()
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    sender = os.getenv("SMTP_FROM", user).strip()
    if not host or not user or not password or not sender:
        raise SMTPConfigurationError(
            "SMTP_HOST, SMTP_USER, SMTP_PASSWORD, and SMTP_FROM must be configured."
        )

    port = int(os.getenv("SMTP_PORT", "587"))
    use_ssl = os.getenv("SMTP_USE_SSL", "false").strip().lower() == "true"
    if action == "reassign":
        subject = "ArmorCode: authorize code ownership reassignment"
        detail = "authorize a change to the owner signature of your registered code"
        warning = (
            "If you did not request this change, do not share this code with anyone."
        )
    else:
        subject = "ArmorCode: verify your email before signing code"
        detail = "verify your email before assigning an ownership signature to code"
        warning = "Your email will be associated with the registered code artifact."

    safe_otp = html.escape(otp_code)
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = to_email
    message.set_content(
        f"You requested to {detail}.\n\n"
        f"Your one-time verification code is {otp_code}.\n"
        "It expires in 10 minutes and can only be used once.\n\n"
        f"Security notice: {warning}"
    )
    message.add_alternative(
        f"""\
        <!doctype html>
        <html>
          <body style="font-family:Arial,sans-serif;background:#080d16;color:#edf3fa;padding:24px">
            <main style="max-width:520px;margin:auto;background:#0f172a;border:1px solid #334155;border-radius:16px;padding:28px">
              <h2 style="color:#34d399">ArmorCode verification</h2>
              <p>You requested to {html.escape(detail)}.</p>
              <p style="font-size:12px;color:#94a3b8">Your one-time code (expires in 10 minutes):</p>
              <p style="font:700 32px monospace;letter-spacing:8px;color:#6ee7b7">{safe_otp}</p>
              <p style="font-size:12px;color:#fcd34d">{html.escape(warning)}</p>
            </main>
          </body>
        </html>
        """,
        subtype="html",
    )

    timeout = float(os.getenv("SMTP_TIMEOUT", "10"))
    if use_ssl:
        with smtplib.SMTP_SSL(
            host, port, timeout=timeout, context=ssl.create_default_context()
        ) as smtp:
            smtp.login(user, password)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            smtp.login(user, password)
            smtp.send_message(message)
