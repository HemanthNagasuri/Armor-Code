import os
import smtplib
import ssl
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"), override=True)

host = os.getenv("SMTP_HOST")
port = int(os.getenv("SMTP_PORT", "587"))
user = os.getenv("SMTP_USER")
password = os.getenv("SMTP_PASSWORD")
use_ssl = os.getenv("SMTP_USE_SSL", "false").lower() == "true"

try:
    print("1. Checking SMTP configuration...")

    if not all([host, user, password]):
        raise ValueError("Missing SMTP environment variables.")

    print("2. Connecting to Gmail SMTP...")

    if use_ssl:
        smtp = smtplib.SMTP_SSL(
            host, port, timeout=20,
            context=ssl.create_default_context()
        )
    else:
        smtp = smtplib.SMTP(host, port, timeout=20)

    with smtp:
        print("3. SMTP connection successful!")

        if not use_ssl:
            smtp.ehlo()
            print("4. Starting TLS...")
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            print("5. TLS encryption successful!")

        print("6. Authenticating with Gmail...")
        smtp.login(user, password)

        print("7. Gmail authentication successful!")
        print("SUCCESS: SMTP is ready to send emails.")

except Exception as error:
    print("\nSMTP TEST FAILED")
    print("Error type:", type(error).__name__)
    print("Error:", str(error))