import os
import smtplib
import ssl
from pathlib import Path
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"), override=True)

email = EmailMessage()
email["Subject"] = "ArmorCode - SMTP Test"
email["From"] = os.getenv("SMTP_FROM")
email["To"] = os.getenv("SMTP_USER")

email.set_content(
    "Congratulations! Your ArmorCode SMTP integration is working successfully."
)

try:
    with smtplib.SMTP(
        os.getenv("SMTP_HOST"),
        int(os.getenv("SMTP_PORT", "587")),
        timeout=20
    ) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        smtp.login(
            os.getenv("SMTP_USER"),
            os.getenv("SMTP_PASSWORD")
        )
        smtp.send_message(email)

    print("SUCCESS: Test email sent!")

except Exception as error:
    print("FAILED:", type(error).__name__, str(error))