import os
import tempfile
import unittest
from unittest.mock import patch


_test_database = tempfile.TemporaryDirectory()
os.environ["ARMORCODE_DB_PATH"] = os.path.join(_test_database.name, "test.db")

from fastapi import HTTPException

from backend import database, email_service, server
from backend.armorcode_cli import encode_signature_to_zw


class AuthWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        with database.get_db() as conn:
            conn.execute("DELETE FROM otp_codes")
            conn.execute("DELETE FROM otp_send_events")
            conn.execute("DELETE FROM sessions")
            conn.execute("DELETE FROM code_registry")
            conn.execute("DELETE FROM users")
        self.owner = database.create_user(
            "owner@example.test", "Code Owner", "owner-password-2026"
        )
        self.owner_token = database.create_session(self.owner["id"])

    def test_account_session_is_required(self) -> None:
        with self.assertRaises(HTTPException) as error:
            server.current_user_from_authorization(None)
        self.assertEqual(error.exception.status_code, 401)

        user = server.current_user_from_authorization(
            f"Bearer {self.owner_token}"
        )
        self.assertEqual(user["email"], self.owner["email"])

    def test_assignment_and_reassignment_require_both_email_codes(self) -> None:
        source = "def protected():\n    return 'original'\n"
        sent_codes: list[tuple[str, str, str]] = []

        def capture_otp(email: str, otp: str, action: str) -> None:
            sent_codes.append((email, otp, action))

        with patch.object(server, "send_otp_email", side_effect=capture_otp):
            sent = server.send_sign_otp(
                server.SignOtpRequest(code_text=source, signature="Owner-Signature"),
                self.owner,
            )
        self.assertTrue(sent["success"])
        self.assertNotIn("demo_otp", sent)
        self.assertEqual(sent_codes[-1][0], self.owner["email"])

        signed = server.verify_sign_otp(
            server.SignOtpRequest(
                code_text=source,
                signature="Owner-Signature",
                otp_code=sent_codes[-1][1],
            ),
            self.owner,
        )
        self.assertTrue(signed["verified"])
        code_hash = database.compute_normalized_code_hash(source)
        self.assertEqual(
            database.get_code_owner(code_hash)["owner_email"], self.owner["email"]
        )

        recipient = database.create_user(
            "recipient@example.test", "New Owner", "recipient-password-2026"
        )
        database.create_session(recipient["id"])
        with patch.object(server, "send_otp_email", side_effect=capture_otp):
            request = server.send_sign_otp(
                server.SignOtpRequest(code_text=source, signature="New-Signature"),
                recipient,
            )
        self.assertTrue(request["requires_reassignment"])
        self.assertEqual(sent_codes[-1][0], recipient["email"])

        result = server.verify_sign_otp(
            server.SignOtpRequest(
                code_text=source,
                signature="New-Signature",
                otp_code=sent_codes[-1][1],
            ),
            recipient,
        )
        self.assertTrue(result["requires_reassignment"])
        with patch.object(server, "send_otp_email", side_effect=capture_otp):
            reassign = server.send_reassign_otp(
                server.SignOtpRequest(code_text=source, signature="New-Signature"),
                recipient,
            )
        self.assertTrue(reassign["success"])
        self.assertEqual(sent_codes[-1][0], self.owner["email"])
        self.assertEqual(sent_codes[-1][2], "reassign")

        result = server.verify_reassign_otp(
            server.ReassignOtpRequest(
                code_text=source,
                signature="New-Signature",
                otp_code=sent_codes[-1][1],
            ),
            recipient,
        )
        self.assertTrue(result["verified"])
        record = database.get_code_owner(code_hash)
        self.assertEqual(record["owner_email"], recipient["email"])
        self.assertEqual(record["author_signature"], "New-Signature")
        self.assertEqual(record["history"][0]["previous_owner"], self.owner["email"])

    def test_code_identity_is_exact_except_for_watermark_characters(self) -> None:
        source = "line one\n\nline two  \n"
        tagged = source[:4] + "\u200b\u200c\u200d" + source[4:]
        self.assertEqual(
            database.compute_normalized_code_hash(source),
            database.compute_normalized_code_hash(tagged),
        )
        self.assertNotEqual(
            database.compute_normalized_code_hash(source),
            database.compute_normalized_code_hash(source.replace("  ", " ")),
        )

    def test_owner_payload_is_detected_with_or_without_checksum(self) -> None:
        for include_checksum in (True, False):
            payload = encode_signature_to_zw(
                "Creator-Signature",
                owner_email="owner@example.test",
                include_checksum=include_checksum,
            )
            self.assertEqual(
                server.extract_zw_author_and_owner(f"code{payload}"),
                ("Creator-Signature", "owner@example.test"),
            )

    def test_smtp_failure_does_not_report_otp_as_sent(self) -> None:
        with patch.object(
            server,
            "send_otp_email",
            side_effect=email_service.SMTPConfigurationError("SMTP is not configured"),
        ):
            with self.assertRaises(HTTPException) as error:
                server.send_sign_otp(
                    server.SignOtpRequest(
                        code_text="source", signature="Owner-Signature"
                    ),
                    self.owner,
                )
        self.assertEqual(error.exception.status_code, 503)
        self.assertIn("backend/.env.example", error.exception.detail)
        with database.get_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM otp_codes").fetchone()[0]
        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
