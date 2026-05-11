from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from protonmail_client import ProtonMailClient, parse_proton_token

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from example.bearer_auth_manager import fetch_latest_inbox_with_bearer_auth
from example.cookie_auth_manager import fetch_latest_inbox_with_cookie_auth


class RecordingBearerAuthManager:
    uid = "UID"
    access_token = "ACCESS_TOKEN"
    refresh_token = "REFRESH_TOKEN"
    auth_time = "AUTH_TIME"
    login_password = "LOGIN_PASSWORD"

    def __init__(self):
        self.apply_headers_calls = 0
        self.refresh_calls = 0

    def apply_headers(self, session):
        self.apply_headers_calls += 1
        session.headers["authorization"] = f"Bearer {self.access_token}"
        session.headers["x-pm-uid"] = self.uid

    def refresh(self, session, api_url):
        self.refresh_calls += 1
        self.access_token = "ROTATED_ACCESS_TOKEN"
        self.refresh_token = "ROTATED_REFRESH_TOKEN"
        self.apply_headers(session)
        return True

    def current_token(self):
        return f"token:proton:{self.uid}.{self.access_token}.{self.refresh_token}.{self.auth_time}:::{self.login_password}"


class RecordingCookieAuthManager:
    uid = "UID"
    access_token = None
    refresh_token = None
    auth_time = None
    login_password = "LOGIN_PASSWORD"

    def __init__(self):
        self.apply_headers_calls = 0
        self.refresh_calls = 0

    def apply_headers(self, session):
        self.apply_headers_calls += 1
        session.headers["cookie"] = "AUTH-UID=COOKIE_VALUE; proton_session=SESSION_VALUE"
        session.headers["x-pm-uid"] = self.uid

    def refresh(self, session, api_url):
        self.refresh_calls += 1
        return False

    def current_token(self):
        raise RuntimeError("Cookie auth cannot be exported as OAuth Proton token")


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self.payload = payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"status {self.status_code}")

    def json(self):
        return self.payload


class FakeSession:
    def __init__(self):
        self.headers = {}
        self.closed = False
        self.requests = []
        self.fail_messages_once = True

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs, dict(self.headers)))
        if url.endswith("core/v4/users"):
            return FakeResponse(200, {"Code": 1000, "User": {"Keys": [{"ID": "key-id"}]}})
        if url.endswith("core/v4/keys/salts"):
            return FakeResponse(200, {"Code": 1000, "KeySalts": [{"ID": "key-id", "KeySalt": "YWJjZGVmZ2hpamtsbW5vcA=="}]})
        if url.endswith("mail/v4/messages"):
            if self.fail_messages_once:
                self.fail_messages_once = False
                return FakeResponse(401, {"Code": 401})
            return FakeResponse(200, {"Code": 1000, "Total": 1, "Messages": [{"ID": "message-id"}]})
        if url.endswith("mail/v4/messages/message-id"):
            return FakeResponse(200, {"Code": 1000, "Message": {
                "ID": "message-id",
                "Subject": "hello",
                "Sender": {"Address": "sender@example.com"},
                "ToList": [{"Address": "user@example.com"}],
                "Body": "plain body",
                "MIMEType": "text/plain",
            }})
        raise AssertionError(url)

    def close(self):
        self.closed = True


class AuthManagerExampleTest(unittest.TestCase):
    def test_bearer_example_uses_auth_manager_and_exports_latest_token(self):
        auth_manager = RecordingBearerAuthManager()
        client_sessions = []
        with patch("requests.Session", lambda: client_sessions.append(FakeSession()) or client_sessions[-1]):
            rfc822_message, latest_token = fetch_latest_inbox_with_bearer_auth("user@example.com", auth_manager)

        token_data = parse_proton_token(latest_token)
        requested_urls = [url for _, url, _, _ in client_sessions[0].requests]
        self.assertIn(b"Subject: hello", rfc822_message)
        self.assertEqual(auth_manager.refresh_calls, 1)
        self.assertEqual(token_data.access_token, "ROTATED_ACCESS_TOKEN")
        self.assertEqual(token_data.refresh_token, "ROTATED_REFRESH_TOKEN")
        self.assertFalse(any("auth/v4/refresh" in url for url in requested_urls))
        self.assertTrue(client_sessions[0].closed)

    def test_cookie_example_uses_auth_manager_without_exporting_token(self):
        auth_manager = RecordingCookieAuthManager()
        client_sessions = []
        with patch("requests.Session", lambda: client_sessions.append(FakeSession()) or client_sessions[-1]):
            with self.assertRaises(RuntimeError):
                fetch_latest_inbox_with_cookie_auth("user@example.com", auth_manager)

        requested_urls = [url for _, url, _, _ in client_sessions[0].requests]
        self.assertEqual(auth_manager.refresh_calls, 1)
        self.assertFalse(any("auth/v4/refresh" in url for url in requested_urls))
        self.assertTrue(client_sessions[0].closed)

    def test_client_auth_manager_is_the_only_refresh_path(self):
        auth_manager = RecordingBearerAuthManager()
        client_sessions = []
        with patch("requests.Session", lambda: client_sessions.append(FakeSession()) or client_sessions[-1]):
            client = ProtonMailClient(email_account="user@example.com", auth_manager=auth_manager)
            rfc822_message = client.get_mail_by_index(1, mailbox="inbox")
            latest_token = client.current_token()
            client.cleanup()

        token_data = parse_proton_token(latest_token)
        requested_urls = [url for _, url, _, _ in client_sessions[0].requests]
        self.assertIn(b"plain body", rfc822_message)
        self.assertEqual(auth_manager.refresh_calls, 1)
        self.assertEqual(token_data.access_token, "ROTATED_ACCESS_TOKEN")
        self.assertEqual(token_data.refresh_token, "ROTATED_REFRESH_TOKEN")
        self.assertFalse(any("auth/v4/refresh" in url for url in requested_urls))
        self.assertTrue(client_sessions[0].closed)


if __name__ == "__main__":
    unittest.main()
