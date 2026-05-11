from __future__ import annotations

from protonmail_client import ProtonCookieAuthManager, ProtonMailClient, ProtonTokenData


def fetch_latest_inbox_with_cookie_auth(email: str, auth_manager: ProtonCookieAuthManager) -> bytes:
    client = ProtonMailClient(email_account=email, auth_manager=auth_manager)
    try:
        return client.get_mail_by_index(1, mailbox="inbox")
    finally:
        client.cleanup()


if __name__ == "__main__":
    auth_manager = ProtonCookieAuthManager(ProtonTokenData(
        cookie="AUTH-UID=COOKIE_VALUE; proton_session=SESSION_VALUE",
        login_password="LOGIN_PASSWORD",
    ))
    rfc822_message = fetch_latest_inbox_with_cookie_auth("user@example.com", auth_manager)
    print(rfc822_message.decode("utf-8", errors="replace"))
