from __future__ import annotations

from protonmail_client import ProtonBearerAuthManager, ProtonMailClient, ProtonTokenData


def fetch_latest_inbox_with_bearer_auth(email: str, auth_manager: ProtonBearerAuthManager) -> tuple[bytes, str]:
    client = ProtonMailClient(email_account=email, auth_manager=auth_manager)
    try:
        rfc822_message = client.get_mail_by_index(1, mailbox="inbox")
        return rfc822_message, client.current_token()
    finally:
        client.cleanup()


if __name__ == "__main__":
    auth_manager = ProtonBearerAuthManager(ProtonTokenData(
        uid="UID",
        access_token="ACCESS_TOKEN",
        refresh_token="REFRESH_TOKEN",
        auth_time="AUTH_TIME",
        login_password="LOGIN_PASSWORD",
    ))
    rfc822_message, latest_token = fetch_latest_inbox_with_bearer_auth("user@example.com", auth_manager)
    print(rfc822_message.decode("utf-8", errors="replace"))
    print("Save this latest token for the next run:", latest_token)
