# protonmail-client-python

ProtonMail client utilities and login helpers.

## Refresh token handling

Proton rotates refresh tokens during login and refresh. Always persist and reuse the latest token printed by the CLI or returned by `_refresh_access_token()`; older refresh tokens may stop working immediately after a successful refresh.

## Example: refresh a token and decrypt the latest inbox message

```python
from protonmail_client import ProtonMailClient, build_proton_token

email = "user@example.com"

# Token format:
# token:proton:<refresh_token>:::<login_password>:<uid>
token = "token:proton:REFRESH_TOKEN:::LOGIN_PASSWORD:UID"

client = ProtonMailClient(email_account=email, token=token)

try:
    refresh_result = client._refresh_access_token()
    if refresh_result.get("Code") != 1000:
        raise RuntimeError(f"refresh failed: {refresh_result!r}")

    latest_token = build_proton_token(
        refresh_token=client.refresh_token,
        login_password=client.login_password,
        uid=client.uid,
    )

    mail_list = client.get_mail_list(mailbox="inbox", page=0, page_size=1)
    messages = mail_list.get("Messages") or []
    if not messages:
        raise RuntimeError("inbox is empty")

    message = client.get_mail_detail(messages[0]["ID"])
    rfc822_bytes = client.message_to_rfc822(message)

    with open("latest-inbox.eml", "wb") as f:
        f.write(rfc822_bytes)

    print("Save this latest token for the next run:", latest_token)
finally:
    client.cleanup()
```

Use `get_mail_list(mailbox="inbox", page=0, page_size=1)` for the newest inbox message. `get_mail_by_index(1)` does not mean the newest message in the current implementation.
