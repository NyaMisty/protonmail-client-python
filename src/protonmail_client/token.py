from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class ProtonTokenData:
    refresh_token: Optional[str] = None
    uid: Optional[str] = None
    login_password: Optional[str] = None
    access_token: Optional[str] = None
    auth_time: Optional[str] = None
    cookie: Optional[str] = None
    auth_mode: str = 'ios'


def parse_oauth_token_string(value: str) -> Optional[Tuple[str, str, Optional[str]]]:
    if not value.startswith('token:'):
        return None
    body = value[len('token:'):]
    provider_name, sep, token_data = body.partition(':')
    if not sep:
        raise ValueError('invalid token string, expected token:{provider}:{token_payload}')
    token_payload, _, additional_data = token_data.partition(':::')
    if not provider_name or not token_payload:
        raise ValueError('invalid token string, expected token:{provider}:{token_payload}')
    return provider_name, token_payload, additional_data or None


def parse_proton_token(value: str) -> ProtonTokenData:
    parsed = parse_oauth_token_string(value)
    if parsed is None:
        raise ValueError('invalid Proton token, expected token:proton:<uid>.<access_token>.<refresh_token>.<auth_time>:::<login_password>')
    provider_name, token_payload, additional_data = parsed
    if provider_name != 'proton':
        raise ValueError(f'unsupported Proton OAuth provider: {provider_name}')
    if not additional_data:
        raise ValueError('Proton token additional_data must be <login_password>')
    uid, sep, rest = token_payload.partition('.')
    if not sep:
        raise ValueError('invalid Proton token, expected token:proton:<uid>.<access_token>.<refresh_token>.<auth_time>:::<login_password>')
    access_token, sep, rest = rest.partition('.')
    refresh_token, sep, auth_time = rest.rpartition('.')
    if not sep or not uid or not access_token or not refresh_token or not auth_time:
        raise ValueError('invalid Proton token, expected token:proton:<uid>.<access_token>.<refresh_token>.<auth_time>:::<login_password>')
    return ProtonTokenData(
        uid=uid,
        access_token=access_token,
        refresh_token=refresh_token,
        auth_time=auth_time,
        login_password=additional_data,
        auth_mode='ios',
    )


def build_proton_token(uid: str, access_token: str, refresh_token: str, auth_time: str, login_password: str) -> str:
    return f'token:proton:{uid}.{access_token}.{refresh_token}.{auth_time}:::{login_password}'
