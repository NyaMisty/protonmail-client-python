from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class ProtonTokenData:
    refresh_token: Optional[str] = None
    uid: Optional[str] = None
    login_password: Optional[str] = None
    access_token: Optional[str] = None
    cookie: Optional[str] = None
    auth_mode: str = 'ios'


def parse_oauth_token_string(value: str) -> Optional[Tuple[str, str, Optional[str]]]:
    if not value.startswith('token:'):
        return None
    body = value[len('token:'):]
    provider_name, sep, token_data = body.partition(':')
    if not sep:
        raise ValueError('invalid token string, expected token:{provider}:{refresh_token}')
    refresh_token, _, additional_data = token_data.partition(':::')
    if not provider_name or not refresh_token:
        raise ValueError('invalid token string, expected token:{provider}:{refresh_token}')
    return provider_name, refresh_token, additional_data or None


def parse_token_additional_data(additional_data: Optional[str]) -> Dict[str, str]:
    if not additional_data or ':' not in additional_data:
        raise ValueError('Proton token additional_data must be <login_password>:<uid>')
    login_password, uid = additional_data.rsplit(':', 1)
    if not login_password or not uid:
        raise ValueError('Proton token additional_data must be <login_password>:<uid>')
    return {'login_password': login_password, 'uid': uid}


def parse_proton_token(value: str) -> ProtonTokenData:
    parsed = parse_oauth_token_string(value)
    if parsed is None:
        raise ValueError('invalid Proton token, expected token:proton:<refresh_token>:::<additional_data>')
    provider_name, refresh_token, additional_data = parsed
    if provider_name != 'proton':
        raise ValueError(f'unsupported Proton OAuth provider: {provider_name}')
    data = parse_token_additional_data(additional_data)
    return ProtonTokenData(
        refresh_token=refresh_token,
        uid=data['uid'],
        login_password=data['login_password'],
        auth_mode='ios',
    )


def build_proton_token(refresh_token: str, login_password: str, uid: str) -> str:
    return f'token:proton:{refresh_token}:::{login_password}:{uid}'
