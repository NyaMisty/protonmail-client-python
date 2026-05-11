from __future__ import annotations

import logging
import secrets
import time
from http.cookies import SimpleCookie
from typing import Any, Optional, Protocol

import requests

from .auth import ACCEPT, APP_VERSION, USER_AGENT, redact_api_data
from .token import ProtonTokenData, build_proton_token

logger = logging.getLogger(__name__)


class ProtonAuthManager(Protocol):
    uid: Optional[str]
    access_token: Optional[str]
    refresh_token: Optional[str]
    auth_time: Optional[str]
    login_password: Optional[str]

    def apply_headers(self, session: requests.Session) -> None:
        ...

    def refresh(self, session: requests.Session, api_url: str) -> bool:
        ...

    def current_token(self) -> str:
        ...


class ProtonBearerAuthManager:
    def __init__(self, token: ProtonTokenData):
        self.uid = token.uid
        self.access_token = token.access_token
        self.refresh_token = token.refresh_token
        self.auth_time = token.auth_time
        self.login_password = token.login_password
        self.auth_mode = token.auth_mode

    def apply_headers(self, session: requests.Session) -> None:
        session.headers.update({
            'x-pm-appversion': APP_VERSION,
            'user-agent': USER_AGENT,
        })
        if self.uid:
            session.headers['x-pm-uid'] = self.uid
        if self.access_token:
            session.headers['authorization'] = f'Bearer {self.access_token}'

    def refresh(self, session: requests.Session, api_url: str) -> bool:
        if not self.uid or not self.refresh_token:
            raise RuntimeError('ProtonMail refresh requires uid and refresh_token')
        logger.info('Refreshing ProtonMail access token for uid %s', self.uid)
        old_auth = session.headers.get('authorization')
        data = {
            'UID': self.uid,
            'RefreshToken': self.refresh_token,
            'ResponseType': 'token',
            'GrantType': 'refresh_token',
            'RedirectURI': 'https://protonmail.ch',
            'State': secrets.token_urlsafe(32),
        }
        if self.access_token:
            data['AccessToken'] = self.access_token
        try:
            last_error = None
            for attempt in range(3):
                try:
                    response = session.post(f'{api_url}/auth/v4/refresh', json=data)
                    break
                except requests.RequestException as e:
                    last_error = e
                    logger.warning('ProtonMail refresh network error, retry %d/3', attempt + 1)
                    if attempt == 2:
                        raise
                    time.sleep(1)
            else:
                raise last_error
            if old_auth and response.status_code >= 400:
                session.headers['authorization'] = old_auth
            response.raise_for_status()
            ret = response.json()
            if ret.get('Code') != 1000:
                raise RuntimeError(f'ProtonMail refresh error: {redact_api_data(ret)}')
            self.uid = ret.get('UID') or self.uid
            self.access_token = ret['AccessToken']
            self.refresh_token = ret.get('RefreshToken') or self.refresh_token
            self.apply_headers(session)
            return True
        except Exception:
            if old_auth:
                session.headers['authorization'] = old_auth
            raise

    def current_token(self) -> str:
        if not self.uid or not self.access_token or not self.refresh_token or not self.auth_time or not self.login_password:
            raise RuntimeError('ProtonMail token requires uid, access_token, refresh_token, auth_time and login_password')
        return build_proton_token(self.uid, self.access_token, self.refresh_token, self.auth_time, self.login_password)


class ProtonCookieAuthManager:
    def __init__(self, token: ProtonTokenData):
        self.cookie = token.cookie
        self.uid = token.uid
        self.access_token = token.access_token
        self.refresh_token = token.refresh_token
        self.auth_time = token.auth_time
        self.login_password = token.login_password
        self.auth_mode = token.auth_mode

    def apply_headers(self, session: requests.Session) -> None:
        session.headers.update({
            'x-pm-appversion': 'web-mail@5.0.112.4',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36',
        })
        if self.cookie:
            session.headers['cookie'] = self.cookie
            cookie = SimpleCookie()
            cookie.load(self.cookie)
            for name in cookie.keys():
                if name.startswith('AUTH-'):
                    self.uid = name[len('AUTH-'):]
                    session.headers['x-pm-uid'] = self.uid
                    break

    def refresh(self, session: requests.Session, api_url: str) -> bool:
        return False

    def current_token(self) -> str:
        raise RuntimeError('Cookie auth cannot be exported as OAuth Proton token')
