from __future__ import annotations

import base64
import logging
import secrets
import time
from http.cookies import SimpleCookie
from urllib.parse import ParseResult, urlparse
from typing import Any, Dict, List, Optional, Tuple, Union

import requests

from .auth import ACCEPT, APP_VERSION, USER_AGENT, redact_api_data
from .crypto import compute_key_password, decrypt_pgp_message
from .message import proton_message_to_rfc822
from .token import ProtonTokenData, parse_proton_token

logger = logging.getLogger(__name__)


class ProtonMailClient:
    LABEL_IDS = {
        'inbox': '0',
    }

    def __init__(self, email_account: str, token: Union[str, ProtonTokenData], server_uri: Optional[str] = None):
        self.email_account = email_account
        self.server_uri: ParseResult = urlparse(server_uri or 'proton://mail.proton.me')
        host = self.server_uri.hostname or 'mail.proton.me'
        if host.endswith('-api.proton.me'):
            self.api_url = f'https://{host}'
        else:
            self.api_url = f'https://{host}/api'
        self.sess = requests.Session()
        self.sess.headers.update({
            'accept': ACCEPT,
            'x-pm-locale': 'zh_CN',
        })
        self.uid = None
        self.access_token = None
        self.refresh_token = None
        self.login_password = None
        self.key_password = None
        self.auth_mode = 'unknown'
        self.total_cache: Dict[str, int] = {}
        self.message_cache: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self.private_keys = None

        token_data = parse_proton_token(token) if isinstance(token, str) else token
        self._configure_token_data(token_data)
        self.user = self.get_proton_user()
        self._load_key_password()

    @classmethod
    def from_access_token(cls, email_account: str, uid: str, access_token: str, login_password: str, server_uri: Optional[str] = None, refresh_token: Optional[str] = None):
        return cls(email_account, ProtonTokenData(
            uid=uid,
            access_token=access_token,
            refresh_token=refresh_token,
            login_password=login_password,
            auth_mode='ios',
        ), server_uri)

    @classmethod
    def from_cookie(cls, email_account: str, cookie_header: str, login_password: str, server_uri: Optional[str] = None, refresh_token: Optional[str] = None):
        return cls(email_account, ProtonTokenData(
            cookie=cookie_header,
            refresh_token=refresh_token,
            login_password=login_password,
            auth_mode='cookie',
        ), server_uri)

    def _configure_token_data(self, token: ProtonTokenData):
        self.uid = token.uid
        self.access_token = token.access_token
        self.refresh_token = token.refresh_token
        self.login_password = token.login_password
        self.auth_mode = token.auth_mode
        if token.cookie:
            self._setup_cookie(token.cookie)
            return
        self._setup_bearer_headers()
        if not self.access_token and self.refresh_token:
            self._refresh_access_token()

    def _setup_bearer_headers(self):
        self.sess.headers.update({
            'x-pm-appversion': APP_VERSION,
            'user-agent': USER_AGENT,
        })
        if self.uid:
            self.sess.headers['x-pm-uid'] = self.uid
        if self.access_token:
            self.sess.headers['authorization'] = f'Bearer {self.access_token}'

    def _setup_cookie(self, cookie_header: str):
        self.sess.headers.update({
            'x-pm-appversion': 'web-mail@5.0.112.4',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36',
            'cookie': cookie_header,
        })
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        for name in cookie.keys():
            if name.startswith('AUTH-'):
                self.uid = name[len('AUTH-'):]
                self.sess.headers['x-pm-uid'] = self.uid
                break

    def _refresh_access_token(self):
        if not self.uid or not self.refresh_token:
            raise RuntimeError('ProtonMail refresh requires uid and refresh_token')
        logger.info('Refreshing ProtonMail access token for uid %s', self.uid)
        old_auth = self.sess.headers.pop('authorization', None)
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
                    response = self.sess.post(f'{self.api_url}/auth/v4/refresh', json=data)
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
                self.sess.headers['authorization'] = old_auth
            response.raise_for_status()
            ret = response.json()
            if ret.get('Code') != 1000:
                raise RuntimeError(f'ProtonMail refresh error: {redact_api_data(ret)}')
            self.uid = ret.get('UID') or self.uid
            self.access_token = ret['AccessToken']
            self.refresh_token = ret.get('RefreshToken') or self.refresh_token
            self._setup_bearer_headers()
            return ret
        except Exception:
            if old_auth:
                self.sess.headers['authorization'] = old_auth
            raise

    def _request(self, method, path, **kwargs):
        url = path if path.startswith('http') else f'{self.api_url}/{path.lstrip("/")}'
        response = self.sess.request(method, url, **kwargs)
        if response.status_code == 401 and self.refresh_token:
            self._refresh_access_token()
            response = self.sess.request(method, url, **kwargs)
        if response.status_code == 401:
            raise RuntimeError(f'ProtonMail unauthorized for {url}. Please refresh the provided token/cookie.')
        response.raise_for_status()
        data = response.json()
        if data.get('Code') != 1000:
            raise RuntimeError(f'ProtonMail API error: {redact_api_data(data)}')
        return data

    def _get_label_id(self, mailbox: str) -> str:
        mailbox = mailbox.lower()
        if mailbox not in self.LABEL_IDS:
            raise ValueError(f'unsupported ProtonMail mailbox: {mailbox}')
        return self.LABEL_IDS[mailbox]

    def get_proton_user(self):
        return self._request('get', 'core/v4/users')['User']

    def _load_key_password(self):
        if not self.login_password:
            raise RuntimeError('ProtonMail login password is required in token for PGP decryption.')

        salts = self._request('get', 'core/v4/keys/salts').get('KeySalts', [])
        key_salt = None
        for key_info in self.user.get('Keys', []):
            key_id = key_info.get('ID')
            if not key_id:
                continue
            for salt in salts:
                if salt.get('ID') == key_id and salt.get('KeySalt'):
                    key_salt = salt['KeySalt']
                    break
            if key_salt is not None:
                break
        if key_salt is None:
            raise RuntimeError('ProtonMail key salt not found for current user key')
        self.key_password = compute_key_password(self.login_password, key_salt)

    def get_mailboxes(self) -> List[str]:
        return ['inbox']

    def get_mail_list(self, mailbox='inbox', page=0, page_size=50):
        label_id = self._get_label_id(mailbox)
        data = self._request('get', 'mail/v4/messages', params={
            'Page': str(page),
            'PageSize': str(page_size),
            'Limit': str(page_size),
            'LabelID[]': label_id,
            'Sort': 'Time',
            'Desc': '1',
        })
        self.total_cache[mailbox] = int(data['Total'])
        return data

    def get_mails_countmap(self, mailboxes: List[str]) -> Dict[str, int]:
        results = {}
        for mailbox in mailboxes:
            data = self.get_mail_list(mailbox=mailbox, page_size=1)
            results[mailbox] = int(data['Total'])
        return results

    def get_mail_by_index(self, index, mailbox='inbox') -> bytes:
        total = self.total_cache.get(mailbox)
        if total is None or index > total:
            total = self.get_mails_countmap([mailbox])[mailbox]
        if index < 1 or index > total:
            raise IndexError(f'ProtonMail message index out of range: {index}/{total}')

        newest_offset = total - index
        page_size = 50
        page = newest_offset // page_size
        item_offset = newest_offset % page_size
        cache_key = (mailbox, page)
        if cache_key not in self.message_cache:
            self.message_cache[cache_key] = self.get_mail_list(mailbox=mailbox, page=page, page_size=page_size)
        messages = self.message_cache[cache_key]['Messages']
        if item_offset >= len(messages):
            raise IndexError(f'ProtonMail page item missing: index={index}, page={page}, offset={item_offset}')
        message = self.get_mail_detail(messages[item_offset]['ID'])
        return self.message_to_rfc822(message)

    def get_mail_detail(self, message_id: str) -> Dict[str, Any]:
        return self._request('get', f'mail/v4/messages/{message_id}')['Message']

    def message_to_rfc822(self, message: Dict[str, Any]) -> bytes:
        body = self.decrypt_body(message)
        return proton_message_to_rfc822(message, body)

    def decrypt_body(self, message: Dict[str, Any]) -> str:
        body = message.get('Body') or ''
        if '-----BEGIN PGP MESSAGE-----' not in body:
            return body
        keys = self.get_private_keys()
        last_error = None
        for key in keys:
            try:
                return decrypt_pgp_message(body, key, self.key_password)
            except Exception as e:
                last_error = e
        raise RuntimeError('Failed to decrypt ProtonMail PGP body') from last_error

    def get_private_keys(self):
        if self.private_keys is not None:
            return self.private_keys
        if not self.key_password:
            raise RuntimeError('ProtonMail login password is required in token for PGP decryption.')
        try:
            import pgpy
        except ImportError as e:
            raise RuntimeError('PGPy is required for ProtonMail PGP decryption; install dependency from Pipfile') from e

        addresses = self._request('get', 'core/v4/addresses', params={'Page': '0', 'PageSize': '50'}).get('Addresses', [])
        key_blobs = []
        for address in addresses:
            if address.get('Email', '').lower() != self.email_account.lower():
                continue
            key_blobs.extend(key_info.get('PrivateKey') for key_info in address.get('Keys', []) if key_info.get('PrivateKey'))
        if not key_blobs:
            key_blobs.extend(key_info.get('PrivateKey') for key_info in self.user.get('Keys', []) if key_info.get('PrivateKey'))

        keys = []
        for key_blob in key_blobs:
            key, _ = pgpy.PGPKey.from_blob(key_blob)
            keys.append(key)
        self.private_keys = keys
        return keys

    def refresh_connection(self):
        self._request('get', 'core/v4/users')

    def cleanup(self):
        self.sess.close()

    def kill(self):
        self.cleanup()


def b64decode_str(value: str) -> str:
    padding = '=' * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode()).decode()
