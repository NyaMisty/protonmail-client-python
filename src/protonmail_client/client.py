from __future__ import annotations

import base64
import logging
from urllib.parse import ParseResult, urlparse
from typing import Any, Dict, List, Optional, Tuple, Union

import requests

from .auth import ACCEPT, redact_api_data
from .auth_manager import ProtonAuthManager, ProtonBearerAuthManager, ProtonCookieAuthManager
from .crypto import compute_key_password, decrypt_pgp_message
from .message import proton_message_to_rfc822
from .token import ProtonTokenData, parse_proton_token

logger = logging.getLogger(__name__)


class ProtonMailClient:
    LABEL_IDS = {
        'inbox': '0',
    }

    def __init__(self, email_account: str, token: Union[str, ProtonTokenData, None] = None, server_uri: Optional[str] = None, auth_manager: Optional[ProtonAuthManager] = None):
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
        self.key_password = None
        self.total_cache: Dict[str, int] = {}
        self.message_cache: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self.private_keys = None
        self.user_key_passwords = {}
        self.address_key_passwords = {}

        self.auth_manager = auth_manager or self._create_auth_manager(token)
        self.auth_manager.apply_headers(self.sess)
        if not self.auth_manager.access_token and self.auth_manager.refresh_token:
            self.auth_manager.refresh(self.sess, self.api_url)
        self.user = self.get_proton_user()
        self._load_key_password()

    def _create_auth_manager(self, token: Union[str, ProtonTokenData, None]) -> ProtonAuthManager:
        if token is None:
            raise ValueError('token or auth_manager is required')
        token_data = parse_proton_token(token) if isinstance(token, str) else token
        if token_data.cookie:
            return ProtonCookieAuthManager(token_data)
        return ProtonBearerAuthManager(token_data)

    @classmethod
    def from_access_token(cls, email_account: str, uid: str, access_token: str, login_password: str, server_uri: Optional[str] = None, refresh_token: Optional[str] = None, auth_time: Optional[str] = None):
        return cls(email_account, ProtonTokenData(
            uid=uid,
            access_token=access_token,
            refresh_token=refresh_token,
            auth_time=auth_time,
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
        self.auth_manager = self._create_auth_manager(token)
        self.auth_manager.apply_headers(self.sess)
        if not self.auth_manager.access_token and self.auth_manager.refresh_token:
            self.auth_manager.refresh(self.sess, self.api_url)

    @property
    def uid(self):
        return self.auth_manager.uid

    @property
    def access_token(self):
        return self.auth_manager.access_token

    @property
    def refresh_token(self):
        return self.auth_manager.refresh_token

    @property
    def login_password(self):
        return self.auth_manager.login_password

    @property
    def auth_time(self):
        return self.auth_manager.auth_time

    @property
    def auth_mode(self):
        return getattr(self.auth_manager, 'auth_mode', 'unknown')

    def _setup_bearer_headers(self):
        self.auth_manager.apply_headers(self.sess)

    def _refresh_access_token(self):
        return self.auth_manager.refresh(self.sess, self.api_url)

    def _setup_cookie(self, cookie_header: str):
        token = ProtonTokenData(cookie=cookie_header, auth_mode='cookie')
        self.auth_manager = ProtonCookieAuthManager(token)
        self.auth_manager.apply_headers(self.sess)

    def current_token(self) -> str:
        return self.auth_manager.current_token()

    def _request(self, method, path, **kwargs):
        url = path if path.startswith('http') else f'{self.api_url}/{path.lstrip("/")}'
        response = self.sess.request(method, url, **kwargs)
        if response.status_code == 401 and self.auth_manager.refresh(self.sess, self.api_url):
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
        for key_info in self.user.get('Keys', []):
            key_id = key_info.get('ID')
            if not key_id:
                continue
            for salt in salts:
                if salt.get('ID') == key_id and salt.get('KeySalt'):
                    key_password = compute_key_password(self.login_password, salt['KeySalt'])
                    self.user_key_passwords[key_id] = key_password
                    if not self.key_password:
                        self.key_password = key_password
        if not self.key_password:
            raise RuntimeError('ProtonMail key salt not found for current user key')

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
        key_passwords = self.address_key_passwords
        for key in keys:
            try:
                return decrypt_pgp_message(body, key, key_passwords.get(str(key.fingerprint), self.key_password))
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

        user_keys = []
        for key_info in self.user.get('Keys', []):
            key_blob = key_info.get('PrivateKey')
            key_password = self.user_key_passwords.get(key_info.get('ID')) or self.key_password
            if not key_blob:
                continue
            key, _ = pgpy.PGPKey.from_blob(key_blob)
            user_keys.append((key, key_password))

        addresses = self._request('get', 'core/v4/addresses', params={'Page': '0', 'PageSize': '50'}).get('Addresses', [])
        keys = []
        for address in addresses:
            if address.get('Email', '').lower() != self.email_account.lower():
                continue
            for key_info in address.get('Keys', []):
                key_blob = key_info.get('PrivateKey')
                if not key_blob:
                    continue
                key, _ = pgpy.PGPKey.from_blob(key_blob)
                if key_info.get('Token'):
                    token_value = self._decrypt_address_key_token(user_keys, key_info['Token'])
                    self.address_key_passwords[str(key.fingerprint)] = token_value.decode('utf-8', errors='replace') if isinstance(token_value, bytes) else str(token_value)
                keys.append(key)
        if not keys:
            keys.extend(key for key, _ in user_keys)

        self.private_keys = keys
        return keys

    def _decrypt_address_key_token(self, user_keys, token: str):
        try:
            import pgpy
        except ImportError as e:
            raise RuntimeError('PGPy is required for ProtonMail PGP decryption; install dependency from Pipfile') from e

        token_message = pgpy.PGPMessage.from_blob(token)
        last_error = None
        for user_key, key_password in user_keys:
            try:
                with user_key.unlock(key_password) as unlocked_key:
                    decrypted = unlocked_key.decrypt(token_message)
                return decrypted.message
            except Exception as e:
                last_error = e
        raise RuntimeError('Failed to decrypt ProtonMail address key token') from last_error

    def refresh_connection(self):
        self._request('get', 'core/v4/users')

    def cleanup(self):
        self.sess.close()

    def kill(self):
        self.cleanup()


def b64decode_str(value: str) -> str:
    padding = '=' * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode()).decode()
