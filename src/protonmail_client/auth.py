from __future__ import annotations

import base64
import gzip
import json
import logging
import re
import secrets
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

from .crypto import bcrypt_b64_encode, compute_key_password, pmhash

API_URL = 'https://mail-api.proton.me'
APP_VERSION = 'ios-mail@4.20.0.10280'
USER_AGENT = 'ProtonMail/4.20.0 (iOS/17.0; iPhone16,2)'
ACCEPT = 'application/vnd.protonmail.v1+json'

logger = logging.getLogger(__name__)


class ProtonLoginError(RuntimeError):
    pass


def hash_password(password: bytes, salt: bytes, modulus: bytes, version: int) -> bytes:
    if version not in (3, 4):
        raise ProtonLoginError(f'unsupported Proton SRP version: {version}')
    try:
        import bcrypt
    except ImportError as e:
        raise ProtonLoginError('missing dependency: pip install bcrypt') from e
    bcrypt_salt = bcrypt_b64_encode((salt + b'proton')[:16])[:22]
    hashed = bcrypt.hashpw(password, b'$2y$10$' + bcrypt_salt)
    return pmhash(hashed + modulus).digest()


def bytes_to_long(data: bytes) -> int:
    return int.from_bytes(data, 'little')


def long_to_bytes(value: int, size: int = 256) -> bytes:
    return value.to_bytes(size, 'little')


def custom_hash(*args) -> int:
    h = pmhash()
    for value in args:
        h.update(long_to_bytes(value) if isinstance(value, int) else value)
    return bytes_to_long(h.digest())


def generate_srp_proofs(password: str, modulus: bytes, salt: bytes, server_ephemeral: bytes, version: int):
    import os

    n = bytes_to_long(modulus)
    g = 2
    k = custom_hash(g, n)
    a = bytes_to_long(os.urandom(32)) | (1 << 255)
    A = pow(g, a, n)
    B = bytes_to_long(server_ephemeral)
    if B % n == 0:
        raise ProtonLoginError('invalid Proton SRP server challenge')
    u = custom_hash(A, B)
    if u == 0:
        raise ProtonLoginError('invalid Proton SRP scrambling parameter')
    x = bytes_to_long(hash_password(password.encode(), salt, long_to_bytes(n), version))
    v = pow(g, x, n)
    S = pow((B - k * v), (a + u * x), n)
    K = long_to_bytes(S)

    h = pmhash()
    h.update(long_to_bytes(A))
    h.update(long_to_bytes(B))
    h.update(K)
    client_proof = h.digest()

    h = pmhash()
    h.update(long_to_bytes(A))
    h.update(client_proof)
    h.update(K)
    server_proof = h.digest()
    logger.debug('SRP proofs generated: version=%s', version)
    return long_to_bytes(A), client_proof, server_proof, K


def verify_modulus(armored_modulus: str) -> bytes:
    try:
        import gnupg
        from proton.constants import SRP_MODULUS_KEY, SRP_MODULUS_KEY_FINGERPRINT
    except ImportError:
        logger.warning('python-gnupg/proton-client missing; parsing SRP modulus without signature verification')
        return extract_armored_modulus(armored_modulus)

    logger.debug('Verifying signed Proton SRP modulus')
    try:
        gpg = gnupg.GPG()
        gpg.import_keys(SRP_MODULUS_KEY)
        verified = gpg.decrypt(armored_modulus)
    except RuntimeError as e:
        logger.warning('GnuPG binary unavailable (%s); parsing SRP modulus without signature verification', e)
        return extract_armored_modulus(armored_modulus)
    if verified.valid and verified.fingerprint.lower() == SRP_MODULUS_KEY_FINGERPRINT:
        return base64.b64decode(bytes(verified.data).strip())
    raise ProtonLoginError('invalid signed Proton SRP modulus')


def extract_armored_modulus(armored_modulus: str) -> bytes:
    match = re.search(r'\n\n([A-Za-z0-9+/=\n]+)\n-----BEGIN PGP SIGNATURE-----', armored_modulus)
    if not match:
        raise ProtonLoginError('cannot parse Proton SRP modulus; install proton-client and python-gnupg for signature verification')
    return base64.b64decode(''.join(match.group(1).split()))


def redact_api_data(data: Dict[str, Any]) -> Dict[str, Any]:
    sensitive = {'AccessToken', 'RefreshToken', 'Token', 'HumanVerificationToken', 'ServerProof'}
    redacted = {}
    for key, value in data.items():
        if key in sensitive:
            redacted[key] = '<redacted>'
        elif isinstance(value, dict):
            redacted[key] = redact_api_data(value)
        else:
            redacted[key] = value
    return redacted


def read_challenge_payload(path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path:
        return None
    logger.info('Loading iOS challenge payload from %s', path)
    data = Path(path).read_bytes()
    if data[:2] == b'\x1f\x8b':
        data = gzip.decompress(data)
    dump = json.loads(data.decode())
    payload = dump.get('Payload')
    if not isinstance(payload, dict):
        raise ProtonLoginError('challenge dump must contain a Proton iOS Payload object')
    logger.debug('Loaded challenge payload keys: %s', list(payload.keys()))
    return {'Payload': payload}


def default_ios_payload(username: str) -> Dict[str, Any]:
    return {
        'Payload': {
            'mail-ios-v4-challenge-0': {
                'isDarkmodeOn': False,
                'cellulars': [
                    {'mobileNetworkCode': '65535', 'mobileCountryCode': '65535'},
                    {'mobileNetworkCode': '65535', 'mobileCountryCode': '65535'},
                ],
                'v': '2.1.0',
                'keyboards': [
                    'en_US@hw=Automatic;sw=QWERTY',
                    'zh_Hans-Pinyin@sw=Pinyin-Simplified;hw=Automatic',
                    'emoji@sw=Emoji;hw=Automatic',
                    'zh_Hant-Pinyin@sw=Pinyin-Traditional;hw=Automatic',
                    'ja_JP-Romaji@sw=QWERTY-Japanese;hw=Automatic',
                ],
                'timezone': 'Asia/Shanghai',
                'regionCode': 'CN',
                'timezoneOffset': -480,
                'uuid': str(uuid.uuid4()).upper(),
                'preferredContentSize': 'UICTContentSizeCategoryL',
                'isJailbreak': False,
                'deviceName': 2005451,
                'appLang': 'zh',
                'copyUsername': [],
                'keydownUsername': ['', 'Paste'],
                'clickUsername': 0,
                'frame': {'name': 'username'},
                'timeUsername': [1],
                'pasteUsername': [username],
            }
        }
    }


class ProtonIOSLogin:
    def __init__(self, api_url: str = API_URL, timeout: int = 30, challenge_payload: Optional[Dict[str, Any]] = None):
        self.api_url = api_url.rstrip('/')
        self.timeout = timeout
        self.challenge_payload = challenge_payload
        self.sess = requests.Session()
        self.sess.headers.update({
            'Accept': ACCEPT,
            'Content-Type': 'application/json',
            'x-pm-appversion': APP_VERSION,
            'x-pm-locale': 'zh_CN',
            'User-Agent': USER_AGENT,
            'Accept-Language': 'zh-Hans-CN;q=1.0, en-CN;q=0.9, ja-CN;q=0.8, zh-Hant-CN;q=0.7',
        })

    def request(self, method: str, path: str, *, expected=(1000,), **kwargs) -> Dict[str, Any]:
        url = f'{self.api_url}/{path.lstrip("/")}'
        logger.debug('Proton request: %s %s', method.upper(), path)
        response = self.sess.request(method, url, timeout=self.timeout, **kwargs)
        logger.debug('Proton response: %s %s status=%s', method.upper(), path, response.status_code)
        try:
            data = response.json()
        except ValueError:
            response.raise_for_status()
            return {}
        code = data.get('Code')
        if code not in expected:
            logger.error('Proton API error for %s: code=%s error=%s', path, code, data.get('Error'))
            safe_data = redact_api_data(data)
            raise ProtonLoginError(f'Proton API error for {path}: {json.dumps(safe_data, ensure_ascii=False)}')
        logger.debug('Proton response accepted: %s code=%s keys=%s', path, code, list(data.keys()))
        return data

    def init_session(self):
        logger.info('Initializing anonymous Proton iOS session')
        payload = self.challenge_payload or default_ios_payload('')
        data = self.request('post', 'auth/v4/sessions', json=payload)
        self.sess.headers['x-pm-uid'] = data['UID']
        self.sess.headers['Authorization'] = f"Bearer {data['AccessToken']}"
        logger.info('Anonymous session initialized')
        self.request('head', 'core/v4/tests/ping')
        self.request('get', 'core/v4/domains/available', params={'Type': 'login'})
        logger.info('Proton preflight checks completed')

    def auth_info(self, username: str) -> Dict[str, Any]:
        logger.info('Fetching SRP auth info for %s', username)
        return self.request('post', 'core/v4/auth/info', json={'Username': username, 'Intent': 'Auto'})

    def build_auth_payload(self, username: str, password: str) -> Tuple[Dict[str, Any], bytes]:
        info = self.auth_info(username)
        modulus = verify_modulus(info['Modulus'])
        client_ephemeral, client_proof, expected_server_proof, session_key = generate_srp_proofs(
            password=password,
            modulus=modulus,
            salt=base64.b64decode(info['Salt']),
            server_ephemeral=base64.b64decode(info['ServerEphemeral']),
            version=int(info['Version']),
        )
        payload = {
            'Username': username,
            'ClientProof': base64.b64encode(client_proof).decode(),
            'ClientEphemeral': base64.b64encode(client_ephemeral).decode(),
            'SRPSession': info['SRPSession'],
        }
        payload.update(self.challenge_payload or default_ios_payload(username))
        return payload, expected_server_proof

    def submit_auth_payload(self, payload: Dict[str, Any], expected_server_proof: bytes) -> Dict[str, Any]:
        logger.info('Submitting SRP login proof')
        auth = self.request('post', 'auth/v4', json=payload, expected=(1000, 9001))
        if auth.get('Code') == 9001:
            return auth
        if 'ServerProof' in auth:
            server_proof = base64.b64decode(auth['ServerProof'])
            if server_proof != expected_server_proof:
                raise ProtonLoginError('invalid Proton SRP server proof')
            logger.info('SRP server proof verified')
        self.sess.headers['x-pm-uid'] = auth['UID']
        self.sess.headers['Authorization'] = f"Bearer {auth['AccessToken']}"
        logger.info('Proton login succeeded')
        return auth

    def login(self, username: str, password: str, captcha_callback, hv_type: str) -> Dict[str, Any]:
        payload, expected_server_proof = self.build_auth_payload(username, password)
        auth = self.submit_auth_payload(payload, expected_server_proof)
        if auth.get('Code') != 9001:
            return auth

        details = auth.get('Details') or {}
        logger.warning('Proton requires human verification: methods=%s expires_at=%s', details.get('HumanVerificationMethods'), details.get('ExpiresAt'))
        hv_token = captcha_callback(details)
        if not hv_token:
            raise ProtonLoginError('captcha callback returned empty human verification token')
        self.sess.headers['X-PM-Human-Verification-Token-Type'] = hv_type
        self.sess.headers['X-PM-Human-Verification-Token'] = hv_token
        logger.info('Retrying SRP login with human verification token in the same session')
        auth = self.submit_auth_payload(payload, expected_server_proof)
        if auth.get('Code') == 9001:
            raise ProtonLoginError('Proton human verification failed or token was not accepted')
        return auth

    def provide_2fa(self, code: str):
        logger.info('Submitting Proton 2FA code')
        return self.request('post', 'auth/v4/2fa', json={'TwoFactorCode': code})

    def refresh_access_token(self, uid: str, refresh_token: str, access_token: Optional[str] = None) -> Dict[str, Any]:
        logger.info('Testing Proton refresh token exchange')
        old_auth = self.sess.headers.pop('Authorization', None)
        payload = {
            'UID': uid,
            'RefreshToken': refresh_token,
            'ResponseType': 'token',
            'GrantType': 'refresh_token',
            'RedirectURI': 'https://protonmail.ch',
            'State': secrets.token_urlsafe(32),
        }
        if access_token:
            payload['AccessToken'] = access_token
        try:
            refreshed = None
            for attempt in range(3):
                try:
                    refreshed = self.request('post', 'auth/v4/refresh', json=payload)
                    break
                except requests.RequestException:
                    logger.warning('Refresh token exchange network error, retry %d/3', attempt + 1)
                    if attempt == 2:
                        raise
            if refreshed is None:
                raise ProtonLoginError('refresh token exchange failed without response')
        finally:
            if old_auth:
                self.sess.headers['Authorization'] = old_auth
        self.sess.headers['x-pm-uid'] = refreshed.get('UID') or uid
        self.sess.headers['Authorization'] = f"Bearer {refreshed['AccessToken']}"
        logger.info('Refresh token exchange succeeded')
        return refreshed

    def get_key_password(self, password: str, email: Optional[str]):
        logger.info('Fetching Proton key salts')
        salts = self.request('get', 'core/v4/keys/salts').get('KeySalts', [])
        if not salts:
            logger.warning('No Proton key salts returned')
            return None
        wanted_ids = []
        if email:
            logger.info('Fetching Proton keys for %s', email)
            keys = self.request('get', 'core/v4/keys', params={'Email': email}).get('Keys', [])
            wanted_ids.extend(key.get('ID') for key in keys if key.get('ID'))
        if not wanted_ids:
            logger.info('Falling back to user keys for key password derivation')
            user = self.request('get', 'core/v4/users').get('User', {})
            wanted_ids.extend(key.get('ID') for key in user.get('Keys', []) if key.get('ID'))
        for key_id in wanted_ids:
            for salt in salts:
                if salt.get('ID') == key_id and salt.get('KeySalt'):
                    logger.info('Derived Proton key password')
                    return compute_key_password(password, salt['KeySalt'])
        logger.warning('No matching Proton key salt found')
        return None


def needs_2fa(auth: Dict[str, Any]) -> bool:
    two_fa = auth.get('2FA') or auth.get('TwoFactor') or {}
    enabled = two_fa.get('Enabled') if isinstance(two_fa, dict) else two_fa
    return bool(enabled)
