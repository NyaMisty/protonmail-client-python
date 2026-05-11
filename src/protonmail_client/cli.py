import argparse
import asyncio
import json
import logging
import time
from getpass import getpass
from pathlib import Path

from .auth import API_URL, ProtonIOSLogin, needs_2fa, read_challenge_payload
from .captcha_solver_cli import parse_token_from_web_url, solve_token
from .token import build_proton_token

logger = logging.getLogger(__name__)


def build_human_verification_token(details: dict, token_suffix: str) -> str:
    token = details.get('HumanVerificationToken')
    if not token:
        return token_suffix
    if not token_suffix:
        return ''
    if ':' in token_suffix:
        return token_suffix
    return f'{token}:{token_suffix}'


def default_captcha_solver_path() -> str:
    return str(Path(__file__).resolve().parents[2] / 'vendor' / 'proton-captcha-solver')


def input_captcha_callback(details: dict) -> str:
    web_url = details.get('WebUrl')
    methods = details.get('HumanVerificationMethods')
    print('\n需要完成 Proton human verification。')
    print(f'WebUrl: {web_url}')
    print(f'Methods: {methods}')
    print('请在浏览器打开 WebUrl 完成 captcha。')
    print('完成后只粘贴验证码结果里冒号(:)后面的部分；程序会自动拼接 HumanVerificationToken。')
    user_token_suffix = input('Human verification token suffix: ').strip()
    return build_human_verification_token(details, user_token_suffix)


def auto_captcha_callback(details: dict) -> str:
    captcha_token = details.get('HumanVerificationToken') or parse_token_from_web_url(details.get('WebUrl') or '')
    if not captcha_token:
        logger.warning('Automatic captcha solver could not find HumanVerificationToken; falling back to manual input')
        return input_captcha_callback(details)
    try:
        return asyncio.run(solve_token(captcha_token, default_captcha_solver_path()))
    except Exception as e:
        logger.warning('Automatic captcha solver failed: %s', e)
        return input_captcha_callback(details)


def parse_args():
    parser = argparse.ArgumentParser(description='Login Proton Mail using the captured iOS auth flow.')
    parser.add_argument('username', help='Proton username or email')
    parser.add_argument('--password', help='Proton password; if omitted, prompt securely')
    parser.add_argument('--api-url', default=API_URL)
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument('--challenge-dump', help='Optional request.dump from auth/v4/sessions or auth/v4 to reuse the iOS challenge Payload')
    parser.add_argument('--human-verification-token', help='Pre-filled captcha token suffix after colon, or a full captcha token')
    parser.add_argument('--auto-captcha', action='store_true', help='Automatically solve Proton captcha using bundled solver')
    parser.add_argument('--human-verification-type', default='captcha')
    parser.add_argument('--two-factor-code', help='TOTP code; if omitted and required, prompt')
    parser.add_argument('--email', help='Email address for key password salt lookup; defaults to username')
    parser.add_argument('--skip-key-password', action='store_true', help='Do not fetch key salts or derive Proton mailbox key password')
    parser.add_argument('--json', action='store_true', help='Print JSON payload for EmailClientProton')
    parser.add_argument('--output-access-token', action='store_true', help='Output legacy proton:ios token including access token')
    parser.add_argument('--no-test-refresh', action='store_true', help='Skip post-login refresh token exchange test')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--log-level', default=None, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help='Override logging level')
    return parser.parse_args()


def setup_logging(args):
    level_name = args.log_level or ('DEBUG' if args.debug else 'INFO')
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s:%(lineno)d - %(message)s',
        level=getattr(logging, level_name),
    )


def main():
    args = parse_args()
    setup_logging(args)
    logger.info('Starting Proton iOS login for %s', args.username)
    password = args.password or getpass('Proton password: ')
    challenge_payload = read_challenge_payload(args.challenge_dump)
    client = ProtonIOSLogin(args.api_url, args.timeout, challenge_payload)
    client.init_session()

    if args.human_verification_token:
        def captcha_callback(details):
            logger.info('Using pre-filled human verification token')
            return build_human_verification_token(details, args.human_verification_token)
    elif args.auto_captcha:
        captcha_callback = auto_captcha_callback
    else:
        captcha_callback = input_captcha_callback

    auth = client.login(args.username, password, captcha_callback, args.human_verification_type)
    if needs_2fa(auth):
        logger.info('Proton account requires 2FA')
        code = args.two_factor_code or input('2FA TOTP code: ').strip()
        client.provide_2fa(code)
    if not args.no_test_refresh:
        refreshed = client.refresh_access_token(auth['UID'], auth['RefreshToken'], auth.get('AccessToken'))
        auth['RefreshToken'] = refreshed.get('RefreshToken') or auth['RefreshToken']
        auth['AccessToken'] = refreshed.get('AccessToken') or auth['AccessToken']
        auth['UID'] = refreshed.get('UID') or auth['UID']
    key_password = None if args.skip_key_password else client.get_key_password(password, args.email or args.username)
    auth_time = str(auth.get('AuthTime') or auth.get('ServerTime') or int(time.time()))
    result = {
        'type': 'ios-refresh',
        'uid': auth['UID'],
        'refresh_token': auth.get('RefreshToken'),
        'auth_time': auth_time,
    }
    if args.output_access_token:
        result['type'] = 'ios'
        result['access_token'] = auth['AccessToken']
    if key_password:
        result['key_password'] = key_password
    if args.json:
        print(json.dumps(result, ensure_ascii=False))
        return
    if args.output_access_token:
        token = f"proton:ios:{result['uid']}:{auth['AccessToken']}:{result.get('refresh_token') or ''}:{key_password or ''}"
    else:
        if not key_password:
            raise RuntimeError('key_password is required for Proton token output')
        token = build_proton_token(result['uid'], auth['AccessToken'], result.get('refresh_token') or '', result['auth_time'], key_password)
    print(token)


if __name__ == '__main__':
    main()
