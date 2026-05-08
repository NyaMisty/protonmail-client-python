import argparse
import json
import logging
from getpass import getpass

from .auth import API_URL, ProtonIOSLogin, needs_2fa, read_challenge_payload
from .token import build_proton_token

logger = logging.getLogger(__name__)


def input_captcha_callback(details: dict) -> str:
    web_url = details.get('WebUrl')
    token = details.get('HumanVerificationToken')
    methods = details.get('HumanVerificationMethods')
    print('\n需要完成 Proton human verification。')
    print(f'WebUrl: {web_url}')
    print(f'Methods: {methods}')
    print('请在浏览器打开 WebUrl 完成 captcha。')
    print('如果完成后页面/抓包给了新的 token，请粘贴新 token；否则直接回车使用上面的 HumanVerificationToken。')
    user_token = input('Human verification token [回车使用默认]: ').strip()
    return user_token or token or ''


def parse_args():
    parser = argparse.ArgumentParser(description='Login Proton Mail using the captured iOS auth flow.')
    parser.add_argument('username', help='Proton username or email')
    parser.add_argument('--password', help='Proton password; if omitted, prompt securely')
    parser.add_argument('--api-url', default=API_URL)
    parser.add_argument('--timeout', type=int, default=30)
    parser.add_argument('--challenge-dump', help='Optional request.dump from auth/v4/sessions or auth/v4 to reuse the iOS challenge Payload')
    parser.add_argument('--human-verification-token', help='Pre-filled captcha token; if omitted and required, prompt in the same session')
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
        def captcha_callback(_details):
            logger.info('Using pre-filled human verification token')
            return args.human_verification_token
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
    result = {
        'type': 'ios-refresh',
        'uid': auth['UID'],
        'refresh_token': auth.get('RefreshToken'),
        'login_password': password,
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
        token = f"proton:ios:{result['uid']}:{auth['AccessToken']}:{result.get('refresh_token') or ''}:{password}"
    else:
        token = build_proton_token(result.get('refresh_token') or '', password, result['uid'])
    print(token)


if __name__ == '__main__':
    main()
