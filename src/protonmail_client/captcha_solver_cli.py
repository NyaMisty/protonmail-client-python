from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Optional
from urllib.parse import parse_qs, urlparse


class CaptchaSolverError(RuntimeError):
    pass


def parse_token_from_web_url(web_url: str) -> str:
    query = parse_qs(urlparse(web_url).query)
    token = query.get('token') or query.get('Token')
    return token[0] if token else ''


def build_human_verification_token(captcha_token: str, candidate: str) -> str:
    if not candidate:
        return ''
    if ':' in candidate:
        return candidate
    return f'{captcha_token}:{candidate}' if captcha_token else candidate


def load_solver(solver_path: Optional[str]):
    if solver_path and solver_path not in sys.path:
        sys.path.insert(0, solver_path)
    try:
        from captcha_solver import protonSolver
    except ImportError as e:
        raise CaptchaSolverError('cannot import captcha_solver.protonSolver; pass --solver-path or install solver dependencies') from e
    return protonSolver


async def solve_token(captcha_token: str, solver_path: Optional[str]) -> str:
    proton_solver = load_solver(solver_path)
    solver = proton_solver()
    try:
        result = await solver.solve_challenge(captcha_token, purpose='login')
    except Exception as e:
        raise CaptchaSolverError(f'solver failed: {e}') from e
    token = build_human_verification_token(captcha_token, result or '')
    if not token:
        raise CaptchaSolverError('solver returned empty token')
    return token


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Solve Proton captcha using a local proton-captcha-solver checkout.')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--token', help='Proton HumanVerificationToken')
    source.add_argument('--web-url', help='Proton verification WebUrl containing token=...')
    parser.add_argument('--solver-path', help='Local path to ahmedmani/proton-captcha-solver repository')
    parser.add_argument('--import-only', action='store_true', help='Only verify solver import and token parsing; do not solve')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    captcha_token = args.token or parse_token_from_web_url(args.web_url)
    if not captcha_token:
        raise SystemExit('missing captcha token')

    try:
        if args.import_only:
            load_solver(args.solver_path)
            print(captcha_token)
            return
        print(asyncio.run(solve_token(captcha_token, args.solver_path)))
    except CaptchaSolverError as e:
        raise SystemExit(str(e)) from e


if __name__ == '__main__':
    main()
