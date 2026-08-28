"""로그인 자동화 방어(속도 제한) 진단 도구.

승인된 테스트 계정에 동일한 잘못된 비밀번호를 기본 10회 전송하고,
429, Retry-After, 계정/IP 차단, CAPTCHA 같은 방어 신호를 확인한다.
비밀번호, 쿠키, 응답 본문은 결과 JSON에 저장하지 않는다.

사용 예:
    python stage9_login_limit.py http://127.0.0.1:5000/fetch \
        --username rate-limit-test -o stage9_result.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests


# 로그인 성공으로 오해할 수 있는 응답이 나오면 계정 보호를 위해 즉시 중단한다.
SUCCESS_PATTERNS = (
    r"(?i)logout|sign\s*out|my\s*page|dashboard|welcome",
    r"로그아웃|마이페이지|환영합니다",
)

# 제품마다 차단 문구가 다르므로 한국어와 영어의 대표적인 신호만 탐지한다.
BLOCK_PATTERNS = (
    r"(?i)too many (?:requests|attempts)|rate.?limit|try again later",
    r"(?i)account (?:is )?(?:locked|blocked)|temporarily (?:locked|blocked)",
    r"시도 횟수|요청이 너무 많|잠시 후 다시|계정.*(?:잠금|차단)|접근.*차단",
)

CAPTCHA_PATTERNS = (
    r"(?i)captcha|recaptcha|hcaptcha|cf-turnstile",
    r"자동입력 방지|보안문자|로봇이 아닙니다",
)

# CLI에서 --username을 생략했을 때 사용할 비실사용 테스트 계정명이다.
# 실제 admin/guest 계정을 기본값으로 사용하면 계정 잠금 정책을 유발할 수 있다.
DEFAULT_TEST_USERNAME = "stage9-test-user"


def _resolve_login_url(url: str, login_path: str = "/login") -> str:
    """사이트 URL을 검증하고 실제 로그인 POST URL로 변환한다.

    현재 실습 웹은 POST /login, username/password 필드를 사용한다. 사용자가
    /fetch 같은 다른 페이지를 입력해도 동일 origin의 /login을 진단하도록 한다.
    """
    if "://" not in url:
        url = "http://" + url
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("대상은 http:// 또는 https:// 사이트 URL이어야 한다.")

    normalized_login_path = "/" + login_path.strip("/")
    return parsed._replace(
        path=normalized_login_path,
        params="",
        query="",
        fragment="",
    ).geturl()


def _matches_any(body: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, body) for pattern in patterns)


def _response_fingerprint(body: str) -> str:
    """본문을 노출하지 않고 응답 동일성을 비교할 짧은 해시만 만든다."""
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()[:12]


def diagnose_login_limit(
    target_url: str,
    username: str,
    password: str,
    attempts: int = 10,
    interval: float = 0.2,
    timeout: float = 8.0,
    login_path: str = "/login",
    username_field: str = "username",
    password_field: str = "password",
) -> dict[str, Any]:
    """동일한 실패 로그인을 반복하여 자동화 방어 신호를 수집한다."""
    url = _resolve_login_url(target_url, login_path=login_path)
    session = requests.Session()
    session.headers.update({"User-Agent": "Authorized-Login-Rate-Limit-Checker/1.0"})

    results: list[dict[str, Any]] = []
    stopped_reason: str | None = None

    for number in range(1, attempts + 1):
        try:
            # 리다이렉트를 끄면 성공 시 다른 페이지로 이동하는 3xx 응답을 구분할 수 있다.
            response = session.post(
                url,
                data={username_field: username, password_field: password},
                timeout=timeout,
                allow_redirects=False,
            )
            body = response.text[:65536]

            # 일부 취약한 로그인 페이지는 입력값을 오류 메시지에 그대로 반사한다.
            # 계정명에 'rate-limit' 같은 단어가 있어도 방어 신호로 오인하지 않도록 제거한다.
            inspection_body = body.replace(username, "").replace(password, "")

            retry_after = response.headers.get("Retry-After")
            captcha_detected = _matches_any(inspection_body, CAPTCHA_PATTERNS)
            block_detected = response.status_code in {403, 423, 429} or _matches_any(
                inspection_body, BLOCK_PATTERNS
            )

            location = response.headers.get("Location")
            possible_success = (
                response.status_code in {301, 302, 303, 307, 308}
                and bool(location)
                and "login" not in location.lower()
            ) or _matches_any(inspection_body, SUCCESS_PATTERNS)

            results.append({
                "attempt": number,
                "status_code": response.status_code,
                "retry_after": retry_after,
                "captcha_detected": captcha_detected,
                "block_detected": block_detected,
                "possible_login_success": possible_success,
                "response_length": len(response.content),
                "response_fingerprint": _response_fingerprint(inspection_body),
            })

            # 로그인 성공 가능성, CAPTCHA 또는 차단이 확인되면 추가 요청을 보내지 않는다.
            if possible_success:
                stopped_reason = "possible_login_success"
                break
            if response.status_code == 429 or retry_after:
                stopped_reason = "rate_limit_detected"
                break
            if block_detected:
                stopped_reason = "blocking_detected"
                break
            if captcha_detected:
                stopped_reason = "captcha_detected"
                break

        except requests.RequestException as exc:
            results.append({
                "attempt": number,
                "status_code": None,
                "error": type(exc).__name__,
            })
            stopped_reason = "request_error"
            break

        if number < attempts and interval > 0:
            time.sleep(interval)

    rate_limit_detected = any(
        item.get("status_code") == 429 or bool(item.get("retry_after")) for item in results
    )
    blocking_detected = any(item.get("block_detected") for item in results)
    captcha_detected = any(item.get("captcha_detected") for item in results)
    possible_success = any(item.get("possible_login_success") for item in results)
    protection_detected = any(
        (rate_limit_detected, blocking_detected, captcha_detected)
    )

    if possible_success:
        verdict = "inconclusive_possible_login_success"
    elif stopped_reason == "request_error":
        verdict = "inconclusive_request_error"
    elif protection_detected:
        verdict = "protected"
    elif len(results) == attempts:
        # 10회에서 방어가 안 보였다는 의미이며, 비밀번호 추측 성공을 의미하지는 않는다.
        verdict = "no_automation_protection_observed"
    else:
        verdict = "inconclusive"

    timestamp = datetime.now(timezone.utc).isoformat()
    stage_result = {
        "target": url,
        "timestamp": timestamp,
        "configured_attempts": attempts,
        "completed_attempts": len(results),
        "stopped_reason": stopped_reason,
        "credentials_recorded": False,
        "attempts": results,
        "summary": {
            "verdict": verdict,
            "rate_limit_detected": rate_limit_detected,
            "blocking_detected": blocking_detected,
            "captcha_detected": captcha_detected,
            "possible_login_success": possible_success,
        },
    }
    return {
        "meta": {"target": url, "timestamp": timestamp},
        "stages": {"stage9_login_limit": stage_result},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "target",
        help="승인된 사이트 URL(/fetch 등을 입력해도 기본적으로 /login 사용)",
    )
    parser.add_argument(
        "--username",
        default=DEFAULT_TEST_USERNAME,
        help=f"전용 테스트 계정명(기본값: {DEFAULT_TEST_USERNAME})",
    )
    parser.add_argument(
        "--password",
        default="Stage9-Intentionally-Wrong-Password!",
        help="반복할 테스트 비밀번호(기본값은 의도적으로 잘못된 고정값)",
    )
    parser.add_argument("--attempts", type=int, default=10, help="시도 횟수(1~20)")
    parser.add_argument("--interval", type=float, default=0.2, help="요청 사이 대기 초")
    parser.add_argument("--timeout", type=float, default=8.0, help="요청별 타임아웃 초")
    parser.add_argument("--login-path", default="/login", help="로그인 POST 경로")
    parser.add_argument("--username-field", default="username", help="아이디 폼 필드명")
    parser.add_argument("--password-field", default="password", help="비밀번호 폼 필드명")
    parser.add_argument("-o", "--output", help="JSON 결과 저장 경로(미지정 시 stdout)")
    args = parser.parse_args()

    if not 1 <= args.attempts <= 20:
        parser.error("--attempts는 1~20 범위여야 한다.")
    if args.interval < 0:
        parser.error("--interval은 0 이상이어야 한다.")
    if args.timeout <= 0:
        parser.error("--timeout은 0보다 커야 한다.")

    try:
        result = diagnose_login_limit(
            target_url=args.target,
            username=args.username,
            password=args.password,
            attempts=args.attempts,
            interval=args.interval,
            timeout=args.timeout,
            login_path=args.login_path,
            username_field=args.username_field,
            password_field=args.password_field,
        )
    except ValueError as exc:
        parser.error(str(exc))

    output = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(output, encoding="utf-8")
        print(f"[+] 저장: {output_path}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
