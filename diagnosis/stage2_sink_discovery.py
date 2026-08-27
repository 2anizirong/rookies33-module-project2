"""
Stage 2: SSRF Sink Discovery
- 각 파라미터에 콜백 URL(+토큰) 주입
- 콜백 서버에 hit이 오면 server_request_detected=true

Input: Stage 1의 output
Output 규격:
{
  "target": "...",
  "ssrf_candidates": [
    {"name": "url", "method": "GET", "location": "query", "server_request_detected": true},
    ...
  ]
}
"""
import requests
import uuid
import time
from typing import Optional


def run_sink_discovery(
    parameter_json: dict,
    callback_server: str,        # 예: "http://127.0.0.1:9000"
    request_timeout: int = 10,
    callback_wait: float = 2.0,
    include_negatives: bool = False,
) -> dict:
    """
    include_negatives=False면 서버 요청 감지된 것만 반환 (준엽 규격),
    True면 감지 안 된 것도 포함 (디버깅용).
    """
    target = parameter_json["target"]
    parameters = parameter_json.get("parameters", [])
    candidates = []

    for param in parameters:
        token = uuid.uuid4().hex
        probe_url = f"{callback_server.rstrip('/')}/probe/{token}"

        # 1) 파라미터에 콜백 URL 주입 → 요청
        reflected = _inject_and_check(target, param, probe_url, token, request_timeout)

        # 2) 콜백 서버 도착 여부 확인
        time.sleep(callback_wait)
        callback_hit = _check_callback_hit(callback_server, token)

        detected = reflected or callback_hit

        candidates.append({
            "name": param["name"],
            "method": param["method"],
            "location": param["location"],
            "server_request_detected": detected,
        })

    if not include_negatives:
        candidates = [c for c in candidates if c["server_request_detected"]]

    return {"target": target, "ssrf_candidates": candidates}


def _inject_and_check(
    target: str, param: dict, probe_url: str, token: str, timeout: int
) -> bool:
    """콜백 URL 주입 후 응답 본문에 토큰 반사됐는지도 검사 (fast-path)"""
    method = param["method"].upper()
    location = param["location"]
    name = param["name"]

    try:
        if location == "query":
            r = requests.get(target, params={name: probe_url}, timeout=timeout)
        elif location == "json":
            r = requests.post(target, json={name: probe_url}, timeout=timeout)
        elif location == "body":
            r = requests.post(target, data={name: probe_url}, timeout=timeout)
        else:
            r = requests.request(method, target, params={name: probe_url}, timeout=timeout)
        return token in r.text
    except requests.RequestException:
        return False


def _check_callback_hit(callback_server: str, token: str, timeout: int = 5) -> bool:
    """콜백 서버 /hits/<token> 엔드포인트로 hit 여부 조회"""
    try:
        r = requests.get(f"{callback_server.rstrip('/')}/hits/{token}", timeout=timeout)
        return r.status_code == 200 and r.json().get("hit", False)
    except requests.RequestException:
        return False


if __name__ == "__main__":
    import json, sys
    # 테스트: Stage 1 output을 stdin으로 받음
    param_json = json.load(sys.stdin)
    cb = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9000"
    print(json.dumps(run_sink_discovery(param_json, cb), indent=2, ensure_ascii=False))
