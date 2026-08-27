"""
Stage 6: AI Risk Analysis
- 전체 파이프라인 결과를 LLM에 전달
- 위험도/근거/대응방안 JSON 반환

Output 규격:
{
  "risk": {"severity": "high", "score": 8.5},
  "summary": "...",
  "evidence": ["...", "..."],
  "recommendations": ["...", "..."]
}
"""
import json
import os
from typing import Optional


SYSTEM_PROMPT = """You are a cloud security auditor. You will be given the JSON result of an automated SSRF diagnosis pipeline (parameter discovery → sink discovery → bypass diagnosis → IMDS exposure → cloud impact assessment).

Return a STRICT JSON object with this schema (no markdown, no code fences):
{
  "risk": {"severity": "critical|high|medium|low|info", "score": <0.0-10.0>},
  "summary": "<2-3 문장 한국어 요약>",
  "evidence": ["<근거 문장 1>", "<근거 문장 2>", ...],
  "recommendations": ["<대응방안 1>", "<대응방안 2>", ...]
}

Rules:
- Evidence는 반드시 입력 데이터에 근거해서 서술 (없는 사실 지어내지 말 것).
- 자격증명이 노출된 경우 severity는 최소 high.
- 실제 리소스 접근(read_access 이상)이 확인되면 critical 고려.
- SSRF 자체는 성공했지만 IMDS/자격증명은 실패한 경우 medium.
- 아무것도 발견 안 됐으면 info."""


def run_ai_analysis(
    pipeline_result: dict,
    model: str = "gpt-4o-mini",
    api_key: Optional[str] = None,
    offline_fallback: bool = True,
) -> dict:
    """
    pipeline_result: 각 stage 결과를 담은 dict
      {
        "parameter_discovery": {...},
        "sink_discovery": {...},
        "bypass_diagnosis": [...],
        "imds_exposure": {...},          # _raw_credentials 제거된 상태여야 함
        "cloud_impact": {...}
      }
    offline_fallback=True: API 호출 실패시 규칙기반으로 폴백
    """
    safe_input = _sanitize(pipeline_result)

    api_key = api_key or os.environ.get("OPENAI_API_KEY")

    if not api_key:
        if offline_fallback:
            return _rule_based_fallback(safe_input, reason="OPENAI_API_KEY 없음")
        return _error_result("OPENAI_API_KEY 미설정")

    try:
        from openai import OpenAI
    except ImportError:
        if offline_fallback:
            return _rule_based_fallback(safe_input, reason="openai 라이브러리 미설치")
        return _error_result("openai 라이브러리 미설치")

    try:
        client = OpenAI(api_key=api_key)
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(safe_input, ensure_ascii=False)},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )
        text = resp.choices[0].message.content
        return json.loads(text)
    except Exception as e:
        if offline_fallback:
            return _rule_based_fallback(safe_input, reason=f"LLM 호출 실패: {e}")
        return _error_result(str(e))


def _sanitize(pipeline_result: dict) -> dict:
    """LLM에 넘기기 전 자격증명/민감정보 제거"""
    cleaned = json.loads(json.dumps(pipeline_result))  # deep copy
    imds = cleaned.get("imds_exposure", {})
    imds.pop("_raw_credentials", None)
    return cleaned


def _rule_based_fallback(safe_input: dict, reason: str) -> dict:
    """LLM 호출 불가시 파이프라인 결과만 보고 규칙 기반 판정"""
    evidence = []
    recs = []

    bypass = safe_input.get("bypass_diagnosis", [])
    vuln_params = [b for b in bypass if b.get("result") == "vulnerable"]
    if vuln_params:
        for v in vuln_params:
            evidence.append(
                f"SSRF vulnerable parameter '{v['parameter']['name']}' "
                f"via {v.get('bypass_technique')}"
            )

    imds = safe_input.get("imds_exposure", {})
    if imds.get("imds", {}).get("reachable"):
        evidence.append("IMDS reachable via SSRF")
    if imds.get("iam_role", {}).get("detected"):
        evidence.append(f"IAM role detected: {imds['iam_role']['role_name']}")
    if imds.get("temporary_credentials", {}).get("exposed"):
        evidence.append("Temporary credentials exposed")

    cloud = safe_input.get("cloud_impact", {})
    overall = cloud.get("overall_impact", "none")
    for item in cloud.get("cloud_impact", []):
        if item.get("impact") not in ("no_access", None):
            evidence.append(
                f"{item['service']} {item['resource']}: {item['impact']} "
                f"({', '.join(item.get('permissions', []))})"
            )

    # severity 판정
    if overall in ("critical", "high") or imds.get("temporary_credentials", {}).get("exposed"):
        severity, score = "high", 8.0
        recs = [
            "IMDSv2 강제 (HttpTokens=required)",
            "SSRF 목적지 검증 (allowlist 기반)",
            "link-local 및 사설 IP 대역 접근 차단",
            "IAM Role 최소 권한 원칙 적용",
        ]
        if overall == "critical":
            severity, score = "critical", 9.5
    elif vuln_params:
        severity, score = "medium", 5.0
        recs = [
            "SSRF 파라미터에 URL 검증 로직 추가",
            "10진수/16진수/8진수 IP 표현 정규화 후 필터링",
        ]
    else:
        severity, score = "info", 1.0
        recs = ["현재 진단 기준에서는 취약점 미검출"]

    summary = (
        f"[규칙기반 폴백] {reason}. "
        f"SSRF 취약 파라미터 {len(vuln_params)}건, "
        f"자격증명 노출: {imds.get('temporary_credentials', {}).get('exposed', False)}, "
        f"클라우드 영향도: {overall}"
    )

    return {
        "risk": {"severity": severity, "score": score},
        "summary": summary,
        "evidence": evidence or ["진단 결과 근거 없음"],
        "recommendations": recs,
        "_fallback": True,
        "_fallback_reason": reason,
    }


def _error_result(msg: str) -> dict:
    return {
        "risk": {"severity": "info", "score": 0.0},
        "summary": f"AI 분석 실패: {msg}",
        "evidence": [],
        "recommendations": [],
        "error": msg,
    }


if __name__ == "__main__":
    import sys
    pipeline = json.load(sys.stdin)
    print(json.dumps(run_ai_analysis(pipeline), indent=2, ensure_ascii=False))