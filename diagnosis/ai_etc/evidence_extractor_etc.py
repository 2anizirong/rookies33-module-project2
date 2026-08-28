#AAA.json에서 키워드 추출하는 코드 -> ai가 웹서치, 파일서치하기 위해서
"""
scan_result.json에서 SSRF를 제외한 취약점(SQL Injection / Stored XSS / OS Command Injection)
진단 결과만 뽑아서 AI 분석용 안전한 증거로 정규화한다.
 
ai/evidence_extractor.py(SSRF 전용)와 완전히 독립. 서로 import하지 않음.
 
읽는 대상 (main.py가 생성하는 scan_result.json 기준):
{
  "stages": {
    ...(parameter_discovery ~ cloud_impact는 무시, SSRF 쪽 담당)...
    "sqli_diagnosis": [ {endpoint, parameter, tests, result}, ... ],
    "stored_xss": {"injection_points": [...], "summary": {...}},
    "os_command_injection": {"results": [...], "summary": {...}}
  }
}
 
보안 원칙 (SSRF 쪽과 동일한 기준):
- 실제 HTTP 응답 본문(body_snippet, evidence 원문 등)은 그대로 넘기지 않는다.
  페이지에 세션/쿠키/다른 사용자 정보가 우연히 섞여 나올 수 있기 때문.
- endpoint, parameter, technique, vulnerable 여부 같은 "사실"만 넘긴다.
"""
 
from __future__ import annotations
 
from typing import Any
 
 
def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
 
 
def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
 
 
def _is_skipped(value: Any) -> bool:
    """stage가 --base-url 미지정 등으로 건너뛰어졌는지 확인 (main.py의 {"skipped": True, ...} 패턴)."""
    return isinstance(value, dict) and value.get("skipped") is True
 
 
# ── SQL Injection (stage6) ──────────────────────────────────────
 
def _normalize_sqli(raw: Any) -> list[dict[str, Any]]:
    if _is_skipped(raw):
        return []
 
    findings: list[dict[str, Any]] = []
    for item in _as_list(raw):
        if not isinstance(item, dict):
            continue
 
        param = _as_dict(item.get("parameter"))
        techniques_tried = []
        for test in _as_list(item.get("tests")):
            if not isinstance(test, dict):
                continue
            techniques_tried.append({
                "technique": test.get("technique"),
                "vulnerable": test.get("vulnerable"),
            })
 
        findings.append({
            "endpoint": item.get("endpoint"),
            "parameter": {
                "name": param.get("name"),
                "method": param.get("method"),
                "location": param.get("location"),
            },
            "techniques_tried": techniques_tried,
            "result": item.get("result"),
        })
 
    return findings
 
 
# ── Stored XSS (stage7) ─────────────────────────────────────────
 
def _normalize_xss(raw: Any) -> list[dict[str, Any]]:
    raw = _as_dict(raw)
    if _is_skipped(raw):
        return []
 
    findings: list[dict[str, Any]] = []
    for item in _as_list(raw.get("injection_points")):
        if not isinstance(item, dict):
            continue
 
        findings.append({
            "endpoint": item.get("endpoint"),
            "parameter": item.get("parameter"),
            "method": item.get("method"),
            # 실제 페이로드 원문(<script> 등)은 그대로 넘기되, HTML 응답 본문 전체는 넘기지 않음
            "payload_type": item.get("payload"),
            "vulnerable": item.get("vulnerable"),
            "reflected_or_stored": (
                "reflected" if "reflected" in str(item.get("evidence", "")).lower()
                else "stored" if item.get("vulnerable") else None
            ),
        })
 
    return findings
 
 
# ── OS Command Injection (stage8) ───────────────────────────────
 
def _normalize_cmd(raw: Any) -> list[dict[str, Any]]:
    raw = _as_dict(raw)
    if _is_skipped(raw):
        return []
 
    findings: list[dict[str, Any]] = []
    for item in _as_list(raw.get("results")):
        if not isinstance(item, dict):
            continue
 
        findings.append({
            "parameter": item.get("parameter"),
            "method": item.get("method"),
            "location": item.get("location"),
            "result": item.get("result"),
            "detection": item.get("detection"),
        })
 
    return findings
 
 
def build_safe_evidence_etc(scan_result: dict[str, Any]) -> dict[str, Any]:
    stages = scan_result.get("stages", scan_result)
    stages = stages if isinstance(stages, dict) else {}
 
    sqli_findings = _normalize_sqli(stages.get("sqli_diagnosis"))
    xss_findings = _normalize_xss(stages.get("stored_xss"))
    cmd_findings = _normalize_cmd(stages.get("os_command_injection"))
 
    sqli_vuln = sum(1 for f in sqli_findings if f.get("result") == "vulnerable")
    xss_vuln = sum(1 for f in xss_findings if f.get("vulnerable") is True)
    cmd_vuln = sum(1 for f in cmd_findings if f.get("result") == "vulnerable")
 
    return {
        "schema": "diagnosis-safe-evidence-etc-v1",
        "confirmed_summary": {
            "sqli_endpoint_count": len(sqli_findings),
            "sqli_vulnerable_count": sqli_vuln,
            "xss_tested_count": len(xss_findings),
            "xss_vulnerable_count": xss_vuln,
            "cmd_injection_tested_count": len(cmd_findings),
            "cmd_injection_vulnerable_count": cmd_vuln,
        },
        "sqli_diagnosis": {
            "finding_count": len(sqli_findings),
            "findings": sqli_findings,
        },
        "stored_xss": {
            "finding_count": len(xss_findings),
            "findings": xss_findings,
        },
        "os_command_injection": {
            "finding_count": len(cmd_findings),
            "findings": cmd_findings,
        },
    }
 
 
if __name__ == "__main__":
    import json
    import sys
 
    scan_result = json.load(sys.stdin)
    print(json.dumps(build_safe_evidence_etc(scan_result), indent=2, ensure_ascii=False))