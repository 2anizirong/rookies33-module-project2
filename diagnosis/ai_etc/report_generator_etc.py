"""
ai_etc 파이프라인의 최종 리포트 생성 단계.
evidence(SQLi/Stored XSS/OS Command Injection/Login Rate Limit) + web_result를 OpenAI에
종합시켜 "vulnerabilities" 배열(취약점 타입별 항목)을 만들고, 항목별로 markdown도 생성한다.

ai/report_generator.py(SSRF 전용, 취약점 1개 기준 스키마)와 완전히 독립.
여기는 애초에 여러 취약점 유형을 한 번에 다룰 수 있게 vulnerabilities 배열 구조로 설계함
— 실제로 login_rate_limit을 나중에 4번째 타입으로 추가할 때도 VULN_TYPES 목록만
늘리면 됐고 스키마 자체는 그대로 재사용됨.

vuln_type을 AI가 자유롭게 짓지 않고 enum으로 고정하는 이유:
analyze_etc.py가 이 값을 파일명(report_etc_{vuln_type}.md)으로 그대로 쓰기 때문.
UI 사이드바 버튼이 파일명을 안정적으로 참조하려면 값이 항상 고정돼 있어야 함.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI


logger = logging.getLogger(__name__)
PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")

# analyze_etc.py가 파일명에 그대로 쓰는 고정 타입 목록
VULN_TYPES = ["sqli", "stored_xss", "os_command_injection", "login_rate_limit"]


# Responses API Structured Outputs용 스키마.
VULN_ITEM_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "vuln_type": {"type": "string", "enum": VULN_TYPES},
        "verdict": {
            "type": "string",
            "enum": ["vulnerable", "safe"],
        },
        "risk": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"],
                },
                "score": {"type": "number", "minimum": 0, "maximum": 10},
                "reason": {"type": "string"},
            },
            "required": ["severity", "score", "reason"],
            "additionalProperties": False,
        },
        "vulnerability_classification": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "cwe": {"type": "string"},
                "description": {"type": "string"},
                "attack_chain": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["name", "cwe", "description", "attack_chain"],
            "additionalProperties": False,
        },
        "diagnostic_evidence": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "evidence": {"type": "string"},
                    "security_meaning": {"type": "string"},
                },
                "required": ["evidence", "security_meaning"],
                "additionalProperties": False,
            },
        },
        "related_cves": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string"},
                    "relationship": {
                        "type": "string",
                        "enum": ["direct", "similar_attack_pattern", "reference_only"],
                    },
                    "title": {"type": "string"},
                    "relevance": {"type": "string"},
                },
                "required": ["cve_id", "relationship", "title", "relevance"],
                "additionalProperties": False,
            },
        },
        "cve_assessment": {
            "type": "object",
            "properties": {
                "direct_match_found": {"type": "boolean"},
                "explanation": {"type": "string"},
            },
            "required": ["direct_match_found", "explanation"],
            "additionalProperties": False,
        },
        "real_world_cases": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "case_name": {"type": "string"},
                    "year": {"type": "string"},
                    "description": {"type": "string"},
                    "similarity": {"type": "string"},
                },
                "required": ["case_name", "year", "description", "similarity"],
                "additionalProperties": False,
            },
        },
        "official_guidance": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "organization": {"type": "string"},
                    "topic": {"type": "string"},
                    "guidance": {"type": "string"},
                    "relevance": {"type": "string"},
                },
                "required": ["organization", "topic", "guidance", "relevance"],
                "additionalProperties": False,
            },
        },
        "analysis": {
            "type": "object",
            "properties": {
                "attack_scenario": {"type": "string"},
                "confirmed_impact": {"type": "string"},
                "potential_impact": {"type": "string"},
                "limitations": {"type": "string"},
            },
            "required": [
                "attack_scenario",
                "confirmed_impact",
                "potential_impact",
                "limitations",
            ],
            "additionalProperties": False,
        },
        "recommendations": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "priority": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                    },
                    "action": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["priority", "action", "reason"],
                "additionalProperties": False,
            },
        },
    },
    "required": [
        "vuln_type",
        "verdict",
        "risk",
        "vulnerability_classification",
        "diagnostic_evidence",
        "related_cves",
        "cve_assessment",
        "real_world_cases",
        "official_guidance",
        "analysis",
        "recommendations",
    ],
    "additionalProperties": False,
}

REPORT_SCHEMA_ETC: dict[str, Any] = {
    "type": "object",
    "properties": {
        "status": {"type": "string", "enum": ["completed"]},
        "vulnerabilities": {
            "type": "array",
            "items": VULN_ITEM_SCHEMA,
        },
    },
    "required": ["status", "vulnerabilities"],
    "additionalProperties": False,
}


def _fallback_report_etc(reason: str) -> dict[str, Any]:
    return {
        "status": "error",
        "vulnerabilities": [],
        "error": reason,
    }


def generate_etc(
    evidence: dict[str, Any],
    web_result: dict[str, Any],
    model: str = DEFAULT_MODEL,
) -> dict[str, Any]:
    """진단 증거(SQLi/Stored XSS/OS Command Injection) + Web 조사를 종합해 vulnerabilities 배열을 만든다."""

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return _fallback_report_etc("OPENAI_API_KEY를 찾을 수 없음")

    summary = evidence.get("confirmed_summary", {})

    prompt = f"""
다음 두 자료를 종합하여 취약점 타입별 Security Intelligence 보고서를 작성하라.

[1. 자동 진단 증거 - 현재 시스템에 대한 최우선 사실]
{json.dumps(evidence, ensure_ascii=False, indent=2)}

[2. Web Search 조사 결과 - 외부 참고정보]
검색 상태: {web_result.get('status')}
{web_result.get('research') or 'Web Search 조사 결과 없음'}

[Web Sources]
{json.dumps(web_result.get('sources', []), ensure_ascii=False, indent=2)}

분석 규칙:
1. 현재 시스템에 대한 사실은 [자동 진단 증거]에 있는 값만 사용한다.
2. Web 검색 결과가 자동 진단 증거와 충돌하면 검색 결과를 사실로 승격하지 말고 한계로 적는다.
3. 검색 결과가 실패/미설정이면 해당 자료가 없는 상태로 분석하고, 없는 근거를 만들어내지 않는다.
4. 자체 제작 실습 앱은 특정 공개 제품의 CVE와 1:1 대응하지 않는 한 direct_match_found=false로 한다.
5. vulnerabilities 배열에는 "실제로 진단이 시도된" 취약점 타입을 전부 포함한다 (취약 여부와 무관).
   sqli_endpoint_count={summary.get('sqli_endpoint_count', 0)}, sqli_vulnerable_count={summary.get('sqli_vulnerable_count', 0)}
   xss_tested_count={summary.get('xss_tested_count', 0)}, xss_vulnerable_count={summary.get('xss_vulnerable_count', 0)}
   cmd_injection_tested_count={summary.get('cmd_injection_tested_count', 0)}, cmd_injection_vulnerable_count={summary.get('cmd_injection_vulnerable_count', 0)}
   login_rate_limit_tested_count={summary.get('login_rate_limit_tested_count', 0)}, login_rate_limit_vulnerable_count={summary.get('login_rate_limit_vulnerable_count', 0)}
   각 타입의 *_count(테스트된 개수)가 0보다 크면 반드시 vulnerabilities 배열에 포함한다.
   테스트된 개수가 0인 타입(애초에 진단을 시도하지 않은 타입)만 배열에서 제외한다.
6. vuln_type별로 verdict를 정확히 판정한다:
   - 해당 타입의 vulnerable_count > 0 이면 verdict="vulnerable"
   - 해당 타입의 vulnerable_count == 0 이면 verdict="safe" (시도했지만 취약점을 발견하지 못함)
7. verdict="safe"인 타입은 다음을 반드시 지킨다:
   - diagnostic_evidence에는 실제로 어떤 파라미터/엔드포인트에 어떤 기법(technique)으로 시도했는지,
     그리고 그 결과가 응답에 어떻게 반영되지 않았는지(= 왜 안전 판정인지)를 [자동 진단 증거]에 있는
     사실 그대로 적는다. 진단 증거에 없는 방어 원리(예: "파라미터화된 쿼리를 쓴다")는 절대 단정하지 마라 —
     자동 진단은 응답 동작만 관찰했을 뿐 서버 소스코드를 확인하지 않았다.
   - analysis.confirmed_impact는 "확인된 영향 없음(진단 시도한 페이로드로는 우회/실행 실패)"로 적는다.
   - analysis.limitations에 "정확한 방어 메커니즘은 소스코드 확인이 필요하며 자동 진단만으로는 특정할 수 없음"을
     반드시 포함한다.
   - recommendations는 "현재 방어 상태 유지 확인용 회귀 테스트", "추가 페이로드/우회 기법으로 정기 재검증" 등
     방어 유지·검증 관점으로 작성한다.
8. vuln_type은 정확히 "sqli", "stored_xss", "os_command_injection", "login_rate_limit" 중 하나만 사용한다
   (다른 이름 금지).
9. 각 vuln_type의 CWE는 SQLi→CWE-89, Stored/Reflected XSS→CWE-79, OS Command Injection→CWE-78,
   Login Rate Limit(무차별 대입 방어 부재)→CWE-307을 기본으로 한다.
10. 인증 우회(auth_bypass)로 확인된 접근 범위를 넘어서는 권한 상승을 추정하지 마라.
11. login_rate_limit 타입은 "비밀번호가 뚫렸다"가 아니라 "무차별 대입을 막는 방어 장치(rate limit/계정
    잠금/CAPTCHA)가 없다"는 사실만 다룬다. 실제 비밀번호 유출이나 계정 탈취가 확인됐다고 서술하지 마라.

Risk Score 규칙(프로젝트 자체 점수이며 CVSS가 아님):
- verdict="safe"인 타입은 항상 severity="low", score는 0.0~1.9 범위로 고정한다
  (취약점이 발견되지 않았으므로 방어 유지 확인 수준의 낮은 점수).
- verdict="vulnerable"인 타입만 아래 기준을 적용한다:
  - SQL Injection: 인증 우회(관리자 등 임의 계정 접근)까지 확인 → 대체로 7.0~8.9(HIGH).
    에러 기반/데이터 노출만 확인(인증 우회 없음) → 대체로 4.0~6.9(MEDIUM).
  - Stored/Reflected XSS: Stored이고 관리자/다른 사용자가 볼 가능성이 있는 위치 → 대체로 6.0~7.9.
    Reflected만 확인 → 대체로 3.0~5.9.
  - OS Command Injection: 실제 명령 실행(연산 결과가 응답에 반영)까지 확인 → 대체로 8.0~9.5(HIGH~CRITICAL,
    서버 전체 장악 가능성 때문). 단순 응답 지연/에러만 확인 → 대체로 5.0~6.9.
  - Login Rate Limit(무차별 대입 방어 부재, verdict="no_automation_protection_observed") → 대체로
    4.0~6.0(MEDIUM). 단독으로는 즉시 계정 탈취로 이어지지 않고 비밀번호 강도/추가 방어에 의존하지만,
    자동화 공격을 막을 장치가 전혀 없다는 것 자체가 실질적 약점이다. 다른 인증 관련 취약점(SQLi 인증
    우회 등)과 함께 확인됐다면 그 조합 위험을 analysis에서 언급하되 Risk Score 자체를 과도하게 올리지 마라.
  - 9.5 이상/CRITICAL 최상단은 실제 파일 시스템 접근, 원격 코드 실행이 직접 확인된 경우에만 사용.

보고서에서는 반드시 'confirmed_impact'와 'potential_impact'를 구분한다.
현재 진단의 실제 결과를 먼저 설명하고, Web Search는 그 사실을 보강하는 자료로만 사용하라.
"""

    try:
        client = OpenAI(api_key=api_key)
        response = client.responses.create(
            model=model,
            reasoning={"effort": "low"},
            instructions=(
                "You are a web application security intelligence analyst covering "
                "SQL Injection, Cross-Site Scripting, OS Command Injection, and "
                "missing login rate limiting / brute-force protection (CWE-307). "
                "Do not perform additional searches. "
                "The supplied diagnostic evidence is the sole source of truth about the assessed target. "
                "Web research is external context only. "
                "Never invent CVEs, incidents, permissions, identifiers, or requirements. "
                "Include a vulnerability type in the output whenever it was actually tested "
                "(its tested/finding count in the evidence summary is greater than zero), "
                "regardless of whether it was found vulnerable. Set verdict='vulnerable' or "
                "verdict='safe' accordingly. For verdict='safe', never assert a specific defense "
                "mechanism (e.g. parameterized queries) unless the diagnostic evidence itself states it — "
                "automated testing only observed response behavior, not server source code."
            ),
            input=prompt,
            text={
                "format": {
                    "type": "json_schema",
                    "name": "security_intelligence_report_etc",
                    "strict": True,
                    "schema": REPORT_SCHEMA_ETC,
                }
            },
        )

        if response.status == "incomplete":
            reason = (
                getattr(response.incomplete_details, "reason", None)
                if response.incomplete_details
                else None
            )
            return _fallback_report_etc(f"OpenAI 응답 미완료: {reason}")

        text = (response.output_text or "").strip()
        if not text:
            return _fallback_report_etc("최종 AI 분석 응답이 비어 있음")

        parsed = json.loads(text)
        return parsed

    except json.JSONDecodeError:
        return _fallback_report_etc("최종 AI 분석 결과 JSON 파싱 실패")
    except Exception as exc:
        logger.exception("최종 보고서 생성(etc) 실패")
        return _fallback_report_etc(f"{type(exc).__name__}: {str(exc)[:300]}")


VULN_TYPE_LABEL = {
    "sqli": "SQL Injection",
    "stored_xss": "Stored / Reflected XSS",
    "os_command_injection": "OS Command Injection",
    "login_rate_limit": "Login Rate Limiting (Brute-force Protection)",
}


def build_markdown_for_vuln(
    vuln: dict[str, Any],
    web_sources: list[dict[str, Any]] | None = None,
) -> str:
    """vulnerabilities 배열의 항목 하나를 받아 그 취약점 전용 markdown 문서를 만든다."""
    web_sources = web_sources or []
    vuln_type = vuln.get("vuln_type", "unknown")
    label = VULN_TYPE_LABEL.get(vuln_type, vuln_type)
    verdict = vuln.get("verdict", "unknown")
    verdict_label = {
        "vulnerable": "🔴 취약점 발견 (VULNERABLE)",
        "safe": "🟢 안전 확인 (SAFE — 우회 시도했으나 발견되지 않음)",
    }.get(verdict, verdict)

    lines: list[str] = [
        f"# AI Security Intelligence Report — {label}",
        "",
        f"**진단 결과: {verdict_label}**",
        "",
    ]

    risk = vuln.get("risk", {})
    lines += [
        "## 1. 위험도",
        "",
        f"- Severity: **{str(risk.get('severity', 'unknown')).upper()}**",
        f"- AI Risk Score: **{risk.get('score', 0)} / 10**",
    ]
    if risk.get("reason"):
        lines.append(f"- 판단 근거: {risk['reason']}")
    lines.append("")

    classification = vuln.get("vulnerability_classification", {})
    lines += ["## 2. 취약점 분류", ""]
    if classification:
        lines.append(f"- 취약점: {classification.get('name', '-')}")
        lines.append(f"- CWE: {classification.get('cwe', '-')}")
        if classification.get("description"):
            lines.append(f"- 설명: {classification['description']}")
        chain = classification.get("attack_chain", [])
        if chain:
            lines += ["", "### 공격 체인", ""]
            lines.extend(f"{i}. {stage}" for i, stage in enumerate(chain, 1))
    else:
        lines.append("- 분류 결과 없음")
    lines.append("")

    lines += ["## 3. 자동 진단 증거", ""]
    items = vuln.get("diagnostic_evidence", [])
    if items:
        for item in items:
            lines.append(f"- **{item.get('evidence', '')}**")
            if item.get("security_meaning"):
                lines.append(f"  - 의미: {item['security_meaning']}")
    else:
        lines.append("- 진단 증거 정리 결과 없음")
    lines.append("")

    lines += ["## 4. 관련 CVE", ""]
    assessment = vuln.get("cve_assessment", {})
    if assessment:
        lines.append(
            f"- 직접 대응 CVE 확인: {'예' if assessment.get('direct_match_found') else '아니오'}"
        )
        if assessment.get("explanation"):
            lines.append(f"- 설명: {assessment['explanation']}")
        lines.append("")

    cves = vuln.get("related_cves", [])
    if cves:
        for cve in cves:
            lines += [f"### {cve.get('cve_id', 'CVE')}", ""]
            lines.append(f"- 관계: {cve.get('relationship', '-')}")
            if cve.get("title"):
                lines.append(f"- 설명: {cve['title']}")
            if cve.get("relevance"):
                lines.append(f"- 현재 진단과의 관계: {cve['relevance']}")
            lines.append("")
    else:
        lines += ["- 관련 CVE 없음 또는 확인되지 않음", ""]

    lines += ["## 5. 실제 침해 / 공개 사례", ""]
    cases = vuln.get("real_world_cases", [])
    if cases:
        for case in cases:
            heading = f"### {case.get('case_name', '사례')}"
            if case.get("year"):
                heading += f" ({case['year']})"
            lines += [heading, ""]
            if case.get("description"):
                lines.append(f"- 설명: {case['description']}")
            if case.get("similarity"):
                lines.append(f"- 유사점: {case['similarity']}")
            lines.append("")
    else:
        lines += ["- 관련 사례 확인되지 않음", ""]

    lines += ["## 6. 공식 보안 권고", ""]
    official = vuln.get("official_guidance", [])
    if official:
        for item in official:
            lines.append(
                f"- **{item.get('organization', '-')} / {item.get('topic', '-')}**"
            )
            if item.get("guidance"):
                lines.append(f"  - 권고: {item['guidance']}")
            if item.get("relevance"):
                lines.append(f"  - 적용 이유: {item['relevance']}")
    else:
        lines.append("- 공식 권고 조사 결과 없음")
    lines.append("")

    analysis = vuln.get("analysis", {})
    lines += ["## 7. 종합 분석", ""]
    if analysis.get("attack_scenario"):
        lines += ["### 공격 시나리오", "", analysis["attack_scenario"], ""]
    if analysis.get("confirmed_impact"):
        lines += ["### 확인된 영향", "", analysis["confirmed_impact"], ""]
    if analysis.get("potential_impact"):
        lines += ["### 잠재 영향", "", analysis["potential_impact"], ""]
    if analysis.get("limitations"):
        lines += ["### 진단 한계", "", analysis["limitations"], ""]

    lines += ["## 8. 대응방안", ""]
    recommendations = vuln.get("recommendations", [])
    if recommendations:
        for item in recommendations:
            priority = str(item.get("priority", "medium")).upper()
            lines.append(f"- **[{priority}] {item.get('action', '-')}**")
            if item.get("reason"):
                lines.append(f"  - 근거: {item['reason']}")
    else:
        lines.append("- 대응방안 생성 결과 없음")
    lines.append("")

    lines += ["## 9. 검색 출처 (Web)", ""]
    if web_sources:
        for source in web_sources:
            lines.append(
                f"- {source.get('title', 'Untitled source')}: {source.get('url', '')}"
            )
    else:
        lines.append("- Web Search 출처 없음")
    lines.append("")

    return "\n".join(lines)


def save_markdown_reports_etc(result: dict[str, Any], output_dir: str | Path) -> list[Path]:
    """
    result(analyze_etc.py가 저장할 ai_report_etc.json과 동일한 구조)의
    vulnerabilities 배열을 순회하며 타입별로 report_etc_{vuln_type}.md 파일을 각각 저장한다.
    반환값: 실제로 저장된 파일 경로 목록.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    web_sources = (result.get("sources", {}) or {}).get("web", [])
    vulnerabilities = result.get("vulnerabilities", []) or []

    written: list[Path] = []
    for vuln in vulnerabilities:
        vuln_type = vuln.get("vuln_type")
        if vuln_type not in VULN_TYPES:
            continue  # 스키마 위반(있어서는 안 되지만) 방어

        path = output_dir / f"report_etc_{vuln_type}.md"
        path.write_text(
            build_markdown_for_vuln(vuln, web_sources=web_sources),
            encoding="utf-8",
        )
        written.append(path)

    return written
