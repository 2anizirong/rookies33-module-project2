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


# Responses API Structured Outputs용 스키마.
# final synthesis 단계에서 JSON 형식 흔들림을 줄이기 위해 사용한다.
REPORT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "status": {"type": "string", "enum": ["completed"]},
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
        "internal_guidance": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "document": {"type": "string"},
                    "topic": {"type": "string"},
                    "guidance": {"type": "string"},
                    "relationship": {
                        "type": "string",
                        "enum": ["direct", "indirect", "general"],
                    },
                    "relevance": {"type": "string"},
                },
                "required": ["document", "topic", "guidance", "relationship", "relevance"],
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
        "status",
        "risk",
        "vulnerability_classification",
        "diagnostic_evidence",
        "related_cves",
        "cve_assessment",
        "real_world_cases",
        "official_guidance",
        "internal_guidance",
        "analysis",
        "recommendations",
    ],
    "additionalProperties": False,
}


def _fallback_report(reason: str) -> dict[str, Any]:
    return {
        "status": "error",
        "risk": {
            "severity": "low",
            "score": 0.0,
            "reason": "최종 AI 분석을 완료하지 못함",
        },
        "vulnerability_classification": {
            "name": "",
            "cwe": "",
            "description": "",
            "attack_chain": [],
        },
        "diagnostic_evidence": [],
        "related_cves": [],
        "cve_assessment": {
            "direct_match_found": False,
            "explanation": "최종 분석 실패로 판단하지 못함",
        },
        "real_world_cases": [],
        "official_guidance": [],
        "internal_guidance": [],
        "analysis": {
            "attack_scenario": "",
            "confirmed_impact": "",
            "potential_impact": "",
            "limitations": "",
        },
        "recommendations": [],
        "error": reason,
    }


def generate(
    evidence: dict[str, Any],
    web_result: dict[str, Any],
    file_result: dict[str, Any],
    model: str = DEFAULT_MODEL,
) -> dict[str, Any]:
    """진단 증거 + Web 조사 + File 조사를 종합한다. 이 단계에서는 검색하지 않는다."""

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return _fallback_report("OPENAI_API_KEY를 찾을 수 없음")

    prompt = f"""
다음 세 자료를 종합하여 최종 Security Intelligence 보고서를 작성하라.

[1. 자동 진단 증거 - 현재 시스템에 대한 최우선 사실]
{json.dumps(evidence, ensure_ascii=False, indent=2)}

[2. Web Search 조사 결과 - 외부 참고정보]
검색 상태: {web_result.get('status')}
{web_result.get('research') or 'Web Search 조사 결과 없음'}

[Web Sources]
{json.dumps(web_result.get('sources', []), ensure_ascii=False, indent=2)}

[3. File Search 조사 결과 - 등록 문서 근거]
검색 상태: {file_result.get('status')}
{file_result.get('research') or 'File Search 조사 결과 없음'}

[File Sources]
{json.dumps(file_result.get('sources', []), ensure_ascii=False, indent=2)}

분석 규칙:
1. 현재 시스템에 대한 사실은 [자동 진단 증거]에 있는 값만 사용한다.
2. Web/File 검색 결과가 자동 진단 증거와 충돌하면 검색 결과를 사실로 승격하지 말고 한계로 적는다.
3. 검색 결과가 실패/미설정이면 해당 자료가 없는 상태로 분석하고, 없는 근거를 만들어내지 않는다.
4. 자체 제작 실습 앱은 특정 공개 제품의 CVE와 1:1 대응하지 않는 한 direct_match_found=false로 한다.
5. 유사 SSRF CVE는 similar_attack_pattern 또는 reference_only로만 분류한다.
6. 현재 Stage 5에서 확인된 permission 이름만 '확인된 영향'에 쓸 수 있다.
7. List/Get 등 조회성 API만 확인된 경우 write/delete/execute 가능성을 확인 사실로 쓰지 않는다.
8. IAM Role 이름, AWS Account ID, ARN, Bucket/Lambda 실제 이름, Credential 값을 추측하거나 생성하지 않는다.
9. IMDSv2는 SSRF 자체 제거가 아니라 metadata 접근/credential 탈취에 대한 방어 심층화로 설명한다.
10. 주요정보통신기반시설 가이드의 Anti-Spoofing/망분리 같은 항목은 SSRF를 직접 다루지 않으면 indirect/general로 둔다.

AI Risk Score 규칙(프로젝트 자체 점수이며 CVSS가 아님):
- SSRF Sink 미확인: 대체로 0.0~2.9
- SSRF Sink 확인, IMDS 접근 미확인: 대체로 3.0~5.9
- IMDS 접근은 확인됐지만 Credential 미노출: 대체로 6.0~7.4
- Temporary Credential 노출 + 해당 Credential로 Cloud API 접근 확인: 대체로 7.5~8.9 (HIGH)
- 9.0 이상/CRITICAL은 민감 데이터의 실제 읽기 또는 write/delete/execute 같은 고영향 권한까지 직접 확인된 경우에만 사용

보고서에서는 반드시 'confirmed_impact'와 'potential_impact'를 구분한다.
현재 진단의 실제 체인을 먼저 설명하고, Web/File Search는 그 사실을 보강하는 자료로만 사용하라.
"""

    try:
        client = OpenAI(api_key=api_key)
        response = client.responses.create(
            model=model,
            reasoning={"effort": "low"},
            instructions=(
                "You are a cloud security intelligence analyst. "
                "Do not perform additional searches. "
                "The supplied diagnostic evidence is the sole source of truth about the assessed target. "
                "Web research is external context and file research is internal guidance only. "
                "Never invent CVEs, incidents, permissions, identifiers, or requirements."
            ),
            input=prompt,
            text={
                "format": {
                    "type": "json_schema",
                    "name": "security_intelligence_report",
                    "strict": True,
                    "schema": REPORT_SCHEMA,
                }
            },
        )

        if response.status == "incomplete":
            reason = (
                getattr(response.incomplete_details, "reason", None)
                if response.incomplete_details
                else None
            )
            return _fallback_report(f"OpenAI 응답 미완료: {reason}")

        text = (response.output_text or "").strip()
        if not text:
            return _fallback_report("최종 AI 분석 응답이 비어 있음")

        parsed = json.loads(text)
        return parsed

    except json.JSONDecodeError:
        return _fallback_report("최종 AI 분석 결과 JSON 파싱 실패")
    except Exception as exc:
        logger.exception("최종 보고서 생성 실패")
        return _fallback_report(f"{type(exc).__name__}: {str(exc)[:300]}")


def build_markdown_report(result: dict[str, Any]) -> str:
    outer_sources = result.get("sources", {}) if isinstance(result, dict) else {}
    report = result.get("report", result) if isinstance(result, dict) else {}

    lines: list[str] = ["# AI Security Intelligence Report", ""]

    risk = report.get("risk", {})
    lines += [
        "## 1. 종합 위험도",
        "",
        f"- Severity: **{str(risk.get('severity', 'unknown')).upper()}**",
        f"- AI Risk Score: **{risk.get('score', 0)} / 10**",
    ]
    if risk.get("reason"):
        lines.append(f"- 판단 근거: {risk['reason']}")
    lines.append("")

    classification = report.get("vulnerability_classification", {})
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
    items = report.get("diagnostic_evidence", [])
    if items:
        for item in items:
            lines.append(f"- **{item.get('evidence', '')}**")
            if item.get("security_meaning"):
                lines.append(f"  - 의미: {item['security_meaning']}")
    else:
        lines.append("- 진단 증거 정리 결과 없음")
    lines.append("")

    lines += ["## 4. 관련 CVE", ""]
    assessment = report.get("cve_assessment", {})
    if assessment:
        lines.append(
            f"- 직접 대응 CVE 확인: {'예' if assessment.get('direct_match_found') else '아니오'}"
        )
        if assessment.get("explanation"):
            lines.append(f"- 설명: {assessment['explanation']}")
        lines.append("")

    cves = report.get("related_cves", [])
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
    cases = report.get("real_world_cases", [])
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
    official = report.get("official_guidance", [])
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

    lines += ["## 7. 내부 보안 가이드 연계", ""]
    internal = report.get("internal_guidance", [])
    if internal:
        for item in internal:
            lines.append(
                f"- **{item.get('document', '-')} / {item.get('topic', '-')}**"
            )
            lines.append(f"  - 관계: {item.get('relationship', '-')}")
            if item.get("guidance"):
                lines.append(f"  - 내용: {item['guidance']}")
            if item.get("relevance"):
                lines.append(f"  - 진단과의 관계: {item['relevance']}")
    else:
        lines.append("- 내부 자료에서 직접 관련 근거를 확인하지 못함")
    lines.append("")

    analysis = report.get("analysis", {})
    lines += ["## 8. 종합 분석", ""]
    if analysis.get("attack_scenario"):
        lines += ["### 공격 시나리오", "", analysis["attack_scenario"], ""]
    if analysis.get("confirmed_impact"):
        lines += ["### 확인된 영향", "", analysis["confirmed_impact"], ""]
    if analysis.get("potential_impact"):
        lines += ["### 잠재 영향", "", analysis["potential_impact"], ""]
    if analysis.get("limitations"):
        lines += ["### 진단 한계", "", analysis["limitations"], ""]

    lines += ["## 9. 대응방안", ""]
    recommendations = report.get("recommendations", [])
    if recommendations:
        for item in recommendations:
            priority = str(item.get("priority", "medium")).upper()
            lines.append(f"- **[{priority}] {item.get('action', '-')}**")
            if item.get("reason"):
                lines.append(f"  - 근거: {item['reason']}")
    else:
        lines.append("- 대응방안 생성 결과 없음")
    lines.append("")

    lines += ["## 10. 검색 출처", ""]
    web_sources = outer_sources.get("web", []) if isinstance(outer_sources, dict) else []
    file_sources = outer_sources.get("files", []) if isinstance(outer_sources, dict) else []

    lines += ["### Web Search", ""]
    if web_sources:
        for source in web_sources:
            lines.append(
                f"- {source.get('title', 'Untitled source')}: {source.get('url', '')}"
            )
    else:
        lines.append("- Web Search 출처 없음")
    lines.append("")

    lines += ["### File Search", ""]
    if file_sources:
        seen_files: set[str] = set()
        for source in file_sources:
            filename = str(source.get("filename", "Untitled document"))
            if filename in seen_files:
                continue
            seen_files.add(filename)
            lines.append(f"- {filename}")
    else:
        lines.append("- File Search 출처 없음")
    lines.append("")

    return "\n".join(lines)


def save_markdown_report(result: dict[str, Any], path: str | Path) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(build_markdown_report(result), encoding="utf-8")
