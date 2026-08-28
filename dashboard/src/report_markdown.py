from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any

from dotenv import load_dotenv
from openai import OpenAI

from src.ai_risk_analysis import _build_safe_evidence, PROJECT_ROOT

for _env_path in (PROJECT_ROOT / ".env", PROJECT_ROOT.parent / ".env"):
    if _env_path.exists():
        load_dotenv(_env_path)


REPORT_TEMPLATE_INSTRUCTIONS = """
반드시 아래 Markdown 구조를 그대로 따르되, 내용은 진단 증거에 맞게 채워라.
헤더 문구와 순서는 절대 바꾸지 마라. Markdown 코드 블록으로 감싸지 마라.

# AI Security Intelligence Report

## 1. 종합 위험도

- Target: `<진단 대상 URL>`
- Generated: `<YYYY-MM-DD HH:MM UTC>`
- Severity: **<LOW|MEDIUM|HIGH|CRITICAL>**
- Score: **<0.0~10.0> / 10**
- 판단 근거: <전체 공격 체인에 근거한 서술>

## 2. 취약점 분류

- 취약점: <취약점 이름>
- CWE: <CWE 번호>
- 설명: <서술>

### 공격 체인

1. <단계 1>
2. <단계 2>

## 3. 자동 진단 증거

- **<evidence key>: <핵심 사실>**
  - 의미: <해석>

## 4. 관련 CVE

- 직접 대응 CVE 확인: <예|아니오>
- 설명: <서술>

### <CVE-ID>

- 관계: <관계>
- 설명: <서술>
- 현재 진단과의 관계: <서술>

## 5. 실제 침해 / 공개 사례

### <사례 제목>

- 설명: <서술>
- 유사점: <서술>

## 6. 공식 보안 권고

- **<출처>**
  - 권고: <서술>
  - 적용 이유: <서술>

## 7. 내부 보안 가이드 연계

- **<가이드명>**
  - 관계: <direct|indirect|general>
  - 내용: <서술>
  - 진단과의 관계: <서술>

## 8. 종합 분석

### 공격 시나리오

<서술>

### 잠재 영향

<서술>

### 진단 한계

<서술>

## 9. 대응방안

- **[HIGH|MEDIUM|LOW] <조치 제목>**
  - 근거: <서술>
"""


def _fallback_markdown(scan_result: dict[str, Any], reason: str) -> str:
    """OpenAI 호출이 불가능할 때, 확보된 증거만으로 같은 형식의 리포트를 규칙 기반으로 채운다."""
    target = scan_result.get("target", {}).get("endpoint", "-")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    evidence = _build_safe_evidence(scan_result)

    candidate_count = evidence["ssrf_sink_discovery"]["candidate_count"]
    bypass_vulnerable = any(
        item.get("result") == "vulnerable" for item in evidence["ssrf_bypass_diagnosis"]["results"]
    )
    cred_exposed = any(
        item.get("temporary_credentials_exposed") for item in evidence["imds_credential_exposure"]["assessments"]
    )
    accessible_services = [
        s for s in evidence["cloud_impact_assessment"]["services"] if s.get("accessible")
    ]

    if cred_exposed and accessible_services:
        severity, score = "HIGH", 8.0
    elif bypass_vulnerable:
        severity, score = "MEDIUM", 5.5
    elif candidate_count:
        severity, score = "LOW", 3.0
    else:
        severity, score = "LOW", 1.0

    evidence_lines = [
        f"- **parameter_discovery: 파라미터 {evidence['parameter_discovery']['parameter_count']}개 확인**",
        "  - 의미: 입력 파라미터가 SSRF 입력 벡터로 사용될 수 있음",
        f"- **ssrf_sink_discovery: SSRF 후보 파라미터 {candidate_count}개**",
        "  - 의미: 서버 측 요청이 발생하는 SSRF 싱크 존재 여부",
        f"- **ssrf_bypass_diagnosis: {'IMDS 접근 성공' if bypass_vulnerable else '우회 미확인'}**",
        "  - 의미: 필터 우회를 통한 EC2 IMDS 접근 가능 여부",
        f"- **imds_credential_exposure: 임시 자격증명 노출 {'True' if cred_exposed else 'False'}**",
        "  - 의미: IAM Role 임시 자격증명 탈취 여부",
        f"- **cloud_impact_assessment: 접근 가능 서비스 {len(accessible_services)}건**",
        "  - 의미: 탈취한 자격증명으로 실제 AWS API 접근이 가능한 범위",
    ]

    recommendations = [
        "- **[HIGH] EC2 인스턴스에서 IMDSv2 강제(Require) 및 IMDSv1 비활성화**\n  - 근거: 규칙 기반 폴백 — OpenAI 분석 없이도 IMDS 계열 취약점의 표준 대응",
        "- **[HIGH] 서버 측 URL 목적지 검증(허용목록) 및 내부/링크로컬 대역 접근 차단**\n  - 근거: SSRF 자체를 원천 차단하는 가장 기본적인 조치",
        "- **[MEDIUM] IAM Role 최소 권한 원칙 적용**\n  - 근거: 자격증명이 노출되더라도 피해 범위를 제한",
    ]

    return f"""# AI Security Intelligence Report

## 1. 종합 위험도

- Target: `{target}`
- Generated: `{generated_at}`
- Severity: **{severity}**
- Score: **{score} / 10**
- 판단 근거: [규칙 기반 폴백] {reason}. 확보된 증거만으로 자동 산정한 결과이며, 실제 AI 분석보다 보수적일 수 있습니다.

## 2. 취약점 분류

- 취약점: Server-Side Request Forgery
- CWE: CWE-918
- 설명: 사용자 제공 URL을 서버가 검증 없이 요청하여 내부 네트워크 또는 링크 로컬 리소스(EC2 IMDS 등)에 접근하는 취약점.

### 공격 체인

1. 외부 URL 입력
2. 서버 측 요청 발생
3. EC2 IMDS 접근 시도
4. Temporary Credential 노출 여부 확인
5. AWS API 접근 가능 범위 검증

## 3. 자동 진단 증거

{chr(10).join(evidence_lines)}

## 4. 관련 CVE

- 직접 대응 CVE 확인: 아니오
- 설명: 규칙 기반 폴백 모드에서는 CVE 조회를 수행하지 않습니다. OpenAI API 연동 시 유사 사례를 함께 제공합니다.

## 5. 실제 침해 / 공개 사례

- 규칙 기반 폴백 모드에서는 침해 사례 조회를 수행하지 않습니다.

## 6. 공식 보안 권고

- **AWS / IMDSv2**
  - 권고: EC2 Instance Metadata Service v2 사용 강제, IMDSv1 비활성화.
  - 적용 이유: IMDS 관련 SSRF 대응의 표준 권고.

## 7. 내부 보안 가이드 연계

- 규칙 기반 폴백 모드에서는 내부 가이드 연계를 수행하지 않습니다.

## 8. 종합 분석

### 공격 시나리오

확보된 증거를 바탕으로 한 기본 시나리오만 제공됩니다. 상세 시나리오는 OpenAI 연동 시 생성됩니다.

### 잠재 영향

노출된 자격증명의 권한 범위에 따라 데이터 열람/수정 등으로 확대될 수 있습니다.

### 진단 한계

이 리포트는 {reason}(으)로 인해 규칙 기반으로 생성되었으며, AI 분석 대비 근거가 제한적입니다.

## 9. 대응방안

{chr(10).join(recommendations)}
"""


def generate_markdown_report(
    scan_result: dict[str, Any],
    model: str = "gpt-4o-mini",
) -> dict[str, Any]:
    """
    1~5단계 스캔 결과를 근거로 9개 섹션짜리 AI Security Intelligence Report(Markdown)를 생성한다.

    반환값:
      {"markdown": str, "provider": "openai" | "rule_based_fallback", "fallback_reason": str | None}
    """
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        reason = "OPENAI_API_KEY를 찾을 수 없음"
        return {"markdown": _fallback_markdown(scan_result, reason), "provider": "rule_based_fallback", "fallback_reason": reason}

    evidence = _build_safe_evidence(scan_result)
    target = scan_result.get("target", {}).get("endpoint", "-")
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    prompt = f"""
다음은 승인된 보안 실습 환경에서 수행한 SSRF 및 EC2 IMDS 취약점 자동 진단 결과이다.
당신은 클라우드 보안 분석가이다. 주어진 진단 증거만을 사실로 취급하고,
CVE·실제 침해 사례·공식 보안 권고는 알고 있는 지식과 (가능하면) 웹 검색 결과를 근거로 작성하되,
근거 없는 사실을 지어내지 마라.

Target: {target}
Generated: {generated_at}

{REPORT_TEMPLATE_INSTRUCTIONS}

진단 증거:
{json.dumps(evidence, ensure_ascii=False, indent=2)}
"""

    try:
        client = OpenAI(api_key=api_key)
        response = client.responses.create(
            model=model,
            instructions="You are a cloud security analyst producing a structured Korean Markdown report. Follow the given template exactly.",
            input=prompt,
            tools=[{"type": "web_search_preview"}],
        )

        markdown_text = (response.output_text or "").strip()

        if "## 1. 종합 위험도" not in markdown_text or "## 9. 대응방안" not in markdown_text:
            raise ValueError("모델 응답이 요구된 리포트 형식을 따르지 않음")

        return {"markdown": markdown_text, "provider": "openai", "fallback_reason": None}

    except Exception as e:
        reason = f"AI 리포트 생성 실패: {type(e).__name__}"
        return {"markdown": _fallback_markdown(scan_result, reason), "provider": "rule_based_fallback", "fallback_reason": reason}
