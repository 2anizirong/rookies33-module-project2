"""
report_parser.py
AI 보안 리포트(Markdown 텍스트)를 대시보드가 카드/메트릭으로 렌더할 수 있도록
섹션·메타데이터·목록 단위로 파싱하는 헬퍼 모음.

또한 report.md 파일이 없을 때 ai_report.json의 "report" 필드를 동일한 Markdown으로
되돌리는 어댑터(report_json_to_markdown)를 제공해, 이후 파싱 로직이 md/json 어느
쪽에서 왔든 똑같이 동작하게 한다.
"""

from __future__ import annotations

import re
from typing import Any


_H2_RE = re.compile(r"^##\s+(.+?)\s*$")
_H1_RE = re.compile(r"^#\s+(.+?)\s*$")


def parse_sections(markdown_text: str) -> list[dict[str, str]]:
    """`## ...` 최상위 헤더 단위로 리포트를 섹션 리스트로 분리한다."""
    lines = markdown_text.splitlines()
    sections: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    title = None

    for line in lines:
        h1 = _H1_RE.match(line)
        if h1 and not line.startswith("##"):
            title = h1.group(1).strip()
            continue

        h2 = _H2_RE.match(line)
        if h2 and not line.startswith("###"):
            if current:
                sections.append(current)
            current = {"title": h2.group(1).strip(), "body_lines": []}
            continue

        if current is not None:
            current["body_lines"].append(line)

    if current:
        sections.append(current)

    for section in sections:
        section["body"] = "\n".join(section["body_lines"]).strip()
        del section["body_lines"]

    if title is None:
        return sections
    return [{"__title__": title}, *sections]


def get_report_title(sections: list[dict[str, str]]) -> str:
    """parse_sections 결과에서 리포트 제목(`# ...`)을 찾아 반환한다(없으면 기본 제목)."""
    for section in sections:
        if "__title__" in section:
            return section["__title__"]
    return "AI Security Intelligence Report"


def find_section(sections: list[dict[str, str]], keyword: str) -> dict[str, str] | None:
    """제목에 keyword가 포함된 첫 번째 섹션을 반환한다(없으면 None)."""
    for section in sections:
        if "title" in section and keyword in section["title"]:
            return section
    return None


def extract_meta(markdown_text: str) -> dict[str, Any]:
    """리포트 본문에서 Severity/Score/Target/Generated 값을 정규식으로 뽑아 dict로 반환한다.

    히어로 영역·메트릭 카드에 쓰이며, 값이 없으면 severity="UNKNOWN", score=0.0,
    나머지는 None으로 채운다(파싱 실패해도 렌더가 깨지지 않도록).
    """
    severity_m = re.search(r"Severity:\s*\*\*([A-Za-z]+)\*\*", markdown_text)
    score_m = re.search(r"Score:\s*\*\*([\d.]+)\s*/\s*10\*\*", markdown_text)
    target_m = re.search(r"Target:\s*`([^`]+)`", markdown_text)
    generated_m = re.search(r"Generated:\s*`([^`]+)`", markdown_text)

    score = 0.0
    if score_m:
        try:
            score = float(score_m.group(1))
        except ValueError:
            score = 0.0

    return {
        "severity": (severity_m.group(1).upper() if severity_m else "UNKNOWN"),
        "score": score,
        "target": target_m.group(1) if target_m else None,
        "generated_at": generated_m.group(1) if generated_m else None,
    }


def strip_meta_bullets(body: str) -> str:
    """위험도 섹션 본문에서 이미 히어로/메트릭에 표시한 Target/Generated/Severity/Score 줄을 제거한다."""
    keep = []
    for line in body.splitlines():
        if re.match(r"^-\s*(Target|Generated|Severity|Score):", line):
            continue
        keep.append(line)
    return "\n".join(keep).strip()


def count_top_level_bullets(body: str) -> int:
    """중첩되지 않은(들여쓰기 없는) '- ' 항목 개수를 센다."""
    return len(re.findall(r"^-\s+\S", body, re.MULTILINE))


def count_subheadings(body: str) -> int:
    """'### ' 서브헤더 개수를 센다."""
    return len(re.findall(r"^###\s+\S", body, re.MULTILINE))


def extract_evidence_list(body: str) -> list[str]:
    """'- **텍스트**' 형태의 최상위 증거 항목만 뽑는다(하위 '  - 의미:' 줄은 제외)."""
    return re.findall(r"^-\s+\*\*(.+?)\*\*\s*$", body, re.MULTILINE)


def extract_recommendation_list(body: str) -> list[str]:
    """'- **[LEVEL] 제목**' 형태의 최상위 권고 항목만 뽑는다."""
    items = re.findall(r"^-\s+\*\*(.+?)\*\*\s*$", body, re.MULTILINE)
    if items:
        return items
    # 우선순위 표기가 없는 단순 목록으로 폴백
    return re.findall(r"^-\s+(.+)$", body, re.MULTILINE)


def extract_subsection(body: str, keyword: str) -> str:
    """상위 섹션 본문에서 '### <keyword가 포함된 제목>' 서브섹션 텍스트만 추출한다."""
    lines = body.splitlines()
    collecting = False
    collected: list[str] = []

    for line in lines:
        sub = re.match(r"^###\s+(.+?)\s*$", line)
        if sub:
            if collecting:
                break
            if keyword in sub.group(1):
                collecting = True
            continue
        if collecting:
            collected.append(line)

    return "\n".join(collected).strip()


def extract_numbered_list(text: str) -> list[str]:
    """'1. ...', '2. ...' 형태의 번호 매긴 목록 항목들을 순서대로 뽑는다(공격 체인 등)."""
    return re.findall(r"^\d+\.\s+(.+)$", text, re.MULTILINE)


def report_json_to_markdown(data: dict[str, Any]) -> str:
    """
    diagnosis/ai_report.json의 "report" 필드(완전히 타입화된 JSON 스키마)를
    report.md와 동일한 Markdown 텍스트로 재구성한다.

    이후 파이프라인(parse_sections/extract_meta/extract_evidence_list 등)이
    md/json 어느 쪽에서 왔든 동일하게 동작하도록, JSON을 읽는 즉시 markdown
    문자열로 변환해버리는 어댑터다.

    실제 스키마 (diagnosis/ai/report_generator.py가 만드는 형태):
    {
      "status": "completed",
      "risk": {"severity": "high", "score": 8.2, "reason": "..."},
      "vulnerability_classification": {
          "name": "...", "cwe": "CWE-918", "description": "...",
          "attack_chain": ["단계1", "단계2", ...]
      },
      "diagnostic_evidence": [{"evidence": "...", "security_meaning": "..."}, ...],
      "cve_assessment": {"direct_match_found": bool, "explanation": "..."},
      "related_cves": [{"cve_id": "...", "relationship": "...", "title": "...", "relevance": "..."}, ...],
      "real_world_cases": [{"case_name": "...", "year": "...", "description": "...", "similarity": "..."}, ...],
      "official_guidance": [{"organization": "...", "topic": "...", "guidance": "...", "relevance": "..."}, ...],
      "internal_guidance": [{"document": "...", "topic": "...", "guidance": "...", "relationship": "...", "relevance": "..."}, ...],
      "analysis": {"attack_scenario": "...", "confirmed_impact": "...", "potential_impact": "...", "limitations": "..."},
      "recommendations": [{"priority": "high", "action": "...", "reason": "..."}, ...]
    }

    dashboard.py는 ai_report.json 전체가 아니라 그 안의 "report" 값만 이 함수에 넘긴다.
    """
    risk = data.get("risk", {}) or {}
    vuln = data.get("vulnerability_classification", {}) or {}
    cve_assessment = data.get("cve_assessment", {}) or {}
    analysis = data.get("analysis", {}) or {}

    lines = ["# AI Security Intelligence Report", ""]

    lines += [
        "## 1. 종합 위험도",
        "",
        f"- Severity: **{str(risk.get('severity', 'unknown')).upper()}**",
        f"- Score: **{risk.get('score', 0)} / 10**",
        f"- 판단 근거: {risk.get('reason', '')}",
        "",
    ]

    lines += [
        "## 2. 취약점 분류",
        "",
        f"- 취약점: {vuln.get('name', '-')}",
        f"- CWE: {vuln.get('cwe', '-')}",
        f"- 설명: {vuln.get('description', '')}",
        "",
        "### 공격 체인",
        "",
    ]
    lines += [f"{i}. {step}" for i, step in enumerate(vuln.get("attack_chain") or [], 1)]
    lines.append("")

    lines.append("## 3. 자동 진단 증거")
    lines.append("")
    for item in data.get("diagnostic_evidence") or []:
        lines.append(f"- **{item.get('evidence', '')}**")
        lines.append(f"  - 의미: {item.get('security_meaning', '')}")
    lines.append("")

    lines += [
        "## 4. 관련 CVE",
        "",
        f"- 직접 대응 CVE 확인: {'예' if cve_assessment.get('direct_match_found') else '아니오'}",
        f"- 설명: {cve_assessment.get('explanation', '')}",
        "",
    ]
    for cve in data.get("related_cves") or []:
        lines += [
            f"### {cve.get('cve_id', '-')}",
            "",
            f"- 관계: {cve.get('relationship', '-')}",
            f"- 설명: {cve.get('title', '-')}",
            f"- 현재 진단과의 관계: {cve.get('relevance', '')}",
            "",
        ]

    lines.append("## 5. 실제 침해 / 공개 사례")
    lines.append("")
    for case in data.get("real_world_cases") or []:
        heading = case.get("case_name", "-")
        if case.get("year"):
            heading = f"{heading} ({case['year']})"
        lines += [
            f"### {heading}",
            "",
            f"- 설명: {case.get('description', '')}",
            f"- 유사점: {case.get('similarity', '')}",
            "",
        ]

    lines.append("## 6. 공식 보안 권고")
    lines.append("")
    for g in data.get("official_guidance") or []:
        lines.append(f"- **{g.get('organization', '-')} / {g.get('topic', '-')}**")
        lines.append(f"  - 권고: {g.get('guidance', '')}")
        lines.append(f"  - 적용 이유: {g.get('relevance', '')}")
    lines.append("")

    lines += [
        "## 7. 종합 분석",
        "",
        "### 공격 시나리오",
        "",
        analysis.get("attack_scenario", ""),
        "",
        "### 확인된 영향",
        "",
        analysis.get("confirmed_impact", ""),
        "",
        "### 잠재 영향",
        "",
        analysis.get("potential_impact", ""),
        "",
        "### 진단 한계",
        "",
        analysis.get("limitations", ""),
        "",
    ]

    lines.append("## 8. 대응방안")
    lines.append("")
    for rec in data.get("recommendations") or []:
        priority = str(rec.get("priority", "-")).upper()
        lines.append(f"- **[{priority}] {rec.get('action', '')}**")
        lines.append(f"  - 근거: {rec.get('reason', '')}")
    lines.append("")

    return "\n".join(lines).strip() + "\n"
