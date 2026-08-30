"""
dashboard.py
SSRF + SQL Injection + Stored XSS + OS Command Injection + Brute Force 통합 진단 대시보드.

Target URL 하나를 입력하고 '진단 시작'을 누르면 순서대로:
  1) diagnosis/main.py                    (1~8단계 진단, scan_result.json 생성)
  2) diagnosis/ai/analyze.py              (SSRF 전용 AI 리포트 -> report.md / ai_report.json)
  3) diagnosis/ai_etc/analyze_etc.py      (SQLi / Stored XSS / OS Command Injection/ BF AI 리포트
                                            -> report_etc_sqli.md / report_etc_stored_xss.md /
                                               report_etc_os_command_injection.md, ai_report_etc.json 생성)
가 실행된다. 처음에는 SSRF 리포트가 표시되고, 왼쪽 사이드바의 SSRF / SQL Injection /
Stored XSS / OS Command Injection / Brute Force 버튼을 눌러 4개 리포트를 오가며 볼 수 있다.
UI/스타일은 SSRF 전용 대시보드와 동일한 구성을 공유한다.

실행:
    streamlit run dashboard/dashboard.py
"""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime
from html import escape
from typing import Any
from urllib.parse import urlparse

import plotly.graph_objects as go
import streamlit as st

from run_pipeline import VULN_TYPES, run_full_pipeline, split_target
from report_parser import (
    count_subheadings,
    extract_evidence_list,
    extract_meta,
    extract_numbered_list,
    extract_recommendation_list,
    extract_subsection,
    find_section,
    get_report_title,
    parse_sections,
    strip_meta_bullets,
)


# 진단 파이프라인 실행 로직(경로 상수 / STAGE_PROGRESS / split_target / run_full_pipeline)은 분리.
# 여기서는 파이프라인 결과를 렌더링하는 데만 집중한다.
TABS = ["ssrf", *VULN_TYPES]
TAB_LABELS = {
    "ssrf": "SSRF · Cloud Impact",
    "sqli": "SQL Injection",
    "stored_xss": "Stored / Reflected XSS",
    "os_command_injection": "OS Command Injection",
    "login_rate_limit": "Login Rate Limiting",
}

# diagnosis/main.py가 생성하는 scan_result.json을 SSRF 대시보드가 기대하는 top-level 스키마로 변환
# 중첩된 구조 -> 평평한 구조로 변환
def normalize_scan_result(raw: dict[str, Any]) -> dict[str, Any]:
    stages = raw.get("stages", {}) or {}
    meta_block = raw.get("meta", {}) or {}
    imds_exposure = stages.get("imds_exposure") or {}
    raw_cloud = stages.get("cloud_impact") or {}
    normalized_impacts = []
    for item in raw_cloud.get("cloud_impact", []) or []:
        permissions = item.get("permissions") or []
        normalized_impacts.append(
            {
                **item,
                "accessible": True,
                "action": item.get("resource", "-"),
                "assets": permissions,
                "asset_count": len(permissions),
            }
        )

    return {
        "target": {"endpoint": meta_block.get("target", "-")},
        "timestamp": meta_block.get("timestamp"),
        "parameter_discovery": stages.get("parameter_discovery", {}) or {},
        "ssrf_sink_discovery": stages.get("sink_discovery", {}) or {},
        "ssrf_bypass_diagnosis": {"bypass_results": stages.get("bypass_diagnosis", []) or []},
        "imds_credential_exposure": {
            "assessments": [imds_exposure] if imds_exposure else [],
        },
        "cloud_impact_assessment": {
            "principal": raw_cloud.get("principal", {}) or {},
            "cloud_impact": normalized_impacts,
            "overall_impact": raw_cloud.get("overall_impact", "unknown"),
            "region": raw_cloud.get("region", "-"),
        },
    }


SEVERITY_COLORS = {
    "critical": "#ff3b5c",
    "high": "#ff6b45",
    "medium": "#ffb020",
    "low": "#20c997",
    "unknown": "#58a6ff",
}

SQLI_TECHNIQUE_LABELS = {
    "auth_bypass": "인증 우회",
    "error_based": "에러 기반",
    "boolean_based": "불리언 기반",
    "boolean_based_search": "불리언 기반(검색)",
}


st.set_page_config(
    page_title="Vuln Sentinel · SSRF/SQLi/XSS/OS-CMD/Brute Force 진단 대시보드",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Noto+Sans+KR:wght@400;500;600;700&display=swap');

:root { --ink:#e8edf6; --muted:#8b97aa; --panel:#111722; --line:#252f40; --cyan:#4de2c5; --orange:#ff6b45; }
.stApp { background: radial-gradient(circle at 85% -10%, #162c3b 0%, #0a0e15 34%, #080b11 70%); color:var(--ink); }
html, body, [class*="css"] { font-family:'Noto Sans KR',sans-serif; }
[data-testid="stSidebar"] { background:#0c1119; border-right:1px solid #1f2938; }
[data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p { color:#aeb8c8; }
[data-testid="stHeader"] { background:transparent; }
.block-container { padding:2rem 2.6rem 4rem; max-width:1500px; }

.brand { font-family:'IBM Plex Mono'; font-size:.78rem; letter-spacing:.17em; color:#4de2c5; margin-bottom:.4rem; }
.hero-title { font-size:2.15rem; font-weight:700; letter-spacing:-.045em; margin:0; color:#f7f9fc; }
.hero-sub { color:#8793a6; margin-top:.55rem; font-size:.94rem; }
.status-pill { display:inline-flex; align-items:center; gap:.5rem; padding:.45rem .72rem; border-radius:999px; background:rgba(255,107,69,.1); border:1px solid rgba(255,107,69,.28); color:#ff8a6c; font-family:'IBM Plex Mono'; font-size:.72rem; letter-spacing:.07em; }
.status-pill.ok { background:rgba(77,226,197,.1); border-color:rgba(77,226,197,.28); color:#4de2c5; }
.pulse { width:7px; height:7px; background:#ff6b45; border-radius:50%; box-shadow:0 0 0 4px rgba(255,107,69,.12); }
.status-pill.ok .pulse { background:#4de2c5; box-shadow:0 0 0 4px rgba(77,226,197,.12); }

.metric-card { background:linear-gradient(145deg,rgba(20,28,41,.96),rgba(13,18,27,.96)); border:1px solid #242e3d; border-radius:14px; padding:1.05rem 1.15rem; min-height:118px; box-shadow:0 12px 35px rgba(0,0,0,.16); }
.metric-label { color:#78869a; font-size:.72rem; letter-spacing:.08em; text-transform:uppercase; margin-bottom:.65rem; }
.metric-value { color:#f0f4fa; font-family:'IBM Plex Mono'; font-size:1.65rem; font-weight:600; line-height:1.05; }
.metric-foot { color:#6f7d91; font-size:.72rem; margin-top:.65rem; }
.accent-high { color:#ff6b45; }
.accent-green { color:#4de2c5; }

.section-kicker { font-family:'IBM Plex Mono'; font-size:.68rem; color:#4de2c5; letter-spacing:.16em; margin:2rem 0 .35rem; }
.section-title { font-size:1.12rem; font-weight:650; margin:0 0 1rem; }
.panel { background:rgba(15,21,31,.9); border:1px solid #222c3b; border-radius:14px; padding:1.15rem; }
.flow { display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:.55rem; align-items:stretch; }
.flow-node { position:relative; padding:.9rem .75rem; background:#111925; border:1px solid #283447; border-radius:11px; min-height:70px; }
.flow-node:not(:last-child):after { content:'›'; position:absolute; right:-.52rem; top:32%; color:#53627a; z-index:3; font-size:1.25rem; }
.flow-num { font-family:'IBM Plex Mono'; color:#4de2c5; font-size:.65rem; }
.flow-name { font-weight:600; font-size:.82rem; margin:.35rem 0; color:#e8edf5; }
/* 현재 미사용 (예전 flow 노드 디자인 잔재) */
/* .flow-state { font-size:.7rem; color:#8b98aa; } */
/* .flow-alert { border-color:rgba(255,107,69,.42); background:linear-gradient(145deg,#1b1a20,#151820); } */

.test-row { display:grid; grid-template-columns:1.25fr .8fr .8fr 1fr; gap:.6rem; align-items:center; padding:.73rem .85rem; border-bottom:1px solid #222b39; font-size:.79rem; }
.test-row:last-child { border-bottom:0; }
.test-head { color:#718095; font-size:.67rem; text-transform:uppercase; letter-spacing:.08em; }
.mono { font-family:'IBM Plex Mono'; }
.badge { display:inline-block; border-radius:6px; padding:.25rem .48rem; font-size:.66rem; font-weight:600; }
.badge-ok { color:#53e2c6; background:rgba(77,226,197,.1); border:1px solid rgba(77,226,197,.24); }
.badge-bad { color:#ff8d71; background:rgba(255,107,69,.1); border:1px solid rgba(255,107,69,.24); }

.impact-card { padding:.9rem; border:1px solid #263143; border-radius:11px; background:#101722; margin-bottom:.65rem; }
.impact-top { display:flex; justify-content:space-between; gap:1rem; }
.service { font-family:'IBM Plex Mono'; color:#f0f4fa; font-weight:600; }
.resource { color:#7f8ca0; font-size:.72rem; margin:.25rem 0 .55rem; }
.perm { display:inline-block; padding:.18rem .42rem; margin:.12rem; border-radius:5px; background:#172335; color:#9fb3cc; font:500 .64rem 'IBM Plex Mono'; }
.evidence { display:flex; gap:.75rem; padding:.65rem 0; border-bottom:1px solid #212a37; color:#aeb9c8; font-size:.78rem; }
.evidence:last-child { border:0; }
.evidence-mark { color:#4de2c5; font-family:'IBM Plex Mono'; }
.recommend { display:flex; gap:.7rem; padding:.72rem .8rem; margin-bottom:.5rem; background:#101722; border-left:2px solid #4de2c5; border-radius:0 8px 8px 0; color:#b8c2d1; font-size:.78rem; }
.summary-box { padding:1rem 1.1rem; background:rgba(255,107,69,.07); border:1px solid rgba(255,107,69,.25); border-radius:11px; color:#d6dce6; line-height:1.65; font-size:.82rem; }
.footer-note { color:#566377; font:400 .68rem 'IBM Plex Mono'; text-align:right; margin-top:2rem; }
/* 현재 미사용 */
/* .intro-panel { padding:1.4rem 1.5rem; } */
div[data-testid="stDownloadButton"] button { width:100%; background:#172236; color:#dbe5f2; border:1px solid #2b3a50; }
div[data-testid="stDownloadButton"] button:hover { border-color:#4de2c5; color:#4de2c5; }
@media(max-width:900px){ .flow-node:not(:last-child):after{display:none;} .block-container{padding:1.2rem;} }
</style>
""",
    unsafe_allow_html=True,
)

# 값을 문자열로 바꿈, 문자열 안의 HTML 특수문자를 일반 글자로 바꿈
def e(value: Any) -> str:
    return escape(str(value))

# 진단 실행 중 쌓인 로그 리스트를 실시간 로그 박스에 출력.
# 들여쓰기 보존하여 가독성 높임. 세로 스크롤 구현하여 전체를 볼 수 있게 디자인
def render_logs(box: Any, logs: list[str]) -> None:
    with box.container(height=340):
        st.code("\n".join(logs), language="text", wrap_lines=True)

# ISO 형식 시각 문자열을 읽기 좋은 형태로 변환
# ex) 2026-08-29T12:34:56Z -> 2026.08.30  12:34 UTC
def format_time(raw: str) -> str:
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).strftime("%Y.%m.%d  %H:%M UTC")
    except (ValueError, AttributeError, TypeError):
        return raw or "-"

# 사용자가 입력한 Target URL(진단 대상)이 유효한지 검사
# 검사 후,  (성공 여부, 에러메세지) 튜플을 반환
def validate_target(value: str) -> tuple[bool, str]:
    value = value.strip()

    # 빈 값 여부 확인
    if not value:
        return False, "Target URL을 입력하세요."
    
    # URL 파싱 가능 여부 확인
    try:
        parsed = urlparse(value)
    except Exception:
        return False, "올바른 URL 형식이 아닙니다."

    # HTTP/HTTPS 스킴인지 검사
    if parsed.scheme not in {"http", "https"}:
        return False, "http:// 또는 https:// 로 시작하는 URL을 입력하세요."

    # 호스트(도메인/IP) 포함되었는지 검사
    if not parsed.hostname:
        return False, "호스트가 포함된 URL을 입력하세요."

    # IMDS 주소를 실제로 넣지 않았는지 검사
    if parsed.hostname == "169.254.169.254":
        return False, "Target에는 IMDS 주소가 아니라 진단할 웹 애플리케이션 루트 URL을 입력하세요."

    return True, ""

# 민감한 문자열 마스킹 (일부)
def mask_identifier(value: Any, visible: int = 4) -> Any:
    if not isinstance(value, str) or len(value) <= visible:
        return value
    return value[:visible] + "****REDACTED"

# 진단결과 JSON 파일을 다운로드용으로 내보내기 전, AWS 신원 정보를 마스킹하는 함수
# 대시보드 좌측 사이드바에서 JSON 다운로드 버튼에서 사용
def sanitize_raw_scan_result(raw: dict[str, Any]) -> dict[str, Any]:
    """scan_result.json 다운로드용 — cloud_impact.principal(AWS 계정/ARN 등)만 마스킹한다."""
    safe = copy.deepcopy(raw)
    stages = safe.get("stages")
    principal = stages.get("cloud_impact", {}).get("principal") if isinstance(stages, dict) else None
    if isinstance(principal, dict):
        if principal.get("account"):
            principal["account"] = mask_identifier(principal["account"], 3)
        if principal.get("arn"):
            principal["arn"] = "REDACTED"
        if principal.get("user_id"):
            principal["user_id"] = "REDACTED"
    return safe

# 위험도 점수 반원형 게이지 차트 (종합 위험도 게이지 차트 디자인)
def risk_gauge(score: float, color: str):
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"font": {"size": 34, "color": "#f0f4fa", "family": "IBM Plex Mono"}, "suffix": "/10"},
            gauge={
                "axis": {"range": [0, 10], "tickwidth": 0, "tickfont": {"color": "#657287", "size": 10}},
                "bar": {"color": color, "thickness": 0.28},
                "bgcolor": "#151d29",
                "borderwidth": 0,
                "steps": [
                    {"range": [0, 3], "color": "#15231f"},
                    {"range": [3, 6], "color": "#282318"},
                    {"range": [6, 8], "color": "#2b1d18"},
                    {"range": [8, 10], "color": "#2a171d"},
                ],
            },
        )
    )
    fig.update_layout(height=210, margin=dict(l=22, r=22, t=28, b=10), paper_bgcolor="rgba(0,0,0,0)", font={"color": "#8390a3"})
    return fig

# report_etc_*.md 상단의 '**진단 결과: ...**' 배지 줄을 읽어 (표시 텍스트, 취약 여부)를 반환
def extract_verdict(markdown_text: str) -> tuple[str, bool]:
    m = re.search(r"\*\*진단 결과:\s*(.+?)\*\*", markdown_text)
    label = m.group(1).strip() if m else "결과 미상"
    is_vulnerable = "VULNERABLE" in label.upper()
    return label, is_vulnerable

# SQL Injection 진단 결과(stages.sqli_diagnosis, 리스트)를 표 행으로 변환
def sqli_rows(stages: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    items = stages.get("sqli_diagnosis")
    rows: list[tuple[str, str, str, str]] = []
    if not isinstance(items, list):
        return rows
    for item in items:
        if not isinstance(item, dict):
            continue
        param = item.get("parameter") or {}
        techniques = ", ".join(
            SQLI_TECHNIQUE_LABELS.get(t.get("technique"), str(t.get("technique")))
            for t in (item.get("tests") or []) if isinstance(t, dict)
        ) or "-"
        rows.append((
            str(item.get("endpoint", "-")),
            f"{param.get('name', '-')} · {param.get('method', '-')}/{param.get('location', '-')}",
            techniques,
            str(item.get("result", "unknown")),
        ))
    return rows

# Stored/Reflected XSS 결과(stages.stored_xss.injection_points)를 표 행으로 변환
def xss_rows(stages: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    block = stages.get("stored_xss")
    rows: list[tuple[str, str, str, str]] = []
    if not isinstance(block, dict):
        return rows
    for item in block.get("injection_points") or []:
        if not isinstance(item, dict):
            continue
        rows.append((
            str(item.get("endpoint", "-")),
            f"{item.get('parameter', '-')} · {item.get('method', '-')}",
            str(item.get("payload", "-")),
            "vulnerable" if item.get("vulnerable") else "safe",
        ))
    return rows

# OS Command Injection 결과(stages.os_command_injection.results)를 표 행으로 변환
# parameter / method · location / detection (탐지 방식) / result
def cmd_rows(stages: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    block = stages.get("os_command_injection")
    rows: list[tuple[str, str, str, str]] = []
    if not isinstance(block, dict):
        return rows
    for item in block.get("results") or []:
        if not isinstance(item, dict):
            continue
        rows.append((
            str(item.get("parameter", "-")),
            f"{item.get('method', '-')} · {item.get('location', '-')}",
            str(item.get("detection") or "-"),
            str(item.get("result", "unknown")),
        ))
    return rows

# 로그인 무차별 대입 방어(login_rate_limit) 점검 결과를 표로 변환
# Rate limit 감지 / 차단 감지 / CAPTCHA 감지 / 완료 시도 
def login_limit_rows(stages: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    block = stages.get("login_rate_limit")
    if not isinstance(block, dict):
        return []
    if block.get("skipped"):
        return []
    summary = block.get("summary") or {}

    def yn(v: Any) -> str:
        return "예" if v else "아니오"

    return [
        ("Rate limit 감지", yn(summary.get("rate_limit_detected")), "연속 로그인 시도 제한 장치",
         "감지" if summary.get("rate_limit_detected") else "미감지"),
        ("차단(blocking) 감지", yn(summary.get("blocking_detected")), "IP/계정 차단 장치",
         "감지" if summary.get("blocking_detected") else "미감지"),
        ("CAPTCHA 감지", yn(summary.get("captcha_detected")), "자동화 방지 장치",
         "감지" if summary.get("captcha_detected") else "미감지"),
        ("완료 시도", f"{block.get('completed_attempts', '-')}/{block.get('configured_attempts', '-')}",
         "무차별 대입 시뮬레이션(비파괴)", str(block.get("stopped_reason") or "-")),
    ]

# 취약점 종류 → (표 헤더 목록, 행 변환 함수) 를 연결하는 매핑 테이블
DETAIL_ROWS_FN: dict[str, tuple[list[str], Any]] = {
    "sqli": (["ENDPOINT", "PARAMETER", "TECHNIQUE", "RESULT"], sqli_rows),
    "stored_xss": (["ENDPOINT", "PARAMETER", "PAYLOAD", "RESULT"], xss_rows),
    "os_command_injection": (["PARAMETER", "METHOD / LOCATION", "DETECTION", "RESULT"], cmd_rows),
    "login_rate_limit": (["점검 항목", "관측값", "비고", "결과"], login_limit_rows),
}

# 앞서 생성한 행 리스트를 실제 HTML 표로 그려주는 기능
# SSRF 제외한 '자동 진단 상세'표
def render_detail_grid(headers: list[str], rows: list[tuple[str, str, str, str]]) -> None:
    head_html = "".join(f"<div class='test-head'>{e(h)}</div>" for h in headers)
    body_html = []
    for c1, c2, c3, result in rows:
        normalized = str(result).lower()
        vulnerable = normalized in {"vulnerable", "true"}
        safe = normalized in {"safe", "false"}
        badge_cls = "badge-bad" if vulnerable else "badge-ok"
        badge_txt = "VULNERABLE" if vulnerable else ("SAFE" if safe else str(result).upper())
        body_html.append(
            "<div class='test-row'>"
            f"<div>{e(c1)}</div>"
            f"<div class='mono'>{e(c2)}</div>"
            f"<div class='mono'>{e(c3)}</div>"
            f"<div><span class='badge {badge_cls}'>{e(badge_txt)}</span></div>"
            "</div>"
        )
    st.markdown(
        "<div class='panel' style='padding:0'>"
        f"<div class='test-row'>{head_html}</div>"
        f"{''.join(body_html)}"
        "</div>",
        unsafe_allow_html=True,
    )

# SSRF 대시보드 전체를 그리는 메인 함수
# md파일과 json파일로 데이터 준비 -> 화면 렌더링
def render_ssrf_tab(result: dict[str, Any]) -> None:
    markdown_text = result["ssrf"]["markdown"] or ""
    raw = result.get("raw", {}) or {}
    json_result = normalize_scan_result(raw)

    sections = parse_sections(markdown_text)
    meta = extract_meta(markdown_text)
    report_title = get_report_title(sections)

    severity = meta["severity"].lower()
    score = meta["score"]
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["unknown"])

    target_endpoint = meta["target"] or json_result.get("target", {}).get("endpoint", "-")
    generated_at = meta["generated_at"] or format_time(result.get("_dashboard_timestamp", ""))

    section_risk = find_section(sections, "종합 위험도")
    section_vuln = find_section(sections, "취약점 분류")
    section_evidence = find_section(sections, "자동 진단 증거")
    section_cve = find_section(sections, "관련 CVE")
    section_breach = find_section(sections, "실제 침해")
    section_official = find_section(sections, "공식 보안 권고")
    section_analysis = find_section(sections, "종합 분석")
    section_recs = find_section(sections, "대응방안")

    evidence_list = extract_evidence_list(section_evidence["body"]) if section_evidence else []
    recommendation_list = extract_recommendation_list(section_recs["body"]) if section_recs else []
    cve_count = count_subheadings(section_cve["body"]) if section_cve else 0

    attack_chain_text = extract_subsection(section_vuln["body"], "공격 체인") if section_vuln else ""
    attack_chain_steps = extract_numbered_list(attack_chain_text)

    reasoning = ""
    if section_risk:
        m = re.search(r"판단 근거:\s*(.+)", section_risk["body"])
        reasoning = m.group(1).strip() if m else strip_meta_bullets(section_risk["body"])

    ai_report_meta = result["ssrf"].get("ai_meta", {}) or {}

    assessments = json_result.get("imds_credential_exposure", {}).get("assessments", [])
    first_assessment = assessments[0] if assessments else {}
    imds_info = first_assessment.get("imds", {})
    role = first_assessment.get("iam_role", {})
    credentials = first_assessment.get("temporary_credentials", {})
    cloud = json_result.get("cloud_impact_assessment", {})
    impacts = cloud.get("cloud_impact", [])
    accessible_impacts = [
        item for item in impacts
        if item.get("accessible") is True and str(item.get("service", "")).upper() in {"S3", "LAMBDA"}
    ]

    head_left, head_right = st.columns([4, 1], vertical_alignment="center")
    with head_left:
        st.markdown("<div class='brand'>SECURITY ASSESSMENT / RESULT</div>", unsafe_allow_html=True)
        st.markdown(f"<h1 class='hero-title'>{e(report_title)}</h1>", unsafe_allow_html=True)
        st.markdown(
            f"<div class='hero-sub'><span class='mono'>{e(target_endpoint)}</span> · {e(generated_at)}</div>",
            unsafe_allow_html=True,
        )
    with head_right:
        pill_class = "ok" if severity in {"low", "unknown"} else ""
        st.markdown(
            f"<div style='text-align:right'><span class='status-pill {pill_class}'><span class='pulse'></span>{e(severity.upper())} RISK</span></div>",
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height:1.15rem'></div>", unsafe_allow_html=True)
    m1, m2, m3, m4 = st.columns(4)
    cards = [
        (m1, "RISK SCORE", f"{score:.1f}", "10점 기준 종합 위험도", "accent-high" if score >= 6 else "accent-green"),
        (m2, "핵심 근거", str(len(evidence_list)), "자동 진단 증거 항목", ""),
        (m3, "관련 CVE", str(cve_count), "유사 공격 패턴 참고", "accent-high" if cve_count else "accent-green"),
        (m4, "권고 조치", str(len(recommendation_list)), "우선순위별 대응방안", ""),
    ]
    for col, label, value, foot, cls in cards:
        col.markdown(
            f"<div class='metric-card'><div class='metric-label'>{e(label)}</div><div class='metric-value {cls}'>{e(value)}</div><div class='metric-foot'>{e(foot)}</div></div>",
            unsafe_allow_html=True,
        )

    st.markdown("<div class='section-kicker'>ATTACK PATH</div><div class='section-title'>공격 체인</div>", unsafe_allow_html=True)
    if attack_chain_steps:
        flow_html = "".join(
            f"<div class='flow-node'><div class='flow-num'>{idx:02d}</div><div class='flow-name'>{e(step)}</div></div>"
            for idx, step in enumerate(attack_chain_steps, 1)
        )
        st.markdown(f"<div class='panel'><div class='flow'>{flow_html}</div></div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='panel'>공격 체인 정보를 찾지 못했습니다.</div>", unsafe_allow_html=True)

    left, right = st.columns([1.55, 1])
    with left:
        st.markdown("<div class='section-kicker'>EVIDENCE</div><div class='section-title'>자동 진단 증거</div>", unsafe_allow_html=True)
        evidence_html = "".join(
            f"<div class='evidence'><span class='evidence-mark'>[{idx:02d}]</span><span>{e(item)}</span></div>"
            for idx, item in enumerate(evidence_list, 1)
        ) or "<div class='evidence'>탐지 근거가 없습니다.</div>"
        st.markdown(f"<div class='panel'>{evidence_html}</div>", unsafe_allow_html=True)

        if section_vuln:
            vuln_body = extract_subsection(section_vuln["body"], "공격 체인")
            vuln_intro = section_vuln["body"]
            if vuln_body:
                vuln_intro = section_vuln["body"].split("### ", 1)[0].strip()
            st.markdown("<div class='section-kicker'>CLASSIFICATION</div><div class='section-title'>취약점 분류</div>", unsafe_allow_html=True)
            with st.container(border=True):
                st.markdown(vuln_intro or "_내용 없음_")

    with right:
        st.markdown("<div class='section-kicker'>RISK</div><div class='section-title'>종합 위험도</div>", unsafe_allow_html=True)
        st.markdown("<div class='panel'>", unsafe_allow_html=True)
        st.plotly_chart(risk_gauge(score, color), width="stretch", config={"displayModeBar": False})
        st.markdown(f"<div class='summary-box'>{e(reasoning or '요약 정보가 없습니다.')}</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("<div class='section-kicker'>EXPOSURE</div><div class='section-title'>IMDS 및 자격증명</div>", unsafe_allow_html=True)
        exposure_rows = [
            ("IMDS 연결", "REACHABLE" if imds_info.get("reachable") else "NOT FOUND"),
            ("검증 버전", imds_info.get("version_tested", "-")),
            ("IAM Role", role.get("role_name", "-") if role.get("detected") else "미탐지"),
            ("임시 자격증명", "EXPOSED · MASKED" if credentials.get("exposed") else "SAFE"),
        ]
        exposure_html = "".join(
            f"<div class='test-row' style='grid-template-columns:1fr 1.4fr'><div style='color:#78869a'>{e(k)}</div><div class='mono' style='font-size:.72rem;color:{'#ff8d71' if ('REACHABLE' in str(v) or 'EXPOSED' in str(v)) else '#d7deea'}'>{e(v)}</div></div>"
            for k, v in exposure_rows
        )
        st.markdown(f"<div class='panel' style='padding:.35rem .7rem'>{exposure_html}</div>", unsafe_allow_html=True)

    st.markdown("<div class='section-kicker'>CLOUD BLAST RADIUS</div><div class='section-title'>클라우드 영향 범위</div>", unsafe_allow_html=True)
    if accessible_impacts:
        impact_cols = st.columns(max(1, min(3, len(accessible_impacts))))
        for idx, impact in enumerate(accessible_impacts):
            assets = impact.get("assets") or []
            asset_count = impact.get("asset_count", len(assets))
            permissions = "".join(f"<span class='perm'>{e(a)}</span>" for a in assets[:8])
            if len(assets) > 8:
                permissions += f"<span class='perm'>+{len(assets) - 8}</span>"
            impact_cols[idx % len(impact_cols)].markdown(
                "<div class='impact-card'>"
                "<div class='impact-top'>"
                f"<span class='service'>{e(impact.get('service', '-'))}</span>"
                f"<span class='badge badge-bad'>{e(str(impact.get('impact', '-')).upper())}</span>"
                "</div>"
                f"<div class='resource'>{e(impact.get('action', '-'))} · {e(asset_count)}개 권한 확인</div>"
                f"<div>{permissions}</div>"
                "</div>",
                unsafe_allow_html=True,
            )
    else:
        st.info("확인된 클라우드 영향이 없습니다.")

    st.markdown("<div class='section-kicker'>REMEDIATION</div><div class='section-title'>권고 조치</div>", unsafe_allow_html=True)
    if recommendation_list:
        rec_cols = st.columns(2)
        for idx, rec in enumerate(recommendation_list):
            rec_cols[idx % 2].markdown(
                f"<div class='recommend'><span class='mono'>{idx + 1:02d}</span><span>{e(rec)}</span></div>",
                unsafe_allow_html=True,
            )
    else:
        st.info("권고 조치 정보가 없습니다.")

    if ai_report_meta.get("fallback_reason"):
        st.caption(f"※ AI 분석 대신 규칙 기반 리포트가 사용되었습니다: {ai_report_meta['fallback_reason']}")

    st.divider()
    st.subheader("심층 리포트")
    narrative_sections = [
        ("CVE INTEL", "관련 CVE", section_cve),
        ("BREACH INTEL", "실제 침해 / 공개 사례", section_breach),
        ("OFFICIAL GUIDANCE", "공식 보안 권고", section_official),
        ("DEEP DIVE", "종합 분석", section_analysis),
    ]
    for kicker, label, section in narrative_sections:
        st.markdown(f"<div class='section-kicker'>{e(kicker)}</div><div class='section-title'>{e(label)}</div>", unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown((section["body"] if section else "") or "_내용을 찾지 못했습니다._")

    st.markdown(f"<div class='footer-note'>SSRF SENTINEL · TARGET {e(target_endpoint.upper())}</div>", unsafe_allow_html=True)


def render_vuln_tab(vuln_type: str, markdown_text: str, raw: dict[str, Any]) -> None:
    sections = parse_sections(markdown_text)
    meta = extract_meta(markdown_text)
    report_title = get_report_title(sections)
    verdict_label, is_vulnerable = extract_verdict(markdown_text)

    severity = meta["severity"].lower()
    score = meta["score"]
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["unknown"])

    target_endpoint = meta["target"] or (raw.get("meta", {}) or {}).get("target", "-")
    generated_at = meta["generated_at"] or format_time((raw.get("meta", {}) or {}).get("timestamp", ""))

    section_risk = find_section(sections, "위험도")
    section_vuln = find_section(sections, "취약점 분류")
    section_evidence = find_section(sections, "자동 진단 증거")
    section_cve = find_section(sections, "관련 CVE")
    section_breach = find_section(sections, "실제 침해")
    section_official = find_section(sections, "공식 보안 권고")
    section_analysis = find_section(sections, "종합 분석")
    section_recs = find_section(sections, "대응방안")
    section_sources = find_section(sections, "검색 출처")

    evidence_list = extract_evidence_list(section_evidence["body"]) if section_evidence else []
    recommendation_list = extract_recommendation_list(section_recs["body"]) if section_recs else []
    cve_count = count_subheadings(section_cve["body"]) if section_cve else 0

    attack_chain_text = extract_subsection(section_vuln["body"], "공격 체인") if section_vuln else ""
    attack_chain_steps = extract_numbered_list(attack_chain_text)

    reasoning = ""
    if section_risk:
        m = re.search(r"판단 근거:\s*(.+)", section_risk["body"])
        reasoning = m.group(1).strip() if m else strip_meta_bullets(section_risk["body"])

    stages = raw.get("stages", {}) or {}
    grid = DETAIL_ROWS_FN.get(vuln_type)
    if grid:
        headers, rows_fn = grid
        detail_rows = rows_fn(stages if isinstance(stages, dict) else {})
    else:
        headers, detail_rows = [], []

    head_left, head_right = st.columns([4, 1], vertical_alignment="center")
    with head_left:
        st.markdown(f"<div class='brand'>{e(TAB_LABELS[vuln_type].upper())} / RESULT</div>", unsafe_allow_html=True)
        st.markdown(f"<h1 class='hero-title'>{e(report_title)}</h1>", unsafe_allow_html=True)
        st.markdown(
            f"<div class='hero-sub'><span class='mono'>{e(target_endpoint)}</span> · {e(generated_at)}</div>",
            unsafe_allow_html=True,
        )
    with head_right:
        pill_class = "" if is_vulnerable else "ok"
        st.markdown(
            f"<div style='text-align:right'><span class='status-pill {pill_class}'><span class='pulse'></span>{e(verdict_label)}</span></div>",
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height:1.15rem'></div>", unsafe_allow_html=True)
    m1, m2, m3, m4 = st.columns(4)
    cards = [
        (m1, "RISK SCORE", f"{score:.1f}", "10점 기준 위험도", "accent-high" if score >= 6 else "accent-green"),
        (m2, "핵심 근거", str(len(evidence_list)), "자동 진단 증거 항목", ""),
        (m3, "관련 CVE", str(cve_count), "유사 공격 패턴 참고", "accent-high" if cve_count else "accent-green"),
        (m4, "권고 조치", str(len(recommendation_list)), "우선순위별 대응방안", ""),
    ]
    for col, label, value, foot, cls in cards:
        col.markdown(
            f"<div class='metric-card'><div class='metric-label'>{e(label)}</div><div class='metric-value {cls}'>{e(value)}</div><div class='metric-foot'>{e(foot)}</div></div>",
            unsafe_allow_html=True,
        )

    st.markdown("<div class='section-kicker'>ATTACK PATH</div><div class='section-title'>공격 체인</div>", unsafe_allow_html=True)
    if attack_chain_steps:
        flow_html = "".join(
            f"<div class='flow-node'><div class='flow-num'>{idx:02d}</div><div class='flow-name'>{e(step)}</div></div>"
            for idx, step in enumerate(attack_chain_steps, 1)
        )
        st.markdown(f"<div class='panel'><div class='flow'>{flow_html}</div></div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='panel'>공격 체인 정보를 찾지 못했습니다.</div>", unsafe_allow_html=True)

    left, right = st.columns([1.55, 1])
    with left:
        st.markdown("<div class='section-kicker'>EVIDENCE</div><div class='section-title'>자동 진단 증거</div>", unsafe_allow_html=True)
        evidence_html = "".join(
            f"<div class='evidence'><span class='evidence-mark'>[{idx:02d}]</span><span>{e(item)}</span></div>"
            for idx, item in enumerate(evidence_list, 1)
        ) or "<div class='evidence'>탐지 근거가 없습니다.</div>"
        st.markdown(f"<div class='panel'>{evidence_html}</div>", unsafe_allow_html=True)

        if section_vuln:
            vuln_body = extract_subsection(section_vuln["body"], "공격 체인")
            vuln_intro = section_vuln["body"]
            if vuln_body:
                vuln_intro = section_vuln["body"].split("### ", 1)[0].strip()
            st.markdown("<div class='section-kicker'>CLASSIFICATION</div><div class='section-title'>취약점 분류</div>", unsafe_allow_html=True)
            with st.container(border=True):
                st.markdown(vuln_intro or "_내용 없음_")

    with right:
        st.markdown("<div class='section-kicker'>RISK</div><div class='section-title'>위험도</div>", unsafe_allow_html=True)
        st.markdown("<div class='panel'>", unsafe_allow_html=True)
        st.plotly_chart(risk_gauge(score, color), width="stretch", config={"displayModeBar": False})
        st.markdown(f"<div class='summary-box'>{e(reasoning or '요약 정보가 없습니다.')}</div>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(
        f"<div class='section-kicker'>RAW DATA</div><div class='section-title'>자동 진단 상세 ({len(detail_rows)}건)</div>",
        unsafe_allow_html=True,
    )
    if detail_rows:
        render_detail_grid(headers, detail_rows)
    else:
        st.info("원본 진단 상세 데이터가 없습니다.")

    st.markdown("<div class='section-kicker'>REMEDIATION</div><div class='section-title'>대응방안</div>", unsafe_allow_html=True)
    if recommendation_list:
        rec_cols = st.columns(2)
        for idx, rec in enumerate(recommendation_list):
            rec_cols[idx % 2].markdown(
                f"<div class='recommend'><span class='mono'>{idx + 1:02d}</span><span>{e(rec)}</span></div>",
                unsafe_allow_html=True,
            )
    else:
        st.info("대응방안 정보가 없습니다.")

    st.divider()
    st.subheader("심층 리포트")
    narrative_sections = [
        ("CVE INTEL", "관련 CVE", section_cve),
        ("BREACH INTEL", "실제 침해 / 공개 사례", section_breach),
        ("OFFICIAL GUIDANCE", "공식 보안 권고", section_official),
        ("DEEP DIVE", "종합 분석", section_analysis),
        ("WEB SOURCES", "검색 출처 (Web)", section_sources),
    ]
    for kicker, label, section in narrative_sections:
        st.markdown(f"<div class='section-kicker'>{e(kicker)}</div><div class='section-title'>{e(label)}</div>", unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown((section["body"] if section else "") or "_내용을 찾지 못했습니다._")

    st.markdown(f"<div class='footer-note'>{e(TAB_LABELS[vuln_type].upper())} · TARGET {e(target_endpoint.upper())}</div>", unsafe_allow_html=True)


def render_missing(tab: str) -> None:
    label = TAB_LABELS[tab]
    reasons = {
        "ssrf": "- diagnosis/ai/analyze.py 실행이 실패했거나 report.md / ai_report.json이 생성되지 않았습니다.",
        "sqli": (
            "- --base-url로 지정한 대상에 /login, /register 등 SQLi 진단 후보 엔드포인트가 없거나 접근할 수 없었을 수 있습니다.\n"
            "- 또는 AI 리포트 생성(ai_etc/analyze_etc.py)이 실패했을 수 있습니다."
        ),
        "stored_xss": (
            "- --base-url로 지정한 대상에 /post/new, /gallery/upload 등 진단 후보 엔드포인트가 없거나 접근할 수 없었을 수 있습니다.\n"
            "- 또는 AI 리포트 생성(ai_etc/analyze_etc.py)이 실패했을 수 있습니다."
        ),
        "os_command_injection": (
            "- Stage 1(Parameter Discovery)에서 발견된 파라미터가 없었을 수 있습니다.\n"
            "- 또는 AI 리포트 생성(ai_etc/analyze_etc.py)이 실패했을 수 있습니다."
        ),
        "login_rate_limit": (
            "- --base-url로 지정한 대상에 /login 엔드포인트가 없거나 접근할 수 없었을 수 있습니다.\n"
            "- 또는 AI 리포트 생성(ai_etc/analyze_etc.py)이 실패했을 수 있습니다."
        ),
    }
    st.markdown(
        f"<div class='section-kicker'>NO REPORT</div><div class='section-title'>{e(label)} 결과 없음</div>",
        unsafe_allow_html=True,
    )
    st.warning(
        f"**{label}** 진단 리포트가 아직 없습니다. 아래 원인 중 하나일 수 있습니다.\n\n"
        f"{reasons.get(tab, '- 원인을 알 수 없습니다.')}\n\n"
        "OPENAI_API_KEY 설정, Target URL 접근 가능 여부, 위쪽 실행 로그를 확인한 뒤 "
        "'진단 시작'을 다시 눌러 재시도해보세요."
    )


# ── 사이드바 ──────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("<div class='brand'>VULN SENTINEL</div>", unsafe_allow_html=True)

    if "pipeline_result" not in st.session_state:
        st.markdown("### 진단 콘솔")
        st.caption(
            "Target URL을 입력하고 진단을 시작하면 SSRF / SQL Injection / Stored XSS / "
            "OS Command Injection / Brute Force 리포트가 아래 버튼으로 표시됩니다."
        )
    else:
        pipeline_result = st.session_state["pipeline_result"]
        st.markdown("### 취약점 리포트")
        st.caption("현재 진단 대상")
        st.code(pipeline_result["target"]["base_url"], language=None)

        active_tab = st.session_state.get("active_tab", "ssrf")

        def _has_report(tab: str) -> bool:
            if tab == "ssrf":
                return bool(pipeline_result["ssrf"]["markdown"])
            return bool(pipeline_result["etc_reports"].get(tab))

        for tab in TABS:
            available = _has_report(tab)
            btn_type = "primary" if active_tab == tab else "secondary"
            if st.button(TAB_LABELS[tab], key=f"tab_btn_{tab}", type=btn_type, use_container_width=True):
                # 탭이 바뀌면 즉시 rerun 해서 모든 버튼의 하이라이트(primary/secondary)가
                # 새 active_tab 기준으로 다시 그려지게 한다. rerun이 없으면 이번 렌더에서
                # 이미 그려진 버튼들은 이전 active_tab 색을 그대로 유지해 한 박자 늦게 표시됨.
                if st.session_state.get("active_tab") != tab:
                    st.session_state["active_tab"] = tab
                    st.rerun()
            if not available:
                st.caption("결과 없음 · 클릭 시 안내 표시")

        st.markdown("---")

        active_md = (
            pipeline_result["ssrf"]["markdown"] if active_tab == "ssrf"
            else pipeline_result["etc_reports"].get(active_tab)
        )
        if active_md:
            file_name = "report.md" if active_tab == "ssrf" else f"report_etc_{active_tab}.md"
            st.download_button(
                f"{TAB_LABELS[active_tab]} 리포트 다운로드 (Markdown)",
                data=active_md,
                file_name=file_name,
                mime="text/markdown",
            )
        st.download_button(
            "전체 진단 결과 JSON 다운로드 (마스킹)",
            data=json.dumps(sanitize_raw_scan_result(pipeline_result["raw"]), ensure_ascii=False, indent=2),
            file_name="scan_result_sanitized.json",
            mime="application/json",
        )
        st.markdown("---")
        st.caption("Credential values are masked and never rendered in full.")


# ── 메인 화면 ──────────────────────────────────────────────────────
st.markdown("<div class='brand'>VULN SENTINEL / CONSOLE 6조</div>", unsafe_allow_html=True)
st.markdown(
    "<h1 class='hero-title'>SSRF · SQL Injection · Stored XSS · OS Command Injection · Brute Force 통합 진단</h1>",
    unsafe_allow_html=True,
)
st.markdown(
    "<div class='hero-sub'>Target URL 하나로 diagnosis/main.py(1~8단계) → ai/analyze.py(SSRF) + "
    "ai_etc/analyze_etc.py(SQLi/Stored XSS/OS Command Injection/Brute Force)를 함께 실행하고, "
    "좌측 사이드바 버튼으로 4개 리포트를 오가며 봅니다.</div>",
    unsafe_allow_html=True,
)
st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)

with st.container(border=True):
    target = st.text_input(
        "Target URL",
        value="http://52.78.187.138:5000",
        placeholder="http://<EC2_PUBLIC_IP>:5000",
        help=(
            "팀의 허가된 취약 웹 애플리케이션 루트 URL을 입력하세요. "
            "/fetch(SSRF · OS Command Injection), /login, /register, /search, /post/new, "
            "/gallery/upload(SQLi · Stored XSS) 엔드포인트를 자동으로 진단합니다."
        ),
    )

    authorized = st.checkbox(
        "이 대상이 팀이 소유하거나 명시적으로 진단 허가를 받은 실습 환경임을 확인합니다."
    )

    run_button = st.button(
        "진단 시작",
        type="primary",
        use_container_width=True,
        disabled=not authorized,
    )

if run_button:
    valid, error = validate_target(target)

    if not valid:
        st.error(error)
    else:
        st.session_state.pop("pipeline_result", None)
        st.session_state.pop("active_tab", None)

        base_url, fetch_url = split_target(target)

        # 진행 상황 위젯은 여기(대시보드)에서 만들고, run_full_pipeline에는 콜백으로만 연결한다.
        # 파이프라인 실행 자체(run_pipeline.py)는 Streamlit에 의존하지 않는다.
        progress = st.progress(0.0, text="진단 준비 중")
        status_text = st.empty()
        log_box = st.empty()

        try:
            pipeline_result = run_full_pipeline(
                base_url,
                fetch_url,
                on_log=lambda logs: render_logs(log_box, logs),
                on_progress=lambda value, text: progress.progress(value, text=text),
                on_status=lambda text: status_text.caption(text),
            )
            st.session_state["pipeline_result"] = pipeline_result
            st.session_state["active_tab"] = "ssrf"
        except Exception as exc:
            st.error(str(exc))
        else:
            status_text.success(
                f"전체 파이프라인이 완료되었습니다. ({pipeline_result['report_count']}/4개 리포트 생성됨)"
            )

            # 진단이 성공하면 곧바로 rerun 해서 사이드바(맨 위에서 먼저 렌더됨)가
            # 방금 저장된 pipeline_result를 보고 SSRF/SQLi/XSS/OSC/Login-RateLimit 버튼을
            # 즉시 그리게 한다. (rerun 없으면 다음 상호작용 전까지 버튼이 안 보임)
            st.rerun()

if "pipeline_result" in st.session_state:
    pipeline_result = st.session_state["pipeline_result"]
    active_tab = st.session_state.get("active_tab", "ssrf")

    if active_tab == "ssrf":
        if pipeline_result["ssrf"]["markdown"]:
            render_ssrf_tab(pipeline_result)
        else:
            render_missing("ssrf")
    else:
        active_md = pipeline_result["etc_reports"].get(active_tab)
        if active_md:
            render_vuln_tab(active_tab, active_md, pipeline_result["raw"])
        else:
            render_missing(active_tab)
else:
    st.info(
        "Target URL을 입력하고 '진단 시작'을 누르면 SSRF / SQL Injection / Stored XSS / "
        "OS Command Injection 결과가 여기에 표시됩니다."
    )
