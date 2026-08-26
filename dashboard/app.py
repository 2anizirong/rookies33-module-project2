"""
dashboard/app.py
Streamlit 대시보드

- diagnosis/last_result.json (스캔 결과) 과
  diagnosis/judgement.json (AI 위험도 판단 결과) 를 읽어서 화면에 표시합니다.
- 흐름: 필터 우회 시도 목록 -> 최종 판정(양호/취약/N/A) -> AI 위험도/대응방안
"""

import json
import streamlit as st

SCAN_RESULT_PATH = "diagnosis/last_result.json"
JUDGEMENT_PATH = "diagnosis/judgement.json"

st.set_page_config(page_title="SSRF-클라우드 자격증명 탈취 체인 진단", layout="wide")


def load_json_safe(path: str) -> dict | None:
    """파일이 없거나 아직 진단 전이면 None 을 반환합니다."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def verdict_badge(verdict: str) -> str:
    """판정 결과에 따라 색상 있는 뱃지 텍스트를 만듭니다."""
    color_map = {"취약": "🔴 취약", "양호": "🟢 양호", "N/A": "⚪ N/A"}
    return color_map.get(verdict, verdict)


def render_scan_flow(scan_result: dict):
    """우회 시도 흐름을 순서대로 표시합니다."""
    st.subheader("① SSRF 필터 우회 시도 흐름")
    st.write(f"대상: `{scan_result.get('target')}`")
    st.write(f"진단 시각: {scan_result.get('timestamp')}")

    for attempt in scan_result.get("attempts", []):
        with st.expander(f"{attempt.get('technique')} — {verdict_badge(attempt.get('verdict', 'N/A'))}"):
            st.json(attempt)

    st.markdown(f"### 최종 판정: {verdict_badge(scan_result.get('final_verdict', 'N/A'))}")


def render_ai_judgement(judgement: dict):
    """AI 위험도 판단 결과를 표시합니다."""
    st.subheader("② AI 위험도 판단")

    risk_level = judgement.get("risk_level", "N/A")
    risk_color = {"상": "🔴", "중": "🟡", "하": "🟢"}.get(risk_level, "⚪")

    col1, col2 = st.columns([1, 3])
    with col1:
        st.metric("위험도", f"{risk_color} {risk_level}")
    with col2:
        st.write("**판단 근거**")
        st.write(judgement.get("reasoning", "-"))

    st.write("**대응 방안**")
    st.info(judgement.get("recommendation", "-"))


def main():
    st.title("SSRF → 클라우드 자격증명 탈취 체인 자동 진단")

    scan_result = load_json_safe(SCAN_RESULT_PATH)
    judgement = load_json_safe(JUDGEMENT_PATH)

    if scan_result is None:
        st.warning("아직 진단 결과가 없습니다. 먼저 `diagnosis/scanner.py` 를 실행해주세요.")
        return

    render_scan_flow(scan_result)

    st.divider()

    if judgement is None:
        st.warning("아직 AI 위험도 판단 결과가 없습니다. `ai_judge.py` 를 실행해주세요.")
        return

    render_ai_judgement(judgement)


if __name__ == "__main__":
    main()