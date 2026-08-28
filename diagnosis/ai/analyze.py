"""
scan_result.json 후처리 AI 파이프라인.

현재 main.py / src는 수정하지 않고 아래 흐름만 담당한다.

scan_result.json
→ 안전한 Evidence 추출
→ Web Search
→ File Search
→ 최종 LLM 종합
→ ai_report.json + report.md
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from ai.evidence_extractor import build_safe_evidence

AI_ROOT = Path(__file__).resolve().parent
DIAGNOSIS_ROOT = AI_ROOT.parent
PROJECT_ROOT = DIAGNOSIS_ROOT.parent

# module_project2/.env
load_dotenv(PROJECT_ROOT / ".env")

# diagnosis/를 Python import 경로에 추가
if str(DIAGNOSIS_ROOT) not in sys.path:
    sys.path.insert(0, str(DIAGNOSIS_ROOT))

DIAGNOSIS_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")
DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")


def analyze(scan_result: dict[str, Any], model: str = DEFAULT_MODEL) -> dict[str, Any]:
    # OpenAI 의존 모듈은 실제 AI 실행 시점에만 불러온다.
    from ai import file_research, report_generator, web_research

    evidence = build_safe_evidence(scan_result)

    print("[AI 0/3] Evidence Extraction")
    summary = evidence.get("confirmed_summary", {})
    print(
        "         "
        f"parameters={summary.get('parameter_count', 0)}, "
        f"sinks={summary.get('ssrf_candidate_count', 0)}, "
        f"vulnerable={summary.get('vulnerable_candidate_count', 0)}, "
        f"imds={summary.get('imds_reachable', False)}, "
        f"credentials={summary.get('temporary_credentials_exposed', False)}"
    )

    print("[AI 1/3] Web Research")
    web_result = web_research.run(evidence=evidence, model=model)
    print(
        f"         status={web_result.get('status')}, "
        f"tool_used={web_result.get('web_search_used', False)}, "
        f"sources={len(web_result.get('sources', []))}"
    )

    print("[AI 2/3] File Research")
    file_result = file_research.run(evidence=evidence, model=model)
    print(
        f"         status={file_result.get('status')}, "
        f"tool_used={file_result.get('file_search_used', False)}, "
        f"sources={len(file_result.get('sources', []))}"
    )

    print("[AI 3/3] Final Synthesis")
    report = report_generator.generate(
        evidence=evidence,
        web_result=web_result,
        file_result=file_result,
        model=model,
    )

    return {
        "provider": "openai",
        "analysis_type": "security_intelligence",
        "model": model,
        # 안전하게 정규화된 실제 진단 사실을 결과에도 남겨
        # Dashboard/발표에서 AI 판단의 입력 근거를 확인할 수 있게 한다.
        "safe_evidence": evidence,
        "research_status": {
            "web_search": web_result.get("status", "unknown"),
            "file_search": file_result.get("status", "unknown"),
            "web_search_used": web_result.get("web_search_used", False),
            "file_search_used": file_result.get("file_search_used", False),
        },
        "report": report,
        "sources": {
            "web": web_result.get("sources", []),
            "files": file_result.get("sources", []),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="scan_result.json")
    parser.add_argument("--output", default="ai_report.json")
    parser.add_argument("--report", default="report.md")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument(
        "--evidence-only",
        action="store_true",
        help="API 호출 없이 현재 scan_result에서 추출되는 안전한 Evidence만 출력",
    )
    args = parser.parse_args()

    input_path = Path(args.input)

    if not input_path.exists():
        input_path = DIAGNOSIS_ROOT / args.input

    if not input_path.exists():
        parser.error(f"입력 파일을 찾을 수 없음: {args.input}")

    try:
        scan_result = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        parser.error(f"입력 JSON 파싱 실패: {exc}")

    if args.evidence_only:
        evidence = build_safe_evidence(scan_result)
        print(json.dumps(evidence, ensure_ascii=False, indent=2))
        return

    result = analyze(scan_result=scan_result, model=args.model)

    output_path = Path(args.output)

    if not output_path.is_absolute():
        output_path = DIAGNOSIS_ROOT / output_path

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    from ai import report_generator
    report_path = Path(args.report)

    if not report_path.is_absolute():
        report_path = DIAGNOSIS_ROOT / report_path

    report_generator.save_markdown_report(result, report_path)

    print(f"[DONE] {output_path}")
    print(f"[DONE] {args.report}")


if __name__ == "__main__":
    main()
