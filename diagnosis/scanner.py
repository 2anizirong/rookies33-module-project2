"""
diagnosis/scanner.py
SSRF 자동 진단 스캐너

흐름:
1. 정상 요청 1번 보내서 대상 서버가 살아있는지 확인
2. bypass.py 의 우회 기법들을 순서대로 시도
3. 우회 성공(=차단되지 않고 응답 옴) 판별
4. 성공한 우회 정보 + 응답을 결과 JSON으로 저장
   -> docs/api-spec.md 에서 정한 스키마를 따릅니다.
"""

import argparse
import json
import requests
from datetime import datetime

from bypass import BYPASS_TECHNIQUES, bypass_decimal_ip, bypass_redirect

# TODO: 실제 진단 대상 내부 IP (로컬은 127.0.0.1, mock IMDS 등)
DEFAULT_INTERNAL_TARGET = "127.0.0.1"


def check_target_alive(base_url: str) -> bool:
    """진단 대상 웹 서버(web/app.py)가 살아있는지 확인합니다."""
    try:
        response = requests.get(f"{base_url}/health", timeout=3)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def screen_response(response_json: dict) -> str:
    """
    diagnosis/rule 기반 1차 스크리닝.
    응답 패턴을 보고 '양호' / '취약' / 'N/A' 를 판별합니다.
    (이후 ai_judge.py 에서 전체 로그를 근거로 다시 한번 판단합니다.)
    """
    if response_json.get("blocked") is True:
        return "양호"
    if response_json.get("status_code") == 200:
        return "취약"
    return "N/A"


def run_scan(base_url: str, internal_target: str) -> dict:
    """
    전체 스캔을 실행하고 결과 딕셔너리를 반환합니다.
    결과 스키마 (docs/api-spec.md 와 반드시 일치시킬 것):
    {
        "target": "...",
        "timestamp": "...",
        "attempts": [ {기법명, 시도 URL, 응답, 판정}, ... ],
        "final_verdict": "취약" | "양호" | "N/A"
    }
    """
    result = {
        "target": internal_target,
        "timestamp": datetime.now().isoformat(),
        "attempts": [],
        "final_verdict": "N/A",
    }

    if not check_target_alive(base_url):
        result["final_verdict"] = "N/A"
        result["error"] = "대상 서버에 연결할 수 없습니다."
        return result

    for technique_name, technique_fn in BYPASS_TECHNIQUES:
        try:
            # TODO: 기법마다 필요한 인자가 달라서(redirect는 인자 2개) 분기 처리 필요
            if technique_name == "decimal_ip":
                crafted_url = technique_fn(internal_target)
            elif technique_name == "redirect":
                # TODO: 오픈 리다이렉트 엔드포인트 정해지면 채우기
                crafted_url = technique_fn(internal_target, "http://example.com/redirect")
            else:
                continue

            response = requests.get(
                f"{base_url}/fetch", params={"url": crafted_url}, timeout=5
            )
            response_json = response.json()
            verdict = screen_response(response_json)

            result["attempts"].append({
                "technique": technique_name,
                "crafted_url": crafted_url,
                "response": response_json,
                "verdict": verdict,
            })

            if verdict == "취약":
                result["final_verdict"] = "취약"
                # TODO: 우회 성공 시 aws/cloud.py 로 넘겨서 IMDS 탈취 단계 진행

        except requests.exceptions.RequestException as e:
            result["attempts"].append({
                "technique": technique_name,
                "error": str(e),
                "verdict": "N/A",
            })

    if result["final_verdict"] == "N/A" and result["attempts"]:
        # 취약으로 판정된 시도가 하나도 없으면 양호로 처리
        result["final_verdict"] = "양호"

    return result


def save_result(result: dict, output_path: str = "diagnosis/last_result.json"):
    """진단 결과를 JSON 파일로 저장합니다. (대시보드/ai_judge.py 가 읽어갈 파일)"""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"결과 저장 완료: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSRF 자동 진단 스캐너")
    parser.add_argument("--target", default="http://localhost:5000", help="진단 대상 웹 서버 주소")
    parser.add_argument("--internal", default=DEFAULT_INTERNAL_TARGET, help="우회하려는 내부 주소")
    args = parser.parse_args()

    scan_result = run_scan(args.target, args.internal)
    print(json.dumps(scan_result, ensure_ascii=False, indent=2))
    save_result(scan_result)