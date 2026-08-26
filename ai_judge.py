"""
ai_judge.py
LLM 기반 위험도 판단

- diagnosis/scanner.py 가 만든 진단 결과 JSON(우회 시도 로그)과
  aws/cloud.py 가 만든 영향도 리포트를 합쳐서 OpenAI API에 전달합니다.
- 전체 공격 체인을 근거로 위험도(상/중/하)와 대응방안을 자연어로 생성합니다.
"""

import argparse
import json
import os
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

SYSTEM_PROMPT = """\
당신은 클라우드 보안 진단 전문가입니다.
아래 제공되는 SSRF 공격 체인 로그(필터 우회 시도 → IMDS 자격증명 탈취 →
S3/Lambda 접근 범위)를 근거로 다음 형식의 JSON으로만 답변하세요:

{
  "risk_level": "상" | "중" | "하",
  "reasoning": "판단 근거를 전체 체인에 기반하여 설명",
  "recommendation": "대응 방안 (구체적으로)"
}
"""


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def judge_risk(scan_result: dict, impact_report: dict | None = None) -> dict:
    """
    전체 공격 체인 로그를 LLM에 전달하고 위험도 판단 결과를 받아옵니다.
    """
    combined_log = {
        "scan_result": scan_result,
        "impact_report": impact_report or {},
    }

    # TODO: 모델명은 팀 내 사용 가능한 모델로 확정 후 반영
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(combined_log, ensure_ascii=False)},
        ],
        response_format={"type": "json_object"},
    )

    judgement_text = response.choices[0].message.content
    return json.loads(judgement_text)


def save_judgement(judgement: dict, output_path: str = "diagnosis/judgement.json"):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(judgement, f, ensure_ascii=False, indent=2)
    print(f"판단 결과 저장 완료: {output_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LLM 기반 SSRF 공격 체인 위험도 판단")
    parser.add_argument("--log", required=True, help="scanner.py 결과 JSON 경로")
    parser.add_argument("--impact", default=None, help="aws/cloud.py 영향도 리포트 JSON 경로 (선택)")
    args = parser.parse_args()

    scan_data = load_json(args.log)
    impact_data = load_json(args.impact) if args.impact else None

    result = judge_risk(scan_data, impact_data)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    save_judgement(result)