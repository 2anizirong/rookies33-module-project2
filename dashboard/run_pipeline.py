"""
run_pipeline.py
URL을 받아 diagnosis -> ai/analyze 를 순차 실행한다.

사용법:
    python run_pipeline.py http://52.78.187.138:5000

폴더 구조 가정 (dashboard 기준 상대경로):
    rookies33-module-project2/
    ├── dashboard/          <- 이 스크립트는 여기서 실행됨
    └── diagnosis/
        ├── main.py
        ├── AAA.json        <- diagnosis 결과
        └── ai/
            ├── analyze.py
            ├── report.md   <- 최종 결과물
            └── report.json
"""

import argparse
import subprocess
import sys
from pathlib import Path


# dashboard/ 에서 실행한다고 가정하고 경로 잡기
BASE_DIR = Path(__file__).resolve().parent          # dashboard/
DIAGNOSIS_DIR = BASE_DIR.parent / "diagnosis"
DIAGNOSIS_MAIN = DIAGNOSIS_DIR / "main.py"
ANALYZE_MAIN = DIAGNOSIS_DIR / "ai" / "analyze.py"
OUTPUT_JSON = DIAGNOSIS_DIR / "AAA.json"


def build_fetch_url(user_url: str) -> str:
    """사용자가 http://host:port 만 넣었든 /fetch 까지 넣었든 정규화."""
    url = user_url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    if not url.endswith("/fetch"):
        url = url + "/fetch"
    return url


def run(cmd: list[str], cwd: Path) -> int:
    """명령어를 실시간 출력하며 실행. 반환값은 exit code."""
    print(f"\n[$] cd {cwd}")
    print(f"[$] {' '.join(cmd)}\n", flush=True)
    proc = subprocess.run(cmd, cwd=str(cwd))
    return proc.returncode


def run_pipeline(user_url: str) -> dict:
    """
    파이프라인 전체를 실행하고 결과 dict를 반환.
    UI에서도 재사용할 수 있게 함수로 분리.
    """
    fetch_url = build_fetch_url(user_url)

    # 1) diagnosis 실행
    cmd1 = [
        sys.executable,
        str(DIAGNOSIS_MAIN),
        fetch_url,
        "-o", str(OUTPUT_JSON),
    ]
    code1 = run(cmd1, cwd=BASE_DIR)
    if code1 != 0:
        return {"ok": False, "stage": "diagnosis", "code": code1}

    # 2) ai/analyze 실행
    #    원래 명령이 `--input AAA.json` 이라 dashboard/ 에서 상대경로로는 못 찾음.
    #    diagnosis/ 에서 실행하면 AAA.json 이 바로 옆에 있어서 잘 잡힘.
    cmd2 = [
        sys.executable,
        str(ANALYZE_MAIN),
        "--input", str(OUTPUT_JSON.name),  # AAA.json
    ]
    code2 = run(cmd2, cwd=DIAGNOSIS_DIR)
    if code2 != 0:
        return {"ok": False, "stage": "analyze", "code": code2}

    return {
        "ok": True,
        "fetch_url": fetch_url,
        "diagnosis_json": str(OUTPUT_JSON),
        "report_md": str(DIAGNOSIS_DIR / "ai" / "report.md"),
        "report_json": str(DIAGNOSIS_DIR / "ai" / "report.json"),
    }


def main():
    parser = argparse.ArgumentParser(description="Run diagnosis + analyze pipeline")
    parser.add_argument("url", help="타겟 URL (예: http://52.78.187.138:5000)")
    args = parser.parse_args()

    result = run_pipeline(args.url)
    if not result["ok"]:
        print(f"\n[!] 실패: {result['stage']} 단계 (exit={result['code']})")
        sys.exit(1)

    print("\n[✓] 완료")
    print(f"    - diagnosis: {result['diagnosis_json']}")
    print(f"    - report.md : {result['report_md']}")
    print(f"    - report.json: {result['report_json']}")


if __name__ == "__main__":
    main()
