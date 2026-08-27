"""
Stage 1: Parameter Discovery
- Arjun을 서브프로세스로 실행
- 결과 JSON을 준엽 규격으로 변환

Output 규격:
{
  "target": "http://victim.com/fetch",
  "parameters": [
    {"name": "url", "method": "GET", "location": "query"},
    ...
  ]
}
"""
import subprocess
import json
import tempfile
import os
from typing import Optional


def run_parameter_discovery(
    target_url: str,
    method: str = "GET",
    wordlist: Optional[str] = None,
    timeout: int = 300,
) -> dict:
    """Arjun 실행 → 파라미터 리스트 추출 → 규격 dict 반환"""
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    output_path = tmp.name

    cmd = ["arjun", "-u", target_url, "-m", method, "-oJ", output_path]
    if wordlist:
        cmd.extend(["-w", wordlist])

    try:
        subprocess.run(cmd, check=True, timeout=timeout, capture_output=True)
    except FileNotFoundError:
        return _empty(target_url, "Arjun 미설치 (pip install arjun)")
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode(errors='ignore') if e.stderr else ""
        stdout = e.stdout.decode(errors='ignore') if e.stdout else ""
        return _empty(target_url, f"Arjun 실행 실패:\nSTDERR: {stderr}\nSTDOUT: {stdout}")
    except subprocess.TimeoutExpired:
        return _empty(target_url, f"Arjun 타임아웃 ({timeout}s)")

    result = _parse_arjun_output(output_path, target_url, method)
    try:
        os.unlink(output_path)
    except OSError:
        pass
    return result


def _empty(target_url: str, err: str) -> dict:
    return {"target": target_url, "parameters": [], "error": err}


def _parse_arjun_output(json_path: str, target_url: str, method: str) -> dict:
    """
    Arjun JSON 출력을 준엽 규격으로 변환.
    Arjun 2.x 출력 예시:
      [{"url": "...", "method": "GET", "params": ["url", "image"], "headers": {}}]
    또는 dict 포맷도 대응.
    """
    try:
        with open(json_path, "r") as f:
            raw = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"target": target_url, "parameters": []}

    parameters = []

    if isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            params = entry.get("params") or []
            m = (entry.get("method") or method).upper()
            location = _infer_location(m)
            for p in params:
                parameters.append({"name": p, "method": m, "location": location})

    elif isinstance(raw, dict):
        for url_key, val in raw.items():
            if isinstance(val, dict):
                params = val.get("params", [])
                m = (val.get("method") or method).upper()
            else:
                params = val if isinstance(val, list) else []
                m = method.upper()
            location = _infer_location(m)
            for p in params:
                parameters.append({"name": p, "method": m, "location": location})

    return {"target": target_url, "parameters": parameters}


def _infer_location(method: str) -> str:
    """method로 location 유추 (Arjun이 body/json 구분을 안 주는 경우 기본값)"""
    return "query" if method == "GET" else "body"


if __name__ == "__main__":
    import sys
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000/fetch"
    result = run_parameter_discovery(url)
    print(json.dumps(result, indent=2, ensure_ascii=False))
