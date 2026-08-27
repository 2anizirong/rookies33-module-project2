"""
가짜 AWS 메타데이터 서버 (SSRF 실습용 타겟)
- 5001 포트에서 127.0.0.1에만 바인딩
- .env 파일로 가짜 credentials 관리
- 브라우저로 직접 접속하지 말고, 메인 앱(5000)의 /fetch SSRF로 접근해서 탈취하는 게 목표
"""
from flask import Flask, jsonify
from dotenv import load_dotenv
import os

load_dotenv()

app = Flask(__name__)

MOCK_INSTANCE_ID = os.getenv("MOCK_INSTANCE_ID", "i-0abcdef1234567890")
MOCK_HOSTNAME = os.getenv("MOCK_HOSTNAME", "ip-10-0-1-42.ec2.internal")
MOCK_ROLE_NAME = os.getenv("MOCK_ROLE_NAME", "vuln-board-ec2-role")

MOCK_CREDENTIALS = {
    "Code": "Success",
    "LastUpdated": os.getenv("MOCK_LAST_UPDATED", "2025-01-15T10:23:45Z"),
    "Type": "AWS-HMAC",
    "AccessKeyId": os.getenv("MOCK_ACCESS_KEY_ID", "AKIA_FAKE_LEAKED_KEY_XYZ"),
    "SecretAccessKey": os.getenv("MOCK_SECRET_ACCESS_KEY", "fakeS3cr3t/AbCdEfGh1234567890+ExampleKey"),
    "Token": os.getenv("MOCK_SESSION_TOKEN", "FQoGZXIvYXdzEXAMPLE_SESSION_TOKEN_DO_NOT_USE_IN_REAL_WORLD=="),
    "Expiration": os.getenv("MOCK_EXPIRATION", "2025-01-15T16:23:45Z"),
}


@app.route("/")
def root():
    return "AWS EC2 Instance Metadata Service (fake, for practice)\n"


@app.route("/latest/meta-data/")
def list_metadata():
    return "instance-id\niam/\nhostname\n", 200


@app.route("/latest/meta-data/instance-id")
def get_instance_id():
    return MOCK_INSTANCE_ID


@app.route("/latest/meta-data/hostname")
def get_hostname():
    return MOCK_HOSTNAME


@app.route("/latest/meta-data/iam/")
def iam_root():
    return "security-credentials/\n"


@app.route("/latest/meta-data/iam/security-credentials/")
def get_role_name():
    return MOCK_ROLE_NAME, 200


@app.route(f"/latest/meta-data/iam/security-credentials/{MOCK_ROLE_NAME}")
def get_credentials():
    return jsonify(MOCK_CREDENTIALS)


if __name__ == "__main__":
    print("=" * 60)
    print("[mock IMDS] 127.0.0.1:5001 에서 가짜 IMDS 서버 시작")
    print("이 서버는 SSRF 실습의 '탈취 대상'입니다.")
    print("브라우저로 직접 접속하지 말고, 메인 앱(5000)의")
    print("/fetch SSRF 취약점을 통해 접근을 시도하세요.")
    print(f"현재 role name: {MOCK_ROLE_NAME}")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5001, debug=True)
