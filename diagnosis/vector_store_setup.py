"""
guides/ 문서를 OpenAI Vector Store에 등록하는 세팅/동기화 스크립트.

최초 세팅:
    python vector_store_setup.py --init

자료 갱신:
    python vector_store_setup.py --sync

실행 후 출력된 SECURITY_GUIDE_VECTOR_STORE_ID 값을 .env에 추가한다.
"""

from __future__ import annotations

import argparse
import logging
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI


logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DIAGNOSIS_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = DIAGNOSIS_ROOT.parent
load_dotenv(PROJECT_ROOT / ".env")

GUIDES_DIR = DIAGNOSIS_ROOT / os.getenv("SECURITY_GUIDES_DIR", "guides")
VECTOR_STORE_NAME = os.getenv("SECURITY_GUIDE_VECTOR_STORE_NAME", "security-guides")
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".md", ".docx"}
POLL_TIMEOUT_SECONDS = 180
POLL_INTERVAL_SECONDS = 3s


def _iter_guide_files(directory: Path) -> list[Path]:
    if not directory.exists():
        raise FileNotFoundError(f"가이드 디렉토리를 찾을 수 없음: {directory}")

    files = sorted(
        p for p in directory.rglob("*")
        if p.is_file() and p.suffix.lower() in ALLOWED_EXTENSIONS
    )
    if not files:
        raise ValueError(
            f"{directory} 안에 업로드할 문서가 없음 "
            f"(허용 확장자: {sorted(ALLOWED_EXTENSIONS)})"
        )
    return files


def _find_existing_vector_store(client: OpenAI, name: str) -> str | None:
    page = client.vector_stores.list(limit=100)
    for store in page.data:
        if store.name == name:
            return store.id
    return None


def _vector_store_file_count(client: OpenAI, vector_store_id: str) -> int:
    page = client.vector_stores.files.list(vector_store_id=vector_store_id)
    return len(page.data)


def _wait_until_ready(client: OpenAI, vector_store_id: str) -> None:
    deadline = time.monotonic() + POLL_TIMEOUT_SECONDS

    while time.monotonic() < deadline:
        store = client.vector_stores.retrieve(vector_store_id)
        counts = store.file_counts

        if counts.in_progress == 0:
            logger.info(
                "처리 완료: completed=%d failed=%d",
                counts.completed,
                counts.failed,
            )
            if counts.failed:
                logger.warning("일부 파일 처리 실패. Vector Store 상태를 확인하세요.")
            return

        logger.info(
            "파일 처리 중... in_progress=%d completed=%d",
            counts.in_progress,
            counts.completed,
        )
        time.sleep(POLL_INTERVAL_SECONDS)

    raise TimeoutError(
        f"{POLL_TIMEOUT_SECONDS}s 안에 Vector Store 처리가 끝나지 않음: {vector_store_id}"
    )


def _clear_vector_store_files(client: OpenAI, vector_store_id: str) -> None:
    existing = client.vector_stores.files.list(vector_store_id=vector_store_id)
    for item in existing.data:
        client.vector_stores.files.delete(
            vector_store_id=vector_store_id,
            file_id=item.id,
        )
        logger.info("기존 Vector Store 연결 제거: %s", item.id)


def _upload_files(client: OpenAI, vector_store_id: str, files: list[Path]) -> None:
    for file_path in files:
        with file_path.open("rb") as fp:
            uploaded = client.files.create(
                file=fp,
                purpose="user_data",
            )

        client.vector_stores.files.create(
            vector_store_id=vector_store_id,
            file_id=uploaded.id,
        )
        logger.info("업로드/연결: %s (file_id=%s)", file_path.name, uploaded.id)


def build_or_sync_vector_store(reset: bool) -> str:
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError("OPENAI_API_KEY가 .env 또는 환경변수에 설정되지 않음")

    client = OpenAI()
    files = _iter_guide_files(GUIDES_DIR)
    logger.info("가이드 파일 %d개 발견: %s", len(files), GUIDES_DIR)

    vector_store_id = _find_existing_vector_store(client, VECTOR_STORE_NAME)

    if vector_store_id is None:
        store = client.vector_stores.create(name=VECTOR_STORE_NAME)
        vector_store_id = store.id
        logger.info("새 Vector Store 생성: %s", vector_store_id)
        _upload_files(client, vector_store_id, files)

    elif reset:
        logger.info("기존 Vector Store 동기화: %s", vector_store_id)
        _clear_vector_store_files(client, vector_store_id)
        _upload_files(client, vector_store_id, files)

    else:
        # --init을 반복 실행해 중복 업로드되는 것을 방지한다.
        count = _vector_store_file_count(client, vector_store_id)
        if count > 0:
            logger.info(
                "기존 Vector Store에 %d개 파일이 이미 있어 재업로드하지 않음. "
                "자료 갱신은 --sync 사용.",
                count,
            )
        else:
            _upload_files(client, vector_store_id, files)

    _wait_until_ready(client, vector_store_id)
    return vector_store_id


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--init", action="store_true", help="최초 생성/초기 연결")
    group.add_argument("--sync", action="store_true", help="기존 연결 제거 후 guides/ 전체 재등록")
    args = parser.parse_args()

    vector_store_id = build_or_sync_vector_store(reset=args.sync)

    print()
    print("=" * 70)
    print(f"SECURITY_GUIDE_VECTOR_STORE_ID={vector_store_id}")
    print("위 한 줄을 프로젝트 루트의 .env에 추가하세요.")
    print("=" * 70)


if __name__ == "__main__":
    main()
