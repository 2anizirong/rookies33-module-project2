# SSRF-클라우드 자격증명 탈취 체인 자동 진단 도구

SK쉴더스 루키즈 33기 모듈프로젝트2 (2026.08.26 ~ 08.31)

## 프로젝트 개요
SSRF 취약점을 시작점으로 클라우드 내부 자격증명(IMDS)까지 탈취하는
전체 공격 체인을 자동으로 재현/탐지하고, 생성형 AI가 공격 흐름 전체를
근거로 위험도와 대응방안을 판단해주는 자동진단 도구입니다.

배경: `localhost`/점(.) 문자열 필터만으로는 10진수 IP 변환(예: 127.0.0.1
→ 2130706433) 등으로 손쉽게 우회 가능하며, 2019년 Capital One 침해사고처럼
SSRF 하나가 IMDS 접근 → IAM 자격증명 탈취 → S3 대량 유출로 이어질 수 있습니다.

## 폴더 구조
```
rookies33-module-project2/
│
├── aws/
│   └── cloud.py                # IMDS 자격증명 탈취 + S3/Lambda 접근 범위 점검
│
├── dashboard/
│   └── app.py                  # Streamlit 대시보드 - 우회 흐름/판정/AI 위험도 시각화
│
├── diagnosis/
│   ├── bypass.py               # SSRF 필터 우회 기법 모음 (10진수 IP, 리다이렉트 등)
│   └── scanner.py              # 정상/악성 요청 전송 + 규칙 스크리닝 + 결과 JSON 저장
│
├── docs/
│   └── api-spec.md             # 팀 간 연동 규격 (엔드포인트/JSON 스키마 합의 문서)
│
├── infra/
│   └── setup_notes.md          # EC2/보안그룹/IAM/S3 수동 구성 절차 기록
│
├── web/
│   ├── app.py                  # Flask 취약 웹 서버 - SSRF 진입점 + 허술한 필터 구현
│   └── mock_imds.py            # 로컬 테스트용 가짜 IMDS 서버 (실제 169.254.169.254 대체)
│
├── .env.example                # 환경변수 템플릿 (OPENAI_API_KEY, IMDS_BASE_URL 등)
├── .gitignore                  # .env, *.pem, .aws/ 등 자격증명 파일 커밋 방지
├── ai_judge.py                 # 전체 공격 체인 로그 → OpenAI API → 위험도/대응방안 생성
├── README.md                   # 프로젝트 개요, 실행 방법, 역할 분담, 협업 컨벤션
└── requirements.txt            # 프로젝트 전체 의존 패키지 (flask, boto3, openai, streamlit)
```

## 핵심 기능 (MVP)
1. 필터 우회 탐지 (리다이렉트 → 10진수 IP 변환, 순차 재시도)
2. IMDS 자격증명 탈취 (로컬 mock → AWS 확장 시 169.254.169.254)
3. 영향도 분석 (탈취 자격증명으로 S3/Lambda 접근 범위 점검)
4. AI 위험도 판단 (규칙 기반 1차 스크리닝 → 전체 체인 근거 LLM 판단)
5. 결과 시각화 (우회~판단 전체 흐름 대시보드)

## 역할 분담

| 파트 | 담당자 | 담당 파일 |
|---|---|---|
| 웹/AWS 구축 | 김민성, 김상현, 김이안 | `web/app.py`, `aws/cloud.py`, `infra/` |
| 진단 도구 | 김태회, 안준엽, 조윤호 | `diagnosis/bypass.py`, `diagnosis/scanner.py` |
| 대시보드 | (팀 협의 후 배정) | `dashboard/app.py` |

## ⭐⭐⭐ 실행 방법
```bash
pip install -r requirements.txt
cp .env.example .env      # OPENAI_API_KEY 입력

# 1. 취약 웹 서비스 실행
python web/app.py

# 2. 진단 도구 실행 (대상 웹 서버로 정상/악성 요청 전송)
python diagnosis/scanner.py --target http://localhost:5000

# 3. AI 위험도 판단
python ai_judge.py --log diagnosis/last_result.json

streamlit run dashboard/app.py    # 4. 대시보드 실행
```

## ⭐⭐⭐ 주의사항
- `.env` 파일은 절대 git에 커밋하지 않습니다!!! (OpenAI/AWS 키 노출 방지).
- AWS 실제 자격증명(IAM Access Key 등)은 커밋/로그/JSON 결과에 절대 남기지 않습니다.
- 로컬 mock IMDS와 실제 AWS IMDS(169.254.169.254) 대상 코드를 명확히 분리합니다.
- `diagnosis/`와 `web/`은 공격 도구/공격 대상 관계이므로 실제 배포 환경이 아닌
  팀이 직접 구축한 격리된 환경에서만 실행합니다.

## 협업 컨벤션

### 커밋 메시지 규칙

`태그: 작업 내용` 형식으로 작성합니다.

| 태그 | 설명 |
|---|---|
| `feat` | 새로운 기능 추가 |
| `fix` | 버그 수정 |
| `aws` | AWS 인프라/IAM/S3/EC2 관련 |
| `bypass` | SSRF 우회 기법 추가/수정 |
| `docs` | 문서 수정 (README, 기획서 등) |
| `chore` | 설정, 패키지 설치 등 자잘한 작업 |
| `refactor` | 기능 변화 없는 코드 정리 |
| `test` | 테스트 코드 관련 |

**예시**
```
feat: 10진수 IP 우회 기법 구현
aws: IMDS 임시 자격증명 탈취 로직 추가
fix: 대시보드 결과 JSON 파싱 오류 수정
docs: API 규격 문서 초안 작성
```

### 브랜치 전략

- `main` : 항상 동작하는 상태만 유지 (바로 push 지양)
- `web` : 웹/AWS 팀 작업 브랜치
  - 예) `web/ian`, `web/min`, `web/hyun`: 이름 나눠서 브랜치 관리
- `diagnosis` : 진단 도구 팀 작업 브랜치
  - 예) `diagnosis/yeop`, `diagnosis/tae`, `diagnosis/yoonho`: 이름 나눠서 브랜치 관리
- `dashboard` : 대시보드 팀 작업 브랜치

```bash
git checkout -b web
git checkout -b diagnosis
git checkout -b dashboard
```

자기 브랜치에서 작업 후 `main`으로 merge하여 통합 테스트합니다.

### 작업 전후 습관

```bash
# 작업 시작 전 최신 상태로 동기화
git pull origin main

# 작업 후
git add .
git commit -m "feat: 작업 내용"
git push origin 브랜치명
```

### 코드 스타일

- 함수/변수명: `snake_case`
- 우회 기법 함수는 역할이 드러나는 이름 사용 (예: `bypass_decimal_ip`)
- 커밋 전 `.env` 및 AWS 자격증명 파일이 스테이징에 포함되지 않았는지 `git status`로 확인
