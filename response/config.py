"""경로와 상수.

설정 파일(mapping.yml, policies/)은 **코드와 함께 이동**해야 하므로 패키지 기준으로 잡고,
실행 산출물(out/, logs/)은 **실행 위치 기준**으로 잡는다. 통합 파이프라인에서
오케스트레이터가 산출물을 한곳에 모을 수 있어야 하기 때문이다.
"""

import os

# 설정 - 패키지와 한 덩어리로 움직인다
PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
MAPPING_PATH = os.path.join(PACKAGE_DIR, "mapping.yml")
POLICY_DIR = os.path.join(PACKAGE_DIR, "policies")
# 사람이 직접 조치할 때의 안내 (mode=manual). mapping.yml 의 runbook 키가 가리킨다
RUNBOOK_PATH = os.path.join(PACKAGE_DIR, "runbook.yml")

# 조치 대상 범위. 실제 계정 ID 가 들어가는 scope.yml 은 git 에서 제외한다.
# 환경변수(CSPM_SCOPE_ACCOUNTS / CSPM_SCOPE_REGIONS)가 파일보다 우선한다.
SCOPE_PATH = os.path.join(PACKAGE_DIR, "scope.yml")
SCOPE_EXAMPLE_PATH = os.path.join(PACKAGE_DIR, "scope.example.yml")

# 산출물 - 실행 위치 기준. CSPM_WORK_DIR 로 재지정할 수 있다
WORK_DIR = os.environ.get("CSPM_WORK_DIR") or os.getcwd()
OUT_DIR = os.path.join(WORK_DIR, "out")
LOG_DIR = os.path.join(WORK_DIR, "logs")
# 대상 리소스로 범위를 좁힌 임시 정책을 두는 곳
SCOPED_DIR = os.path.join(OUT_DIR, "_scoped")

# Custodian 한 번 실행에 허용할 최대 시간(초)
CUSTODIAN_TIMEOUT = 300

# resources.json 에서 리소스 ARN 을 찾을 때 시도할 필드 순서
# S3 버킷은 BucketArn 을 쓰고, 리소스 타입에 따라 Arn/arn 인 경우도 있다
ARN_FIELDS = ("BucketArn", "Arn", "arn")
