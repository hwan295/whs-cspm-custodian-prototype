#!/usr/bin/env python3
"""
CSPM 자동 대응 프로토타입 - Prowler(탐지)와 Cloud Custodian(조치)을 잇는 파이프라인.

Prowler 가 뱉은 findings(JSON-OCSF)를 읽어, 각 체크에 대응하는 Custodian 정책을
mapping.yml 에서 찾고, 정책 단위로 Custodian 을 dryrun 실행한 뒤,
dryrun 결과에 실제로 걸린 리소스와 finding 을 대조해 조치 로그를 남긴다.

Custodian 은 findings 를 입력으로 받지 않고 AWS 를 직접 조회하는 도구이므로,
두 도구의 연결점은 "Prowler 의 metadata.event_code ↔ Custodian 정책 이름" 매핑뿐이다.

사용법:
    python main.py <prowler-output.ocsf.json>

이번 범위: #1 파서 / #2 매핑 / #3 정책 / #6 실행기(dryrun) / #7 로그
제외:     #4 범위 필터 / #5 분기 로직  (다른 파트와 규약 합의 후 붙인다)

주의: 실제 조치(actions)는 실행하지 않는다. dryrun 전용이다.
"""

import json
import os
import subprocess
import sys
from datetime import datetime

try:
    import yaml
except ImportError:
    print("[!] PyYAML 이 필요합니다:  pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# 기준 경로 - 스크립트가 있는 위치를 기준으로 잡아 어디서 실행해도 동일하게 동작
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_DIR = os.path.join(BASE_DIR, "policies")
MAPPING_PATH = os.path.join(BASE_DIR, "mapping.yml")
OUT_DIR = os.path.join(BASE_DIR, "out")
LOG_DIR = os.path.join(BASE_DIR, "logs")

# Custodian 한 번 실행에 허용할 최대 시간(초)
CUSTODIAN_TIMEOUT = 300

# resources.json 에서 리소스 ARN 을 찾을 때 시도할 필드 순서
# S3 버킷은 BucketArn 을 쓰고, 리소스 타입에 따라 Arn/arn 인 경우도 있다
ARN_FIELDS = ("BucketArn", "Arn", "arn")


# ---------------------------------------------------------------------------
# (1) 파서  -- 티켓 #1
# ---------------------------------------------------------------------------

def _dig(data, path):
    """점(.)으로 구분된 경로를 따라 중첩 dict/list 에서 값을 꺼낸다. 없으면 None."""
    current = data
    for key in path.split("."):
        if isinstance(current, list):
            # 숫자 인덱스만 허용 (예: resources.0.uid)
            if not key.isdigit() or int(key) >= len(current):
                return None
            current = current[int(key)]
        elif isinstance(current, dict):
            if key not in current:
                return None
            current = current[key]
        else:
            return None
    return current


# finding 에서 뽑아낼 필드 -> OCSF 경로
FIELD_PATHS = {
    "finding_uid": "finding_info.uid",
    "check_id": "metadata.event_code",
    "severity": "severity",
    "status_code": "status_code",
    "resource_uid": "resources.0.uid",
    "resource_type": "resources.0.type",
    "service": "resources.0.group.name",
    "region": "resources.0.region",
    "account_uid": "cloud.account.uid",
    "scan_time": "time_dt",
}


def load_raw_findings(path):
    """Prowler JSON-OCSF 파일을 읽어 finding 리스트로 돌려준다.

    Prowler 출력은 보통 JSON 배열이지만, 한 줄에 하나씩(NDJSON) 나오는 경우도
    있어 둘 다 받아준다.
    """
    with open(path, "r", encoding="utf-8") as f:
        text = f.read().strip()

    if not text:
        return []

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # NDJSON 으로 재시도
        data = []
        for lineno, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                data.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[!] {lineno}번째 줄을 JSON 으로 읽지 못해 건너뜁니다: {e}")

    if isinstance(data, dict):
        # 단일 finding 이거나 {"findings": [...]} 형태일 수 있다
        for key in ("findings", "results", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    return data


def parse_finding(raw, index):
    """OCSF finding 하나에서 필요한 필드만 추출한다. 없는 필드는 None + 경고."""
    parsed = {}
    missing = []
    for field, path in FIELD_PATHS.items():
        value = _dig(raw, path)
        parsed[field] = value
        if value is None:
            missing.append(field)

    if missing:
        # finding_uid 가 없을 수도 있으므로 인덱스도 같이 찍는다
        label = parsed.get("finding_uid") or f"#{index}"
        print(f"[!] finding {label}: 필드 누락 -> {', '.join(missing)}")

    return parsed


def parse_findings(path):
    """파일을 읽어 FAIL 인 finding 만 파싱해 돌려준다."""
    print(f"[1/4] findings 파싱: {path}")
    raw_findings = load_raw_findings(path)
    print(f"      전체 finding {len(raw_findings)}건")

    parsed = []
    for index, raw in enumerate(raw_findings):
        if not isinstance(raw, dict):
            print(f"[!] finding #{index}: dict 가 아니라 건너뜁니다")
            continue
        # FAIL 만 대상으로 한다
        if raw.get("status_code") != "FAIL":
            continue
        parsed.append(parse_finding(raw, index))

    print(f"      FAIL {len(parsed)}건 추출")
    return parsed


# ---------------------------------------------------------------------------
# (2) 매핑 조회  -- 티켓 #2
# ---------------------------------------------------------------------------

def load_mapping(path=MAPPING_PATH):
    """mapping.yml 을 읽는다."""
    print(f"[2/4] 매핑 로드: {path}")
    with open(path, "r", encoding="utf-8") as f:
        mapping = yaml.safe_load(f) or {}
    print(f"      매핑 항목 {len(mapping)}건")
    return mapping


def resolve_policy(finding, mapping):
    """finding 의 check_id 로 정책을 찾는다.

    반환: (policy_name, status, reason)
      - 매핑 없음        -> (None, "unmapped", ...)
      - auto_fixable=false -> (None, "not_fixable", 매핑에 적힌 사유)
      - 정상             -> (정책이름, None, None)
    """
    check_id = finding.get("check_id")
    entry = mapping.get(check_id) if check_id else None

    if entry is None:
        return None, "unmapped", f"mapping.yml 에 '{check_id}' 항목이 없음"

    if not entry.get("auto_fixable", False):
        reason = entry.get("reason") or "auto_fixable=false"
        return None, "not_fixable", reason

    policy_name = entry.get("policy")
    if not policy_name:
        return None, "unmapped", "auto_fixable=true 지만 policy 가 비어 있음"

    return policy_name, None, None


# ---------------------------------------------------------------------------
# (3) 실행기  -- 티켓 #6
# ---------------------------------------------------------------------------

def policy_file(policy_name):
    """정책 이름에 대응하는 yml 경로."""
    return os.path.join(POLICY_DIR, f"{policy_name}.yml")


def run_custodian(policy_name):
    """Custodian 을 dryrun 으로 1회 실행한다.

    반환: (성공여부, 에러메시지)
    실패해도 예외를 던지지 않는다. 호출부가 다음 정책으로 계속 진행할 수 있어야 한다.
    """
    path = policy_file(policy_name)
    if not os.path.isfile(path):
        return False, f"정책 파일이 없음: {path}"

    cmd = ["custodian", "run", "-s", OUT_DIR, path, "--dryrun"]
    print(f"      실행: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=CUSTODIAN_TIMEOUT,
        )
    except FileNotFoundError:
        return False, "custodian 실행 파일을 찾을 수 없음 (PATH 확인)"
    except subprocess.TimeoutExpired:
        return False, f"custodian 실행이 {CUSTODIAN_TIMEOUT}초를 초과함"

    if proc.returncode != 0:
        # Custodian 은 진행 로그를 stderr 로 내보내므로 뒤쪽 몇 줄만 사유로 담는다
        detail = (proc.stderr or proc.stdout or "").strip()
        tail = " / ".join(detail.splitlines()[-3:]) if detail else "출력 없음"
        return False, f"custodian 종료 코드 {proc.returncode}: {tail}"

    return True, None


def load_dryrun_resources(policy_name):
    """out/<정책이름>/resources.json 을 읽는다.

    반환: (리소스 리스트, 에러메시지)
    """
    path = os.path.join(OUT_DIR, policy_name, "resources.json")
    if not os.path.isfile(path):
        return None, f"결과 파일이 없음: {path}"

    try:
        with open(path, "r", encoding="utf-8") as f:
            resources = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return None, f"결과 파일을 읽지 못함: {e}"

    if not isinstance(resources, list):
        return None, f"결과 파일 형식이 리스트가 아님: {path}"

    return resources, None


def load_dryrun_account_id(policy_name):
    """out/<정책이름>/metadata.json 에서 Custodian 이 실제로 조회한 계정 ID 를 꺼낸다.

    Custodian 은 실행할 때마다 자신이 쓴 자격증명의 계정을 metadata.json 에 남긴다.
    이걸 finding 의 account_uid 와 대조하면, 다른 계정 자격증명으로 실행해 놓고
    "문제 없음"으로 오독하는 사고를 막을 수 있다.

    확인이 불가능하면 None 을 돌려준다(대조를 건너뛴다).
    """
    path = os.path.join(OUT_DIR, policy_name, "metadata.json")
    if not os.path.isfile(path):
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None

    return _dig(metadata, "config.account_id")


def extract_arn(resource):
    """리소스 dict 에서 ARN 을 꺼낸다. BucketArn -> Arn -> arn 순으로 시도."""
    if not isinstance(resource, dict):
        return None
    for field in ARN_FIELDS:
        value = resource.get(field)
        if value:
            return value
    return None


def execute_policies(findings_by_policy):
    """정책별로 Custodian 을 1회씩 실행하고, findings 에 판정 결과를 채운다.

    같은 정책에 걸린 findings 를 묶어 정책당 1회만 실행한다
    (finding 마다 실행하면 같은 조회를 반복하게 되어 비효율).
    """
    print(f"[3/4] Custodian dryrun 실행: 정책 {len(findings_by_policy)}개")

    for policy_name, findings in findings_by_policy.items():
        print(f"  - {policy_name} (finding {len(findings)}건)")

        ok, error = run_custodian(policy_name)
        if not ok:
            print(f"      실패: {error}")
            for finding in findings:
                finding["status"] = "failed"
                finding["reason"] = error
            continue

        resources, error = load_dryrun_resources(policy_name)
        if error:
            print(f"      실패: {error}")
            for finding in findings:
                finding["status"] = "failed"
                finding["reason"] = error
            continue

        arns = [extract_arn(r) for r in resources]
        matched_arns = {a for a in arns if a}
        print(f"      dryrun 대상 리소스 {len(resources)}건 / ARN 확보 {len(matched_arns)}건")

        # Custodian 이 실제로 조회한 계정. finding 의 계정과 다르면 대조가 무의미하다
        scanned_account = load_dryrun_account_id(policy_name)
        if scanned_account is None:
            print("      경고: 조회 계정을 확인하지 못해 계정 대조를 건너뜁니다")
        else:
            print(f"      조회 계정 {scanned_account}")

        # 리소스는 있는데 ARN 을 하나도 못 뽑으면 finding 과 대조할 방법이 없다
        arn_missing = bool(resources) and not matched_arns

        for finding in findings:
            finding_account = finding.get("account_uid")

            # 계정 대조를 먼저 한다. 계정이 다르면 ARN 이 안 맞는 게 당연하므로
            # dryrun_not_matched 로 남기면 "이미 조치됨"으로 오독된다
            if scanned_account and finding_account and finding_account != scanned_account:
                finding["status"] = "account_mismatch"
                finding["reason"] = (
                    f"finding 계정({finding_account})과 custodian 조회 계정"
                    f"({scanned_account})이 다름 - 대조 생략"
                )
                continue

            if arn_missing:
                finding["status"] = "arn_not_found"
                finding["reason"] = (
                    f"dryrun 결과에서 {'/'.join(ARN_FIELDS)} 필드를 찾지 못해 대조 불가"
                )
                continue

            resource_uid = finding.get("resource_uid")
            if not resource_uid:
                finding["status"] = "arn_not_found"
                finding["reason"] = "finding 에 resource_uid 가 없어 대조 불가"
            elif resource_uid in matched_arns:
                finding["status"] = "dryrun_matched"
                finding["reason"] = None
            else:
                finding["status"] = "dryrun_not_matched"
                finding["reason"] = "dryrun 결과에 해당 리소스가 없음"


# ---------------------------------------------------------------------------
# (4) 로그 출력  -- 티켓 #7
# ---------------------------------------------------------------------------

LOG_FIELDS = (
    "finding_uid",
    "check_id",
    "resource_uid",
    "account_uid",
    "region",
    "severity",
    "policy_name",
    "status",
    "reason",
    "executed_at",
)


def build_log_records(findings):
    """조치 로그로 남길 형태로 정리한다."""
    executed_at = datetime.now().isoformat(timespec="seconds")
    records = []
    for finding in findings:
        record = {field: finding.get(field) for field in LOG_FIELDS}
        record["executed_at"] = executed_at
        records.append(record)
    return records


def write_log(records):
    """logs/actions-<타임스탬프>.json 으로 저장하고 경로를 돌려준다."""
    os.makedirs(LOG_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(LOG_DIR, f"actions-{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    return path


def print_summary(records, log_path):
    """콘솔에 status 별 건수를 요약한다."""
    counts = {}
    for record in records:
        status = record.get("status") or "unknown"
        counts[status] = counts.get(status, 0) + 1

    print(f"[4/4] 조치 로그 저장: {log_path}")
    print("")
    print("=== 요약 ===")
    for status in sorted(counts):
        print(f"  {status:22s} {counts[status]:4d}건")
    print(f"  {'합계':20s} {len(records):4d}건")


# ---------------------------------------------------------------------------
# 파이프라인
# ---------------------------------------------------------------------------

def main(argv):
    if len(argv) != 2:
        print(__doc__.strip())
        return 1

    findings_path = argv[1]
    if not os.path.isfile(findings_path):
        print(f"[!] 파일을 찾을 수 없습니다: {findings_path}", file=sys.stderr)
        return 1

    # #1 파싱
    findings = parse_findings(findings_path)
    if not findings:
        print("[*] 처리할 FAIL finding 이 없습니다.")
        return 0

    # #2 매핑 조회 - 실행 대상만 정책별로 묶는다
    mapping = load_mapping()
    findings_by_policy = {}
    for finding in findings:
        policy_name, status, reason = resolve_policy(finding, mapping)
        finding["policy_name"] = policy_name
        finding["status"] = status
        finding["reason"] = reason
        if policy_name:
            findings_by_policy.setdefault(policy_name, []).append(finding)

    skipped = len(findings) - sum(len(v) for v in findings_by_policy.values())
    print(f"      실행 대상 {len(findings) - skipped}건 / 제외 {skipped}건")

    # #6 실행
    if findings_by_policy:
        execute_policies(findings_by_policy)
    else:
        print("[3/4] 실행할 정책이 없어 건너뜁니다.")

    # #7 로그
    records = build_log_records(findings)
    log_path = write_log(records)
    print_summary(records, log_path)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
