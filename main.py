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
# 대상 리소스로 범위를 좁힌 임시 정책을 두는 곳
SCOPED_DIR = os.path.join(OUT_DIR, "_scoped")

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


# remediation 블록이 없거나 값이 빠졌을 때 쓰는 기본값.
# 모르는 조치는 "위험하다"고 보는 쪽이 안전하므로 mode 를 manual 로 둔다.
DEFAULT_REMEDIATION = {
    "mode": "manual",
    "disruption": "recreate",
    "blast_radius": "resource",
    "propagation_delay": "immediate",
    "reversible": False,
    "cost_impact": "none",
    "risk_note": None,
    # 범위 제한에 쓸 Custodian 리소스 필드 (예: S3 는 Name, EC2 는 InstanceId).
    # 없으면 범위 제한 없이 계정 전체를 대상으로 돈다
    "scope_key": None,
}

# mode 별로 실행 전에 확정되는 status.
# auto 만 실제로 Custodian 을 돌리고, 나머지는 여기서 끝난다
MODE_STATUS = {
    "not_supported": "not_supported",
    "manual": "manual_required",
    "approve": "approval_pending",
}


def resolve_policy(finding, mapping):
    """finding 의 check_id 로 정책과 조치 위험도를 찾는다.

    반환: (policy_name, status, reason, remediation)
      - 매핑 없음      -> (None, "unmapped", ...)
      - mode != auto  -> (None, MODE_STATUS[mode], 사유)
      - 정상           -> (정책이름, None, None)

    remediation 은 항상 채워서 돌려준다. 매핑에 없으면 DEFAULT_REMEDIATION 을 쓴다.
    """
    check_id = finding.get("check_id")
    entry = mapping.get(check_id) if check_id else None

    if entry is None:
        return None, "unmapped", f"mapping.yml 에 '{check_id}' 항목이 없음", dict(DEFAULT_REMEDIATION)

    # 빠진 키는 기본값으로 채운다
    remediation = dict(DEFAULT_REMEDIATION)
    remediation.update(entry.get("remediation") or {})

    mode = remediation.get("mode")
    if mode != "auto":
        status = MODE_STATUS.get(mode)
        if status is None:
            # 알 수 없는 mode 는 실행하지 않는다
            return None, "unmapped", f"알 수 없는 mode: {mode}", remediation
        reason = remediation.get("risk_note") or f"mode={mode}"
        return None, status, reason, remediation

    policy_name = entry.get("policy")
    if not policy_name:
        return None, "unmapped", "mode=auto 지만 policy 가 비어 있음", remediation

    return policy_name, None, None, remediation


# ---------------------------------------------------------------------------
# (3) 실행기  -- 티켓 #6
# ---------------------------------------------------------------------------

def policy_file(policy_name):
    """정책 이름에 대응하는 yml 경로."""
    return os.path.join(POLICY_DIR, f"{policy_name}.yml")


def extract_resource_name(arn):
    """ARN 에서 리소스 식별자(마지막 조각)를 뽑는다.

        arn:aws:s3:::miraen3                       -> miraen3
        arn:aws:ec2:ap-…:123:instance/i-0abc       -> i-0abc
    """
    if not arn:
        return None
    tail = arn.split(":")[-1]
    if "/" in tail:
        tail = tail.split("/")[-1]
    return tail or None


def build_scoped_policy(policy_name, findings):
    """findings 의 리소스만 대상으로 하는 임시 정책 파일을 만든다.

    Custodian 은 정책을 계정 전체에 대해 돌린다. 그래서 원본 정책을 그대로 실행하면
    findings 에 없는 리소스까지 대상이 된다. dryrun 동안은 무해하지만, actions 를
    붙이는 순간 **의도하지 않은 리소스까지 고치게 된다.**
    그래서 실행 전에 대상 리소스로 범위를 좁힌다.

    반환: (실행할 정책 경로, 설명) / 실패 시 (None, 에러메시지)
    """
    src = policy_file(policy_name)
    if not os.path.isfile(src):
        return None, f"정책 파일이 없음: {src}"

    remediation = (findings[0].get("remediation") or {}) if findings else {}
    scope_key = remediation.get("scope_key")

    # 계정 단위 체크는 계정 설정 하나를 보는 것이라 리소스 필터를 얹으면 판정이 어긋난다
    if remediation.get("blast_radius") == "account":
        return src, "계정 단위 체크 - 범위 제한 없이 실행"

    if not scope_key:
        return src, "경고: scope_key 가 없어 계정 전체를 대상으로 실행"

    names = sorted({
        n for n in (extract_resource_name(f.get("resource_uid")) for f in findings) if n
    })
    if not names:
        return src, "경고: 대상 리소스 이름을 뽑지 못해 범위 제한 없이 실행"

    try:
        with open(src, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        policies = doc.get("policies") or []
        if not policies:
            return None, f"정책 파일에 policies 가 없음: {src}"

        # 이름 필터를 맨 앞에 둔다. 뒤쪽 필터는 걸러진 리소스에 대해서만 평가된다
        scope_filter = {"type": "value", "key": scope_key, "op": "in", "value": names}
        policies[0]["filters"] = [scope_filter] + list(policies[0].get("filters") or [])

        os.makedirs(SCOPED_DIR, exist_ok=True)
        dst = os.path.join(SCOPED_DIR, f"{policy_name}.yml")
        with open(dst, "w", encoding="utf-8") as f:
            yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False)
    except (OSError, yaml.YAMLError) as e:
        return None, f"범위 제한 정책 생성 실패: {e}"

    return dst, f"대상 {len(names)}건으로 범위 제한 ({scope_key})"


def run_custodian(policy_path, policy_name):
    """Custodian 을 dryrun 으로 1회 실행한다.

    반환: (성공여부, 에러메시지)
    실패해도 예외를 던지지 않는다. 호출부가 다음 정책으로 계속 진행할 수 있어야 한다.
    """
    path = policy_path
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

    순서가 중요하다. **실행 전에 대상 리소스로 범위를 좁히고**, 실행 후의 대조는
    "의도한 대상이 제대로 걸렸는지" 검증하는 용도다.
    범위 제한 없이 실행하면 findings 에 없는 리소스까지 대상이 된다.
    """
    print(f"[3/4] Custodian dryrun 실행: 정책 {len(findings_by_policy)}개")

    for policy_name, findings in findings_by_policy.items():
        print(f"  - {policy_name} (finding {len(findings)}건)")

        # 실행 전에 범위부터 좁힌다
        policy_path, scope_note = build_scoped_policy(policy_name, findings)
        if policy_path is None:
            print(f"      실패: {scope_note}")
            for finding in findings:
                finding["status"] = "failed"
                finding["reason"] = scope_note
            continue
        print(f"      {scope_note}")

        ok, error = run_custodian(policy_path, policy_name)
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
            # already_fixed 로 남기면 "이미 조치됨"으로 오독된다
            if scanned_account and finding_account and finding_account != scanned_account:
                finding["status"] = "account_mismatch"
                finding["reason"] = (
                    f"finding 계정({finding_account})과 custodian 조회 계정"
                    f"({scanned_account})이 다름 - 대조 생략"
                )
                continue

            # 계정 단위 체크는 리소스 ARN 대조가 의미 없다.
            # 계정 설정 하나를 보는 체크에 리소스 단위로 대조하면 판정 단위가 어긋난다
            # (예: s3_account_level_public_access_blocks).
            # 정책에 걸린 리소스가 하나라도 있으면 "계정에 문제가 있다"로 본다
            remediation = finding.get("remediation") or {}
            if remediation.get("blast_radius") == "account":
                if resources:
                    finding["status"] = "still_open"
                    finding["reason"] = f"계정 단위 판정 - 대상 리소스 {len(resources)}건"
                else:
                    finding["status"] = "already_fixed"
                    finding["reason"] = "계정 단위 판정 - 대상 리소스 없음"
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
                finding["status"] = "still_open"
                finding["reason"] = None
            else:
                finding["status"] = "already_fixed"
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

# remediation 에서 로그로 옮겨 담을 항목.
# propagation_delay 는 지금은 기록만 한다 - 조치 후 재확인(#C3)이 붙을 때 쓴다
REMEDIATION_LOG_FIELDS = (
    "mode",
    "disruption",
    "blast_radius",
    "propagation_delay",
    "risk_note",
)


def build_log_records(findings):
    """조치 로그로 남길 형태로 정리한다."""
    executed_at = datetime.now().isoformat(timespec="seconds")
    records = []
    for finding in findings:
        record = {field: finding.get(field) for field in LOG_FIELDS}
        remediation = finding.get("remediation") or {}
        for field in REMEDIATION_LOG_FIELDS:
            record[field] = remediation.get(field)
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
    warned_checks = set()   # 같은 체크의 risk_note 를 반복 출력하지 않기 위함
    for finding in findings:
        policy_name, status, reason, remediation = resolve_policy(finding, mapping)
        finding["policy_name"] = policy_name
        finding["status"] = status
        finding["reason"] = reason
        finding["remediation"] = remediation
        if policy_name:
            findings_by_policy.setdefault(policy_name, []).append(finding)
            # 자동 조치라도 남아 있는 위험은 실행 전에 눈에 띄게 알린다
            check_id = finding.get("check_id")
            if remediation.get("risk_note") and check_id not in warned_checks:
                warned_checks.add(check_id)
                print(f"      [주의] {check_id}: {remediation['risk_note']}")

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
