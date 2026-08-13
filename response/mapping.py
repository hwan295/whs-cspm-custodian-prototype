"""체크-정책 매핑 조회와 조치 방식 판정 - 동작 방식 ③ (README 참고).

Custodian 은 findings 를 입력으로 받지 않고 AWS 를 직접 조회하므로,
두 도구의 유일한 연결점이 mapping.yml 이다.
"""

import yaml

from .config import MAPPING_PATH


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
    # 사람이 직접 조치할 때의 안내. 비워두면 Prowler 의 remediation.desc 를 쓴다
    "guide": None,
    # 범위 제한에 쓸 Custodian 리소스 필드 (예: S3 는 Name, EC2 는 InstanceId).
    # 없으면 범위 제한 없이 계정 전체를 대상으로 돈다
    "scope_key": None,
}

# Custodian 을 실제로 돌리는 mode.
# approve 도 돌린다 - 무엇을 고칠지 보여줘야 사람이 승인 여부를 판단할 수 있다.
# 실행 후 대조까지 마치고 executor 가 프롬프트를 띄운다.
EXECUTABLE_MODES = ("auto", "approve")

# 실행하지 않는 mode 는 여기서 status 가 확정된다
MODE_STATUS = {
    "not_supported": "not_supported",
    "manual": "manual_required",
}


def check_id_to_policy(check_id):
    """Prowler check_id 를 정책 이름으로 바꾼다.

        s3_bucket_kms_encryption  ->  s3-bucket-kms-encryption

    언더바만 하이픈으로 바꾼다. 이 규칙 덕분에 mapping.yml 에서 policy 를
    생략해도 정책을 찾을 수 있고, 이름이 어긋나 매핑이 깨지는 실수가 줄어든다.
    이름이 규칙과 다른 정책은 mapping.yml 에 policy 를 명시하면 된다.
    """
    return check_id.replace("_", "-") if check_id else None


def build_reason(finding, remediation, mode):
    """조치하지 않는 건에 담을 사유를 만든다.

    mode 에 따라 담는 내용이 다르다.
      manual · approve 거부  -> 사람이 무엇을 해야 하는지 (조치 안내)
      그 밖                  -> 왜 자동으로 처리하지 않는지 (판정 근거)

    조치 안내는 mapping.yml 의 guide 를 우선하고, 없으면 Prowler 가 준
    remediation.desc 를 쓴다. 체크마다 이미 안내가 딸려오므로 중복해서 적지 않는다.
    """
    if mode in ("manual", "approve"):
        return (
            remediation.get("guide")
            or finding.get("remediation_desc")
            or remediation.get("risk_note")
            or "조치 방법 안내 없음"
        )
    return remediation.get("risk_note") or f"mode={mode}"


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
    if mode not in EXECUTABLE_MODES:
        status = MODE_STATUS.get(mode)
        if status is None:
            # 알 수 없는 mode 는 실행하지 않는다
            return None, "unmapped", f"알 수 없는 mode: {mode}", remediation
        return None, status, build_reason(finding, remediation, mode), remediation

    # policy 를 적어두면 그걸 쓰고, 없으면 check_id 를 변환해 찾는다.
    # policy: null 을 명시한 경우(조치 도구 없음)와 키를 생략한 경우를 구분한다
    if "policy" in entry:
        policy_name = entry["policy"]
    else:
        policy_name = check_id_to_policy(check_id)

    if not policy_name:
        return None, "unmapped", f"mode={mode} 지만 policy 가 비어 있음", remediation

    return policy_name, None, None, remediation


def group_by_policy(findings, mapping):
    """finding 마다 매핑을 조회해 상태를 채우고, 실행 대상만 정책별로 묶는다.

    반환: {정책이름: [finding, ...]}
    실행 대상이 아닌 건은 이 시점에 status 가 확정되고 묶음에 들어가지 않는다.
    """
    findings_by_policy = {}
    warned_checks = set()   # 같은 체크의 risk_note 를 반복 출력하지 않기 위함

    for finding in findings:
        policy_name, status, reason, remediation = resolve_policy(finding, mapping)
        finding["policy_name"] = policy_name
        finding["status"] = status
        finding["reason"] = reason
        finding["remediation"] = remediation
        if not policy_name:
            continue

        findings_by_policy.setdefault(policy_name, []).append(finding)
        # 자동 조치라도 남아 있는 위험은 실행 전에 눈에 띄게 알린다
        check_id = finding.get("check_id")
        if remediation.get("risk_note") and check_id not in warned_checks:
            warned_checks.add(check_id)
            print(f"      [주의] {check_id}: {remediation['risk_note']}")

    executed = sum(len(v) for v in findings_by_policy.values())
    print(f"      실행 대상 {executed}건 / 제외 {len(findings) - executed}건")
    return findings_by_policy
