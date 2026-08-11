"""체크-정책 매핑 조회와 조치 방식 판정 - 티켓 #2.

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

# mode 별로 실행 전에 확정되는 status.
# auto 만 실제로 Custodian 을 돌리고, 나머지는 여기서 끝난다
MODE_STATUS = {
    "not_supported": "not_supported",
    "manual": "manual_required",
    "approve": "approval_pending",
}


def build_reason(finding, remediation, mode):
    """실행하지 않는 건에 담을 사유를 만든다.

    mode 에 따라 담는 내용이 다르다.
      manual        -> 사람이 무엇을 해야 하는지 (조치 안내)
      그 밖         -> 왜 자동으로 처리하지 않는지 (판정 근거)

    조치 안내는 mapping.yml 의 guide 를 우선하고, 없으면 Prowler 가 준
    remediation.desc 를 쓴다. 체크마다 이미 안내가 딸려오므로 중복해서 적지 않는다.
    """
    if mode == "manual":
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
    if mode != "auto":
        status = MODE_STATUS.get(mode)
        if status is None:
            # 알 수 없는 mode 는 실행하지 않는다
            return None, "unmapped", f"알 수 없는 mode: {mode}", remediation
        return None, status, build_reason(finding, remediation, mode), remediation

    policy_name = entry.get("policy")
    if not policy_name:
        return None, "unmapped", "mode=auto 지만 policy 가 비어 있음", remediation

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
