"""승인된 건을 실제로 조치한다 - Phase 2.

파이프라인이 둘로 나뉘는 이유는 **승인이 비동기이기 때문**이다.
CLI 는 그 자리에서 물어보지만, 웹은 실행이 끝난 뒤 사람이 나중에 누른다.

    Phase 1 (run)         파싱 -> 매핑 -> 범위 제한 -> dryrun -> 대조
                          -> approve 건은 approval_pending 으로 남기고 종료
    Phase 2 (remediate)   승인된 건만 받아 다시 검증하고 조치

**조치 전에 dryrun 을 한 번 더 돈다.** 승인은 과거 시점의 판단이고 조치는
지금 나간다. 그 사이에 누가 이미 고쳤을 수 있고, 그때 조치를 또 내보내면
안 된다. 승인 시점의 판정을 그대로 믿지 않는 것이 이 모듈의 핵심이다.

입력은 "무엇을 승인했는지"만 있으면 된다. 나머지(정책·위험도·범위)는 조치
시점에 다시 읽는다. 승인 이후 매핑이나 정책이 바뀌었을 수 있기 때문이다.

    remediate([{"check_id": ..., "resource_uid": ..., "account_uid": ...,
                "approved_at": "2026-08-16T11:00:00", "approved_by": "..."}])

주의: apply=False 가 기본이라 **실제 조치는 나가지 않는다.** 조치 직전까지만
가고 ready 로 남긴다. 켜려면 호출부가 apply=True 를 넘겨야 한다.
"""

from datetime import datetime, timedelta

from .executor import dryrun_and_verify, run_custodian
from .mapping import group_by_policy, load_mapping
from .reporter import build_log_records
from .scope import filter_findings, load_scope
from .scoping import build_scoped_policy

# 승인 유효 시간. 오래된 승인으로 지금 조치하면 안 된다 -
# 승인할 때 본 상황과 지금이 다를 수 있다.
APPROVAL_TTL_HOURS = 24

# finding 을 식별하는 데 최소한으로 필요한 것
IDENTITY_FIELDS = ("check_id", "resource_uid", "account_uid", "region")


def _to_finding(approval):
    """승인 레코드를 finding 형태로 되살린다.

    로그 레코드를 그대로 넘겨도 되고, 식별 필드만 담은 dict 를 넘겨도 된다.
    조치에 필요한 정보는 여기서 다시 읽으므로 승인 쪽에서 보낼 필요가 없다.
    """
    finding = {field: approval.get(field) for field in IDENTITY_FIELDS}
    # 안내 문구는 거부·실패 시 그대로 보여주므로 있으면 가져온다
    for field in ("finding_uid", "severity", "remediation_desc", "remediation_refs"):
        finding[field] = approval.get(field)
    finding["approved_at"] = approval.get("approved_at")
    finding["approved_by"] = approval.get("approved_by")
    return finding


def _expired(finding, ttl_hours):
    """승인이 유효 시간을 넘겼는가. 시각이 없으면 만료로 보지 않는다."""
    stamp = finding.get("approved_at")
    if not stamp:
        return False
    try:
        approved = datetime.fromisoformat(str(stamp))
    except ValueError:
        return False
    return datetime.now() - approved > timedelta(hours=ttl_hours)


def _apply(policy_name, findings):
    """실조치를 내보낸다. **여기서 AWS 가 실제로 바뀐다.**

    범위 제한 정책을 다시 만들어 쓴다. 직전 dryrun 에서 만든 것과 같지만,
    still_open 인 건만 남은 좁은 대상으로 다시 좁히기 위해서다.
    """
    policy_path, note = build_scoped_policy(policy_name, findings)
    if policy_path is None:
        return False, note
    print(f"      조치 대상 좁힘: {note}")
    return run_custodian(policy_path, dry_run=False)


def remediate(approvals, apply=False, ttl_hours=APPROVAL_TTL_HOURS):
    """승인된 건을 다시 검증하고 조치한다.

    apply=False (기본) 면 조치 직전까지만 가고 status=ready 로 남긴다.
    조치 전 스냅샷과 롤백이 붙기 전에는 True 로 부르지 않는다.

    반환: 조치 로그 레코드 리스트
    """
    if not approvals:
        return []

    findings = [_to_finding(a) for a in approvals]
    print(f"[조치 1/3] 승인 건 {len(findings)}건 접수")

    # 만료된 승인은 조치하지 않는다. 승인할 때 본 상황과 지금이 다를 수 있다
    live = []
    for finding in findings:
        if _expired(finding, ttl_hours):
            finding["status"] = "expired"
            finding["reason"] = f"승인 후 {ttl_hours}시간이 지나 다시 승인이 필요함"
        else:
            live.append(finding)
    if len(live) != len(findings):
        print(f"      만료 {len(findings) - len(live)}건 제외")

    # 승인 이후 대상 범위가 바뀌었을 수 있으므로 다시 거른다
    live = filter_findings(live, load_scope())

    print("[조치 2/3] 매핑 재조회")
    findings_by_policy = group_by_policy(live, load_mapping())

    print(f"[조치 3/3] 조치 전 재검증: 정책 {len(findings_by_policy)}개")
    for policy_name, group in findings_by_policy.items():
        print(f"  - {policy_name} (승인 {len(group)}건)")

        # 승인 시점의 판정을 믿지 않고 지금 상태를 다시 본다
        if dryrun_and_verify(policy_name, group) is None:
            continue

        target = [f for f in group if f.get("status") == "still_open"]
        for finding in group:
            if finding.get("status") == "already_fixed":
                finding["status"] = "no_longer_open"
                finding["reason"] = "승인 이후 해소됨 - 조치하지 않음"

        if not target:
            print("      조치할 건이 없습니다 (전부 해소되었거나 대조 불가)")
            continue

        if not apply:
            for finding in target:
                finding["status"] = "ready"
                finding["reason"] = "조치 직전까지 확인됨 - 실조치는 꺼져 있음"
            print(f"      조치 대상 {len(target)}건 (실조치 꺼짐)")
            continue

        ok, error = _apply(policy_name, target)
        for finding in target:
            finding["status"] = "remediated" if ok else "remediation_failed"
            finding["reason"] = None if ok else error
        print(f"      {'조치 완료' if ok else '조치 실패'} {len(target)}건")
        if not ok:
            print(f"      사유: {error}")

    return build_log_records(findings)
