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

from .executor import dryrun_and_verify, run_custodian, untargeted_arns
from .mapping import group_by_policy, load_mapping
from .reporter import build_log_records
from .policy_meta import load_meta
from .scope import filter_findings, load_scope
from .scoping import build_scoped_policy, extract_scope_value

# 승인 유효 시간. 오래된 승인으로 지금 조치하면 안 된다 -
# 승인할 때 본 상황과 지금이 다를 수 있다.
APPROVAL_TTL_HOURS = 24

# finding 을 식별하는 데 최소한으로 필요한 것
IDENTITY_FIELDS = ("check_id", "resource_uid", "account_uid", "region")

# 한 정책이 한 번에 조치할 수 있는 최대 건수.
#
# 실조치는 되돌리기 어려우므로 **예상보다 많이 걸리면 일단 멈춘다.**
# 승인은 몇 건인 줄 알고 눌렀는데 실행 시점에 대상이 불어났다면 뭔가 잘못된
# 것이다 - 범위 제한이 안 걸렸거나, 계정 단위 체크에 초과분이 섞였거나.
MAX_TARGETS = 10

# 초과 리소스(finding 이 없는데 정책에 걸린 것)를 몇 건까지 눈감아 줄지.
# 계정·리전 단위 체크는 구조상 초과가 생기므로 0 으로 두면 아무것도 못 한다.
MAX_UNTARGETED = 5


def circuit_breaker(policy_name, targets, resources):
    """조치 대상이 예상 범위를 벗어났는지 본다.

    **실행 직전의 마지막 방어선이다.** 범위 제한(④)이 유일한 방어선인데
    계정·리전 단위 체크는 그것을 걸 수 없다. 그때 여기서 멈춘다.

    반환: 중단 사유 / 문제 없으면 None
    """
    if len(targets) > MAX_TARGETS:
        return f"조치 대상 {len(targets)}건 - 한 번에 {MAX_TARGETS}건을 넘어 중단"

    untargeted = untargeted_arns(targets, resources)
    if len(untargeted) > MAX_UNTARGETED:
        return (
            f"finding 이 없는 리소스 {len(untargeted)}건이 함께 조치됨 - "
            f"{MAX_UNTARGETED}건을 넘어 중단"
        )
    return None


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


def rollback_hint(policy_name, finding):
    """되돌리는 명령을 만든다.

    정책의 metadata.auto.rollback_cli 에 템플릿이 있다. 조치가 나간 뒤에
    이걸 보여주지 않으면 **필드가 장식으로 남는다** - 문제가 생겼을 때
    운영자가 정책 파일을 뒤져야 한다.

    템플릿의 {resource_id} · {region} 을 실제 값으로 채운다.
    """
    template = (load_meta(policy_name).get("auto") or {}).get("rollback_cli")
    if not template:
        return None

    scope_key = (finding.get("mapping") or {}).get("scope_key")
    resource_id = extract_scope_value(finding.get("resource_uid"), scope_key)
    try:
        return template.format(
            resource_id=resource_id or "<리소스ID>",
            region=finding.get("region") or "<리전>",
        )
    except (KeyError, IndexError):
        # 템플릿에 우리가 모르는 자리표시자가 있으면 원문 그대로 보여준다
        return template


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


def _confirm(policy_name, findings):
    """조치 후 같은 정책을 다시 돌려 해소됐는지 본다.

    **조치를 내보낸 것과 고쳐진 것은 다르다.** Custodian 이 정상 종료해도
    권한 부족이나 파라미터 오류로 실제 설정이 안 바뀌었을 수 있다.

    정책당 코드가 따로 필요 없다 - 위반을 찾던 그 필터를 다시 돌려서
    안 걸리면 해소된 것이다. 값 비교(before/after)는 못 하지만 해소 여부는
    이걸로 충분하다.

    **반영을 기다리지 않는다.** 정책에 propagation_delay 가 있지만 minutes 단위를
    기다리려면 프로세스를 붙잡아야 해서 쓸 수 없다. 그래서 반영이 느린 조치는
    여기서 still_failing 으로 나올 수 있다 - 비동기 재확인이 붙을 때 해결한다.
    """
    resources = dryrun_and_verify(policy_name, findings)
    if resources is None:
        # 재확인 자체가 실패. 조치는 나갔으므로 상태를 모른다고 남긴다
        for finding in findings:
            finding["status"] = "remediation_unverified"
            finding["reason"] = "조치는 실행됐으나 반영 확인에 실패함"
        return

    for finding in findings:
        if finding.get("status") == "still_open":
            finding["status"] = "still_failing"
            finding["reason"] = "조치를 실행했으나 여전히 위반 상태 - 확인 필요"
        else:
            finding["status"] = "remediated"
            finding["reason"] = "조치 후 재확인에서 해소 확인됨"


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
        resources = dryrun_and_verify(policy_name, group)
        if resources is None:
            continue

        target = [f for f in group if f.get("status") == "still_open"]
        for finding in group:
            if finding.get("status") == "already_fixed":
                finding["status"] = "no_longer_open"
                finding["reason"] = "승인 이후 해소됨 - 조치하지 않음"

        if not target:
            print("      조치할 건이 없습니다 (전부 해소되었거나 대조 불가)")
            continue

        # 실행 직전에 대상 규모를 다시 본다. 승인 시점과 달라졌을 수 있다
        blocked = circuit_breaker(policy_name, target, resources)
        if blocked:
            for finding in target:
                finding["status"] = "blocked"
                finding["reason"] = blocked
            print(f"      [중단] {blocked}")
            continue

        if not apply:
            for finding in target:
                finding["status"] = "ready"
                finding["reason"] = "조치 직전까지 확인됨 - 실조치는 꺼져 있음"
            print(f"      조치 대상 {len(target)}건 (실조치 꺼짐)")
            continue

        ok, error = _apply(policy_name, target)
        if not ok:
            for finding in target:
                finding["status"] = "remediation_failed"
                finding["reason"] = error
            print(f"      조치 실패 {len(target)}건 - {error}")
            continue

        print(f"      조치 실행 {len(target)}건 - 반영 확인 중")
        _confirm(policy_name, target)

        # 되돌리는 방법을 조치 직후에 알린다. 나중에 찾게 하면 늦다
        for finding in target:
            hint = rollback_hint(policy_name, finding)
            if hint:
                finding["rollback_cli"] = hint
        hints = {f["rollback_cli"] for f in target if f.get("rollback_cli")}
        if hints:
            print("      되돌리려면:")
            for hint in sorted(hints):
                print(f"        {hint}")

    return build_log_records(findings)
