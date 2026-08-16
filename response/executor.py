"""Custodian 실행과 결과 대조 - 동작 방식 ⑤⑥ (README 참고).

이 모듈이 유일하게 AWS 와 통신하는 곳이고, 실조치를 켜면 되돌릴 수 없는 변경이
나가는 통로다. 순서가 중요하다.

    범위 제한(scoping) -> 실행 -> 대조

대조는 "어느 게 내 대상인가"를 고르는 게 아니라
**"의도한 대상이 제대로 걸렸는지" 검증**하는 용도다.
"""

import json
import os
import subprocess

from .approval import confirm_each, print_guidance
from .config import ARN_FIELDS, CUSTODIAN_TIMEOUT, OUT_DIR, WORK_DIR
from .findings import dig
from .mapping import build_reason
from .optin import is_opted_in
from .policy_meta import is_account_scoped
from .scoping import build_scoped_policy


def run_custodian(policy_path, dry_run=True):
    """Custodian 을 1회 실행한다.

    dry_run=False 로 부르면 **실제로 AWS 리소스가 바뀐다.**
    지금은 호출부가 항상 True 를 넘긴다. 실조치를 켜려면 이 인자만 바꾸면 되지만,
    조치 전 스냅샷과 롤백이 붙기 전에는 False 로 부르지 않는다.

    반환: (성공여부, 에러메시지)
    실패해도 예외를 던지지 않는다. 호출부가 다음 정책으로 계속 진행할 수 있어야 한다.
    """
    if not os.path.isfile(policy_path):
        return False, f"정책 파일이 없음: {policy_path}"

    cmd = ["custodian", "run", "-s", OUT_DIR, policy_path]
    if dry_run:
        cmd.append("--dryrun")
    print(f"      실행: {' '.join(cmd)}")

    try:
        proc = subprocess.run(
            cmd,
            cwd=WORK_DIR,
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

    return dig(metadata, "config.account_id")


def extract_arn(resource):
    """리소스 dict 에서 ARN 을 꺼낸다. BucketArn -> Arn -> arn 순으로 시도."""
    if not isinstance(resource, dict):
        return None
    for field in ARN_FIELDS:
        value = resource.get(field)
        if value:
            return value
    return None


def _mark_all(findings, status, reason):
    """묶음 전체를 같은 상태로 확정한다. 실행 자체가 실패했을 때 쓴다."""
    for finding in findings:
        finding["status"] = status
        finding["reason"] = reason


def verify_findings(findings, resources, scanned_account):
    """실행 결과와 finding 을 대조해 판정을 채운다.

    순서가 중요하다. 앞의 조건이 걸리면 뒤는 보지 않는다.
      1. 계정이 다름        -> account_mismatch
      2. 계정 단위 체크      -> 리소스 유무로 판정
      3. ARN 을 못 뽑음     -> arn_not_found
      4. ARN 일치 여부      -> still_open / already_fixed
    """
    arns = [extract_arn(r) for r in resources]
    matched_arns = {a for a in arns if a}
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

        # 계정·리전 단위 체크는 리소스 ARN 대조가 의미 없다.
        # 설정 하나를 보는 체크에 리소스 단위로 대조하면 판정 단위가 어긋난다
        # (예: s3_account_level_public_access_blocks, ec2_ebs_default_encryption).
        # 정책에 걸린 리소스가 하나라도 있으면 "설정에 문제가 있다"로 본다
        approve = (finding.get("policy_meta") or {}).get("approve") or {}
        if is_account_scoped(approve):
            unit = approve.get("blast_radius")
            if resources:
                finding["status"] = "still_open"
                finding["reason"] = f"{unit} 단위 판정 - 대상 리소스 {len(resources)}건"
            else:
                finding["status"] = "already_fixed"
                finding["reason"] = f"{unit} 단위 판정 - 대상 리소스 없음"
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


def execute_policies(findings_by_policy):
    """정책별로 Custodian 을 1회씩 실행하고, findings 에 판정 결과를 채운다.

    같은 정책에 걸린 findings 를 묶어 정책당 1회만 실행한다
    (finding 마다 실행하면 같은 조회를 반복하게 되어 비효율).
    """
    print(f"[3/4] Custodian dryrun 실행: 정책 {len(findings_by_policy)}개")

    for policy_name, findings in findings_by_policy.items():
        print(f"  - {policy_name} (finding {len(findings)}건)")
        resources = dryrun_and_verify(policy_name, findings)
        if resources is None:
            continue
        request_approval(policy_name, findings, resources)


def dryrun_and_verify(policy_name, findings):
    """범위 제한 -> dryrun -> 대조. 판정 결과를 findings 에 채운다.

    승인 전(execute_policies)과 조치 직전(remediation) 양쪽에서 쓴다.
    **조치 직전에 한 번 더 도는 것이 중요하다.** 승인은 과거 시점의 판단이고
    조치는 지금 나가므로, 그 사이에 이미 해소됐을 수 있다.

    반환: dryrun 결과 리소스 리스트 / 실패하면 None (findings 는 failed 로 확정)
    """
    policy_path, scope_note = build_scoped_policy(policy_name, findings)
    if policy_path is None:
        print(f"      실패: {scope_note}")
        _mark_all(findings, "failed", scope_note)
        return None
    print(f"      {scope_note}")

    ok, error = run_custodian(policy_path)
    if not ok:
        print(f"      실패: {error}")
        _mark_all(findings, "failed", error)
        return None

    resources, error = load_dryrun_resources(policy_name)
    if error:
        print(f"      실패: {error}")
        _mark_all(findings, "failed", error)
        return None

    matched = len({a for a in (extract_arn(r) for r in resources) if a})
    print(f"      dryrun 대상 리소스 {len(resources)}건 / ARN 확보 {matched}건")

    # Custodian 이 실제로 조회한 계정. finding 의 계정과 다르면 대조가 무의미하다
    scanned_account = load_dryrun_account_id(policy_name)
    if scanned_account is None:
        print("      경고: 조회 계정을 확인하지 못해 계정 대조를 건너뜁니다")
    else:
        print(f"      조회 계정 {scanned_account}")

    verify_findings(findings, resources, scanned_account)
    return resources


def untargeted_arns(findings, resources):
    """정책에 걸렸지만 finding 이 없는 리소스의 ARN 을 추린다.

    범위 제한이 걸리면 보통 비어 있다. 비어 있지 않다는 것은 정책이 우리가
    요청하지 않은 리소스까지 대상으로 삼았다는 뜻이고, 실조치를 켜면
    **그것들도 함께 바뀐다.** 승인 화면에 반드시 노출해야 한다.

    계정 단위 체크에서는 정상적으로 발생한다 (범위 제한을 걸 수 없으므로).
    """
    targeted = {f.get("resource_uid") for f in findings if f.get("resource_uid")}
    found = {a for a in (extract_arn(r) for r in resources) if a}
    return sorted(found - targeted)


def request_approval(policy_name, findings, resources):
    """mode=approve 인 건에 대해 승인을 묻고 결과를 status 에 반영한다.

    still_open 인 건만 묻는다. 이미 해소됐거나 대조가 안 된 건은 물을 이유가 없다.

    승인(approved)해도 지금은 AWS 가 바뀌지 않는다. dryrun 으로만 돌기 때문이다.
    실조치를 켜면 이 지점에서 run_custodian(dry_run=False) 를 한 번 더 부르게 된다.
    """
    mode = (findings[0].get("mapping") or {}).get("mode") if findings else None
    if mode != "approve":
        return

    pending = [f for f in findings if f.get("status") == "still_open"]
    if not pending:
        return

    # 사용자가 이 체크의 자동 실행을 켜 두었으면 묻지 않는다.
    # 지금은 optin 이 항상 False 라 이 가지로 들어오지 않는다 (optin.py 참고)
    head = pending[0]
    if is_opted_in(head.get("account_uid"), head.get("check_id")):
        for finding in pending:
            finding["status"] = "auto_approved"
            finding["reason"] = "사용자가 자동 실행을 켜 둔 체크 - 승인 생략"
        print(f"      자동 실행 {len(pending)}건 (opt-in)")
        return

    result = confirm_each(policy_name, pending, untargeted_arns(pending, resources))

    for finding in result["approved"]:
        finding["status"] = "approved"
        finding["reason"] = "승인됨 - dryrun 이라 실제 변경은 없음"

    for finding in result["pending"]:
        finding["status"] = "approval_pending"
        finding["reason"] = "승인 대기 - 물을 수 없어 보류"

    # 거부 - 사람이 직접 조치할 수 있도록 안내를 남긴다
    for finding in result["declined"]:
        finding["status"] = "declined"
        finding["reason"] = build_reason(finding, finding.get("mapping") or {}, "approve")

    if result["approved"]:
        print(f"      승인 {len(result['approved'])}건 (dryrun 이므로 실제 변경 없음)")
    if result["declined"]:
        print(f"      거부 {len(result['declined'])}건 - 조치 방법:")
        print_guidance(result["declined"])
