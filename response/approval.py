"""승인 프롬프트 - mode=approve 인 건을 사람에게 묻는다.

dryrun 으로 대상을 확인한 뒤에 묻는다. 무엇을 고칠지 보여줘야 판단할 수 있기 때문이다.

물을 때는 다섯 가지를 보여준다.
    무엇이 문제인가   체크 제목 · severity · 위험 설명
    무엇을 할 것인가   정책이 실행할 액션
    왜 확인이 필요한가 risk_note (자동으로 돌리지 않는 이유)
    어느 리소스인가   ARN · 리전 · 리소스별 FAIL 사유
    또 무엇이 바뀌나   finding 이 없는데 정책에 걸린 리소스 (초과 영향)

비대화형(파이프·CI)에서는 묻지 않고 approval_pending 으로 남긴다.
자동 실행 중에 입력을 기다리며 멈추면 안 된다.
"""

import sys

from .scoping import find_policy

# 프롬프트 없이 일괄 처리할 때 쓰는 값. run.py 가 CLI 인자로 설정한다.
#   None  - 물어본다 (기본)
#   True  - 전부 승인
#   False - 전부 거부
AUTO_ANSWER = None


def set_auto_answer(value):
    """--yes / --no 플래그를 반영한다."""
    global AUTO_ANSWER
    AUTO_ANSWER = value


def is_interactive():
    """사람이 답할 수 있는 환경인가."""
    try:
        return sys.stdin.isatty()
    except (AttributeError, ValueError):
        return False


def describe_actions(policy_name):
    """정책이 실행할 액션을 사람이 읽을 수 있게 요약한다.

    승인자가 "무엇을 할 것인지" 알아야 판단할 수 있다.
    이름으로 정확히 찾는다 - 서비스 파일에는 정책이 여러 개 들어 있어서
    첫 정책을 집으면 다른 체크의 액션을 보여주게 된다.
    정책을 찾지 못하면 빈 리스트를 돌려주고 프롬프트에서 생략한다.
    """
    policy, error = find_policy(policy_name)
    if error:
        return []

    actions = policy.get("actions") or []

    summary = []
    for action in actions:
        if isinstance(action, str):
            summary.append(action)
            continue
        if not isinstance(action, dict):
            continue
        name = action.get("type", "?")
        # 액션 이름만으로는 무엇이 바뀌는지 모르니 주요 파라미터를 붙인다
        params = [
            f"{k}={v}" for k, v in action.items()
            if k != "type" and not isinstance(v, (dict, list))
        ]
        summary.append(f"{name}({', '.join(params)})" if params else name)
    return summary


def _print_request(policy_name, findings, untargeted=()):
    """승인 요청 내용을 출력한다.

    untargeted 는 정책에 걸렸지만 finding 이 없는 리소스다. 승인하면 이것들도
    같이 바뀌므로 반드시 보여준다 (아래 _print_untargeted 참고).
    """
    head = findings[0]
    remediation = head.get("remediation") or {}

    print("")
    print("  " + "─" * 66)
    print(f"  승인 요청  ·  {head.get('check_id')}  ({head.get('severity') or '?'})")
    print("  " + "─" * 66)

    title = head.get("title")
    if title:
        print(f"  문제   {title}")

    risk = head.get("risk_details") or head.get("description")
    if risk:
        print(f"         {_trim(risk)}")

    actions = describe_actions(policy_name)
    if actions:
        print(f"  조치   {'; '.join(actions)}")
    else:
        print(f"  조치   정책 {policy_name} 실행")

    note = remediation.get("risk_note")
    if note:
        print(f"  주의   {note}")

    disruption = remediation.get("disruption")
    blast = remediation.get("blast_radius")
    if disruption or blast:
        print(f"  영향   중단={disruption or '?'} · 범위={blast or '?'}")

    print("")
    _print_untargeted(untargeted)
    print(f"  대상 {len(findings)}건 - 건별로 확인합니다")
    print("")


# 초과 리소스를 몇 개까지 나열할지. 넘으면 건수만 알린다
UNTARGETED_PREVIEW = 10


def _print_untargeted(untargeted):
    """finding 이 없는데 정책에 걸린 리소스를 경고로 보여준다.

    **승인 화면이 영향 범위를 축소해서 말하면 안 된다.** Custodian 은 필터에 걸린
    리소스를 전부 조치하므로, 여기 나온 것들도 승인과 함께 바뀐다.

    주로 계정 단위 체크에서 생긴다. 계정 설정 하나를 보는 체크라 범위 제한을
    걸 수 없고, 그래서 계정의 리소스가 전부 걸린다.
    scope_key 를 빠뜨린 경우에도 나온다 - 그때는 매핑을 고쳐야 한다.
    """
    if not untargeted:
        return

    print(f"  [경고] finding 이 없는 리소스 {len(untargeted)}건도 함께 조치됩니다")
    for arn in untargeted[:UNTARGETED_PREVIEW]:
        print(f"         · {arn}")
    if len(untargeted) > UNTARGETED_PREVIEW:
        print(f"         · ... 외 {len(untargeted) - UNTARGETED_PREVIEW}건")
    print("")


def _trim(text, limit=160):
    """긴 설명을 한 줄로 줄인다."""
    flat = " ".join(str(text).split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def confirm_each(policy_name, findings, untargeted=()):
    """리소스 하나씩 조치 여부를 묻는다.

    **건별로 묻는 이유** - 같은 체크에 걸렸어도 리소스마다 사정이 다르다.
    한 버킷은 고쳐도 되지만 다른 버킷은 정적 웹사이트를 호스팅 중일 수 있다.
    실조치는 되돌릴 수 없으므로 한 번의 y 로 전부 나가면 안 된다.

    a(나머지 전부 승인) · q(나머지 전부 거부)로 일괄 처리할 수 있다.

    untargeted 는 정책에 걸렸지만 finding 이 없는 리소스의 ARN 이다.
    묻지 않는 경로(플래그·비대화형)에서도 반드시 알린다 - 조용히 넘어가면
    영향 범위를 모른 채 승인되기 때문이다.

    반환: {"approved": [...], "declined": [...], "pending": [...]}
    """
    result = {"approved": [], "declined": [], "pending": []}

    if AUTO_ANSWER is not None:
        label = "승인" if AUTO_ANSWER else "거부"
        print(f"      [{policy_name}] 대상 {len(findings)}건 - 플래그로 일괄 {label}")
        if AUTO_ANSWER:
            _print_untargeted(untargeted)
        result["approved" if AUTO_ANSWER else "declined"] = list(findings)
        return result

    if not is_interactive():
        print(f"      [{policy_name}] 대상 {len(findings)}건 - 비대화형이라 승인 보류")
        _print_untargeted(untargeted)
        result["pending"] = list(findings)
        return result

    _print_request(policy_name, findings, untargeted)

    bulk = None          # a / q 를 누르면 나머지를 여기에 담아 처리한다
    total = len(findings)

    for index, finding in enumerate(findings, 1):
        region = finding.get("region") or "-"
        print(f"  [{index}/{total}] {finding.get('resource_uid')}  [{region}]")
        detail = finding.get("status_detail")
        if detail:
            print(f"          {_trim(detail, 100)}")

        if bulk is not None:
            result["approved" if bulk else "declined"].append(finding)
            print(f"          → 일괄 {'승인' if bulk else '거부'}")
            continue

        try:
            answer = input("          조치할까요? (y/n, a=나머지 모두 승인, q=나머지 모두 거부) ")
        except (EOFError, KeyboardInterrupt):
            print("")
            print("      입력이 중단되어 남은 건을 보류합니다")
            result["pending"].extend(findings[index - 1:])
            return result

        answer = answer.strip().lower()
        if answer in ("a", "all"):
            bulk = True
            result["approved"].append(finding)
        elif answer in ("q", "quit"):
            bulk = False
            result["declined"].append(finding)
        elif answer in ("y", "yes"):
            result["approved"].append(finding)
        else:
            result["declined"].append(finding)

    print("")
    return result


def print_guidance(findings):
    """거부했을 때 조치 방법을 출력한다."""
    for finding in findings:
        print(f"     · {finding.get('resource_uid')}")
        if finding.get("reason"):
            print(f"       {_trim(finding['reason'])}")
        for ref in finding.get("remediation_refs") or []:
            print(f"       참고: {ref}")
