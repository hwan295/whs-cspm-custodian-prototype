"""승인 프롬프트 - mode=approve 인 건을 사람에게 묻는다.

dryrun 으로 대상을 확인한 뒤에 묻는다. 무엇을 고칠지 보여줘야 판단할 수 있기 때문이다.

비대화형(파이프·CI)에서는 묻지 않고 approval_pending 으로 남긴다.
자동 실행 중에 입력을 기다리며 멈추면 안 된다.
"""

import sys

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


def confirm(policy_name, findings):
    """조치 여부를 묻는다.

    반환: True(승인) / False(거부) / None(물을 수 없어 보류)
    """
    if AUTO_ANSWER is not None:
        answer = "승인" if AUTO_ANSWER else "거부"
        print(f"      [{policy_name}] 대상 {len(findings)}건 - 플래그로 일괄 {answer}")
        return AUTO_ANSWER

    if not is_interactive():
        print(f"      [{policy_name}] 대상 {len(findings)}건 - 비대화형이라 승인 보류")
        return None

    print("")
    print(f"  ── 승인 요청: {policy_name} ──")
    for finding in findings:
        print(f"     · {finding.get('resource_uid')}")
    risk = (findings[0].get("remediation") or {}).get("risk_note")
    if risk:
        print(f"     주의: {risk}")

    try:
        answer = input(f"  {len(findings)}건을 조치하시겠습니까? (y/N) ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("")
        print("      입력이 중단되어 승인을 보류합니다")
        return None

    return answer in ("y", "yes")


def print_guidance(findings):
    """거부했을 때 조치 방법을 출력한다."""
    for finding in findings:
        print(f"     · {finding.get('resource_uid')}")
        if finding.get("reason"):
            print(f"       {finding['reason']}")
        for ref in finding.get("remediation_refs") or []:
            print(f"       참고: {ref}")
