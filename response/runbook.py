"""사람이 직접 조치할 때의 안내 - runbook.yml 조회.

Custodian 으로 조치할 수 없는 건(mode=manual)은 담당자가 콘솔이나 CLI 에서
직접 처리해야 한다. 그때 "무엇을 어떻게 하라"를 담는 곳이 runbook.yml 이다.

Prowler 도 remediation.desc 로 안내를 주지만 영문 원문이고 우리 환경 사정을
담지 못한다. runbook 이 있으면 그것을 우선하고, 없으면 Prowler 안내로 넘어간다.

mapping.yml 이 runbook 키를 가리키고, 실제 내용은 여기 있다.

    mapping.yml   iam_root_mfa_enabled:
                    mode: manual
                    runbook: iam_root_mfa_enabled

    runbook.yml   iam_root_mfa_enabled:
                    method: console | cli_or_console | guide
                    description: 무엇을 왜 해야 하는가
                    command_template: 복붙할 CLI (없으면 null)
                    console_steps: 콘솔 절차 목록
                    docs_url: 참고 문서
"""

import os

import yaml

from .config import RUNBOOK_PATH

# 콘솔 절차를 콘솔 출력에 몇 줄까지 보여줄지. 전문은 로그 레코드에 담긴다
CONSOLE_STEP_PREVIEW = 5

_cache = None


def load_runbooks(path=RUNBOOK_PATH):
    """runbook.yml 을 읽는다. 한 번 읽고 재사용한다.

    파일이 없어도 실행을 막지 않는다. 안내가 빠질 뿐 판정은 그대로 된다.
    """
    global _cache
    if _cache is not None:
        return _cache

    if not os.path.isfile(path):
        print(f"[!] runbook 파일이 없어 조치 안내를 건너뜁니다: {path}")
        _cache = {}
        return _cache

    try:
        with open(path, "r", encoding="utf-8") as f:
            _cache = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        print(f"[!] runbook 파일을 읽지 못했습니다: {e}")
        _cache = {}
    return _cache


def find(runbook_key):
    """runbook 항목 하나를 꺼낸다. 없으면 None."""
    if not runbook_key:
        return None
    entry = load_runbooks().get(runbook_key)
    return entry if isinstance(entry, dict) else None


def format_guide(entry):
    """runbook 을 사람이 읽을 한 덩어리 문자열로 만든다.

    로그의 reason 에 들어가므로 줄바꿈으로 이어 붙인다. 웹 화면은 원본
    구조가 필요하므로 as_record() 를 따로 쓴다.
    """
    if not entry:
        return None

    parts = []
    if entry.get("description"):
        parts.append(" ".join(str(entry["description"]).split()))

    command = entry.get("command_template")
    if command:
        parts.append(f"CLI: {command}")

    steps = entry.get("console_steps") or []
    if steps:
        shown = [f"{i}. {s}" for i, s in enumerate(steps[:CONSOLE_STEP_PREVIEW], 1)]
        if len(steps) > CONSOLE_STEP_PREVIEW:
            shown.append(f"... 외 {len(steps) - CONSOLE_STEP_PREVIEW}단계")
        parts.append("콘솔: " + " / ".join(shown))

    if entry.get("docs_url"):
        parts.append(f"문서: {entry['docs_url']}")

    return "\n".join(parts) or None


def as_record(entry):
    """웹 화면이 쓸 수 있도록 구조를 그대로 넘긴다.

    조치 안내를 화면에 그리려면 CLI 와 콘솔 절차가 분리돼 있어야 한다.
    reason 에 뭉쳐 넣은 문자열로는 버튼이나 복사 영역을 만들 수 없다.
    """
    if not entry:
        return None
    return {
        "method": entry.get("method"),
        "description": entry.get("description"),
        "command_template": entry.get("command_template"),
        "console_steps": entry.get("console_steps") or [],
        "docs_url": entry.get("docs_url"),
    }
