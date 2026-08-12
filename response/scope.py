"""조치 대상 범위 필터 - 티켓 #4.

**실행 전에** 대상이 아닌 finding 을 걸러낸다. 실행 후의 계정 대조
(executor 의 account_mismatch)와 역할이 다르다.

    범위 필터   사전 - "애초에 우리가 건드릴 계정이 아니다"
    계정 대조   사후 - "돌려보니 자격증명이 다른 계정이었다"

둘 다 남긴다. 앞은 의도한 범위만 건드린다는 보장이고, 뒤는 자격증명이 잘못됐을 때의
안전망이다.

계정 ID 는 코드에 하드코딩하지 않는다. 환경변수 → scope.yml → scope.example.yml
순으로 읽고, 실제 값이 든 scope.yml 은 git 에서 제외한다.
"""

import os

import yaml

from .config import SCOPE_EXAMPLE_PATH, SCOPE_PATH

ENV_ACCOUNTS = "CSPM_SCOPE_ACCOUNTS"
ENV_REGIONS = "CSPM_SCOPE_REGIONS"


def _split_env(name):
    """쉼표로 구분된 환경변수를 리스트로. 없으면 None."""
    raw = os.environ.get(name)
    if not raw:
        return None
    return [v.strip() for v in raw.split(",") if v.strip()]


def load_scope():
    """대상 범위를 읽는다.

    우선순위: 환경변수 > scope.yml > scope.example.yml
    어느 출처를 썼는지 출력한다. 예시 파일의 더미 계정으로 도는 사고를 막기 위함이다.

    반환: {"accounts": [...], "regions": [...], "source": "..."}
    """
    env_accounts = _split_env(ENV_ACCOUNTS)
    env_regions = _split_env(ENV_REGIONS)
    if env_accounts or env_regions:
        scope = {
            "accounts": env_accounts or [],
            "regions": env_regions or [],
            "source": "환경변수",
        }
        _print_scope(scope)
        return scope

    for path, label in ((SCOPE_PATH, "scope.yml"), (SCOPE_EXAMPLE_PATH, "scope.example.yml")):
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                doc = yaml.safe_load(f) or {}
        except (OSError, yaml.YAMLError) as e:
            print(f"[!] {label} 을 읽지 못했습니다: {e}")
            continue

        scope = {
            "accounts": [str(a) for a in (doc.get("accounts") or [])],
            "regions": list(doc.get("regions") or []),
            "source": label,
        }
        if label == "scope.example.yml":
            print("[!] scope.yml 이 없어 예시 파일로 실행합니다. 더미 계정이라 전부 제외될 수 있습니다.")
        _print_scope(scope)
        return scope

    print("[!] 범위 설정이 없어 전체를 대상으로 합니다 (scope.yml 또는 환경변수 필요)")
    return {"accounts": [], "regions": [], "source": "없음"}


def _print_scope(scope):
    accounts = ", ".join(scope["accounts"]) or "제한 없음"
    regions = ", ".join(scope["regions"]) or "제한 없음"
    print(f"      범위 [{scope['source']}] 계정 {accounts} / 리전 {regions}")


def in_scope(finding, scope):
    """finding 이 조치 대상 범위 안에 있는지 본다.

    반환: (통과 여부, 제외 사유)
    목록이 비어 있는 항목은 검사하지 않는다.
    """
    accounts = scope.get("accounts") or []
    if accounts and finding.get("account_uid") not in accounts:
        return False, f"대상 계정이 아님 ({finding.get('account_uid')})"

    regions = scope.get("regions") or []
    if regions and finding.get("region") not in regions:
        return False, f"대상 리전이 아님 ({finding.get('region')})"

    return True, None


def filter_findings(findings, scope):
    """범위 밖 finding 에 status 를 채우고, 대상만 골라 돌려준다.

    제외된 건도 로그에는 남아야 하므로 원본 리스트에서 지우지 않고 status 만 채운다.
    """
    kept = []
    for finding in findings:
        ok, reason = in_scope(finding, scope)
        if ok:
            kept.append(finding)
        else:
            finding["status"] = "out_of_scope"
            finding["reason"] = reason

    excluded = len(findings) - len(kept)
    if excluded:
        print(f"      범위 밖 {excluded}건 제외")
    return kept
