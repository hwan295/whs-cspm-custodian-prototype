"""findings 파싱 - 티켓 #1.

입력 구조에 의존하는 곳은 여기뿐이다. 스캔 파트의 데이터 형식이 바뀌면
FIELD_PATHS 만 갈아끼우면 되고, 아래 단계는 평평한 dict 만 본다.
"""

import json


def dig(data, path):
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
    # Prowler 가 체크마다 제공하는 조치 안내. 자동 조치가 불가능한 건을
    # 담당자에게 넘길 때 그대로 쓴다
    "remediation_desc": "remediation.desc",
    "remediation_refs": "remediation.references",
}

# 없어도 파이프라인이 도는 필드. 누락 경고를 띄우지 않는다
OPTIONAL_FIELDS = {"remediation_desc", "remediation_refs"}


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
        value = dig(raw, path)
        parsed[field] = value
        if value is None and field not in OPTIONAL_FIELDS:
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
    return parse_raw_findings(raw_findings)


def parse_raw_findings(raw_findings):
    """이미 읽어들인 finding 리스트를 파싱한다.

    파일이 아니라 DB·API 에서 받은 경우를 위해 파일 읽기와 분리해 둔다.
    """
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
