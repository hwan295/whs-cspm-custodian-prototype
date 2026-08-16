"""조치 로그 생성과 출력 - 동작 방식 ⑧ (README 참고).

다음 파트(⑤ 분석·리포팅)가 소비하는 산출물이라 필드 구성이 곧 계약이다.
통합 시 remediation_runs 테이블로 들어간다.

레코드는 세 곳에서 모인다.
    finding       무엇이 문제였나 (Prowler 가 준 것)
    mapping.yml   어디로 보냈나 (mode · 정책 이름)
    policies/*.yml 조치가 어떤 성질인가 (metadata.approve) ·
                  자동화할 수 있나 (metadata.auto)
"""

import json
import os
from datetime import datetime

from .config import LOG_DIR

# finding 에서 그대로 옮기는 항목
LOG_FIELDS = (
    "finding_uid",
    "check_id",
    "resource_uid",
    "account_uid",
    "region",
    "severity",
    "policy_name",
    "status",
    "reason",
    "remediation_refs",
)

# 정책의 metadata.approve 에서 옮겨 담을 항목.
# 조치의 "위험도"를 리포팅 파트에 그대로 넘긴다. 어느 것을 먼저 처리할지,
# 승인 화면에 무엇을 보여줄지는 그쪽에서 판단해야 하기 때문이다.
# propagation_delay 는 지금은 기록만 한다 - 조치 후 재확인 기능이 붙을 때 쓴다
APPROVE_LOG_FIELDS = (
    "disruption",
    "blast_radius",
    "propagation_delay",
    "reversible",
    "cost_impact",
)

# mapping.yml 에서 옮겨 담을 항목.
# 판정에 대한 서술이라 mode 와 같은 파일에 있다. mode 가 manual / not_supported 면
# 정책 파일이 아예 없으므로 여기 말고는 둘 데가 없다
MAPPING_LOG_FIELDS = (
    "mode",
    "risk_note",
    "auto_eligible",
    "auto_reason",
)


def build_log_records(findings):
    """조치 로그로 남길 형태로 정리한다.

    auto_eligible 은 대시보드가 "자동화 가능" 열을 그리는 데 쓴다.
    사용자가 opt-in 할 수 있는 후보를 여기서 알려주는 셈이다.
    """
    executed_at = datetime.now().isoformat(timespec="seconds")
    records = []
    for finding in findings:
        record = {field: finding.get(field) for field in LOG_FIELDS}

        entry = finding.get("mapping") or {}
        for field in MAPPING_LOG_FIELDS:
            record[field] = entry.get(field)

        meta = finding.get("policy_meta") or {}
        approve = meta.get("approve") or {}
        for field in APPROVE_LOG_FIELDS:
            record[field] = approve.get(field)

        record["executed_at"] = executed_at
        records.append(record)
    return records


def write_log(records):
    """logs/actions-<타임스탬프>.json 으로 저장하고 경로를 돌려준다."""
    os.makedirs(LOG_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(LOG_DIR, f"actions-{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)
    return path


def print_summary(records, log_path=None):
    """콘솔에 status 별 건수를 요약한다."""
    counts = {}
    for record in records:
        status = record.get("status") or "unknown"
        counts[status] = counts.get(status, 0) + 1

    if log_path:
        print(f"[4/4] 조치 로그 저장: {log_path}")
    print("")
    print("=== 요약 ===")
    for status in sorted(counts):
        print(f"  {status:22s} {counts[status]:4d}건")
    print(f"  {'합계':20s} {len(records):4d}건")

    eligible = sum(1 for r in records if r.get("auto_eligible"))
    if eligible:
        print(f"\n  자동화 후보 {eligible}건 - 대시보드에서 켤 수 있습니다")
