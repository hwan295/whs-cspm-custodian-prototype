"""조치 로그 생성과 출력 - 티켓 #7.

다음 파트(⑤ 분석·리포팅)가 소비하는 산출물이라 필드 구성이 곧 계약이다.
통합 시 remediation_status 테이블로 들어간다.
"""

import json
import os
from datetime import datetime

from .config import LOG_DIR

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
    "executed_at",
)

# remediation 에서 로그로 옮겨 담을 항목.
# propagation_delay 는 지금은 기록만 한다 - 조치 후 재확인(#C3)이 붙을 때 쓴다
REMEDIATION_LOG_FIELDS = (
    "mode",
    "disruption",
    "blast_radius",
    "propagation_delay",
    "risk_note",
)


def build_log_records(findings):
    """조치 로그로 남길 형태로 정리한다."""
    executed_at = datetime.now().isoformat(timespec="seconds")
    records = []
    for finding in findings:
        record = {field: finding.get(field) for field in LOG_FIELDS}
        remediation = finding.get("remediation") or {}
        for field in REMEDIATION_LOG_FIELDS:
            record[field] = remediation.get(field)
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
