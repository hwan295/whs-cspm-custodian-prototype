#!/bin/sh
# AWS 없이 파이프라인 전체를 돌린다. 자격증명도 랩도 필요 없다.
#
#   sh tests/run.sh          Phase 1 만 (판정까지)
#   sh tests/run.sh --apply  Phase 2 까지 (조치 후 재확인)
#
# custodian 은 tests/bin 의 스텁으로 바뀐다. 결과는 tests/_work 에 쌓인다.
set -e
cd "$(dirname "$0")/.."

rm -rf tests/_work
mkdir -p tests/_work

PATH="$PWD/tests/bin:$PATH" \
CSPM_WORK_DIR="$PWD/tests/_work" \
CSPM_SCOPE_ACCOUNTS=123456789012 \
  python3 -m response "$@" sample-findings.ocsf.json

echo ""
echo "결과: tests/_work/logs/  ·  dryrun 산출물: tests/_work/out/"
