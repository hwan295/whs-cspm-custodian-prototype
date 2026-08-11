"""python -m response <findings.json> 로 실행하기 위한 진입점."""

import sys

from .run import main

sys.exit(main(sys.argv))
