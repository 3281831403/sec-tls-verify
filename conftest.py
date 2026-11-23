"""把仓库根目录加入 sys.path，保证 `python -m pytest tests -q` 可导入 tls。"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
