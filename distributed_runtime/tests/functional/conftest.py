import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]          # distributed_runtime/
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
