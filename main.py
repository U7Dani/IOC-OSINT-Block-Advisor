from __future__ import annotations

import runpy
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent / "ioc_osint_block_advisor"
sys.path.insert(0, str(PROJECT_DIR))
runpy.run_path(str(PROJECT_DIR / "main.py"), run_name="__main__")
