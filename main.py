#!/usr/bin/env python3
"""DeepPierce — AI Agent 渗透测试工具。直接运行此文件启动。"""

import sys
from pathlib import Path

# 确保项目根目录在 Python 路径中
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from DeepPierce.gui.app import run_app

if __name__ == "__main__":
    run_app()
