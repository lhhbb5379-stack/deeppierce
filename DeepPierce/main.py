"""DeepPierce — AI Agent 渗透测试工具入口。

用法:
    deeppierce          # 安装后直接运行
    python -m DeepPierce.main   # 开发模式
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def main():
    from DeepPierce.gui.app import run_app
    run_app()


if __name__ == "__main__":
    main()
