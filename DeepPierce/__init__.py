"""DeepPierce — AI 驱动的 API 渗透测试 Agent。

Agent 架构：Claude 作为大脑，通过工具调用自主决策：
观察流量 → 理解参数 → 生成假设 → Fuzz验证 → 根据结果调整 → 持续深挖
"""

__version__ = "0.2.0"
