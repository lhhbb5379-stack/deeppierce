"""DeepPierce 信息增强模块 — 整合 FindSomething / HaE / CaA 的核心能力。

三个子模块:
- patterns: 敏感信息正则模式库 (700+ 规则，来源 FindSomething + HaE)
- rules: 可配置规则引擎 (HaE 风格，支持 NFA/DFA + 作用域 + 格式化)
- dictionary: Fuzz 字典构建器 (CaA 风格，从流量中提取参数/路径/值)
"""

from DeepPierce.enrich.patterns import SecretPatternMatcher
from DeepPierce.enrich.rules import RuleEngine, Rule, RuleGroup, RuleScope
from DeepPierce.enrich.dictionary import FuzzDictionaryBuilder

__all__ = [
    "SecretPatternMatcher",
    "RuleEngine", "Rule", "RuleGroup", "RuleScope",
    "FuzzDictionaryBuilder",
]
