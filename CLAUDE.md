# DeepPierce — AI-Powered API Fuzzing Tool

## 项目定位

独立 Python CLI 工具，专精于用 AI 做接口 Fuzz。
不替代传统字典 Fuzz，而是让 AI 做传统工具做不到的事：理解接口语义、生成攻击策略、判断响应含义。

## 核心架构决策

### 1. 独立工具，非 Burp 插件
- Python 生态（AI SDK、异步 HTTP）远超 Burp 的 Jython 限制
- 通过 BurpMCP 桥接 Burp 流量，不绑死在 Burp 上
- 也可以独立运行（HAR 文件、OpenAPI 文档）

### 2. AI 做"指挥"，不做"执行"
- AI 不生成已知 payload（`' OR 1=1--`）——字典更快
- AI 做：参数语义理解、攻击面推断、策略树生成、响应判断、误报过滤
- 执行层用 httpx 异步并发发包，不走 AI

### 3. 策略树而非 Payload 列表
- 每个策略是一个树：成功→深入，失败→剪枝
- AI 根据参数语义生成针对性策略，而不是对所有参数用同一套 payload

### 4. 四阶段 Pipeline
ingest → understand → strategize → execute

## 模块结构

```
DeepPierce/
├── cli.py              # Click CLI (run/ingest/analyze/sessions)
├── config.py           # 环境变量 + YAML 配置
├── core/
│   ├── models.py       # Pydantic 数据模型 (HttpExchange, ApiEndpoint, FuzzStrategy, FuzzFinding)
│   ├── engine.py       # Pipeline 编排 (FuzzEngine)
│   └── session.py      # 会话持久化 (save/resume)
├── ingest/
│   ├── base.py         # 摄入器抽象接口
│   └── har.py          # HAR 文件解析 (已完成)
│   # TODO: burp.py (BurpMCP), openapi.py (OpenAPI/Swagger)
├── understand/
│   └── analyzer.py     # AI 语义理解 (Claude API)
│       - 参数语义识别 (user_id, token, signature, timestamp...)
│       - 攻击面映射 (idor, sqli, xss, ssrf...)
│       - 风险评分 (0-10)
│       - 接口关系图构建
├── fuzz/
│   ├── strategy_gen.py # AI 策略树生成
│   │   - 根据攻击面生成针对性策略
│   │   - 策略是树结构，支持成功→深入的分支
│   └── runner.py       # 策略执行引擎
│       - 自适应树遍历 (深度限制 5)
│       - 响应快速分析 (状态码、错误模式、长度变化)
│       - AI 误报过滤
└── output/             # 报告生成 (Markdown + JSON)

## 关键技术点

### AI Prompt 设计
- System prompt 定位为"高级 API 安全研究员"
- 提供攻击面映射参考表 (参数类型 → 攻击面)
- 输出格式用 JSON Schema 约束，支持结构化提取

### 策略执行
- Semaphore 控制并发 (默认 10)
- 每个策略的步骤树深度优先遍历
- 成功指标匹配 → 深入子步骤；失败指标匹配 → 剪枝
- 快速分析层 (正则+规则) 先过滤，AI 研判再做最终判断

### 去重
- 同一 attack_type + URL path + status_code 去重
- AI 最终研判阶段做语义去重

## 已知限制

- 仅支持 HAR 输入，BurpMCP 实时流量未实现
- 策略树的 payload 模板依赖 AI 生成质量，可能不够精确
- 多步攻击链（跨接口编排）未实现，当前每个策略只针对单个接口
- Auth 边界对比（多角色自动测试）未实现
- 无 Web UI
- 大流量场景 (>1000 接口) 的 token 成本需要控制（分批 + 采样）
