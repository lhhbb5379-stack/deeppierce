# DeepPierce — AI-Powered API Penetration Testing

> AI Agent 驱动的接口 Fuzz 工具。自动从 Burp 流量中提取接口，理解业务语义，智能生成攻击策略，逐个深度测试。

## 快速开始

### 1. 安装

```bash
git clone <repo-url> && cd DeepPierce
pip install -e .
```

依赖：Python ≥ 3.11

### 2. 配置

启动后点右上角**设置**，填写：

| 配置项 | 说明 |
|--------|------|
| API 密钥 | Anthropic API Key（支持自定义端点） |
| 模型 | 推荐 `claude-sonnet-4-6` |
| Burp 代理 | 默认 `http://127.0.0.1:8080`（可关闭） |
| BurpMCP | 默认 `http://127.0.0.1:9876`（可关闭） |

配置保存在 `~/.deeppierce/config.yml`。

### 3. 运行

```bash
deeppierce
```

1. 输入目标 URL
2. （可选）选择 JS 文件目录，自动提取隐藏接口
3. 点**开始**，Agent 自动工作

## 前置条件

- **Burp Suite** — 需安装 [BurpMCP-Ultra](https://github.com/xiaoxiaoranxxx/BurpMCP-Ultra) 扩展
- **Claude API Key** — 从 [Anthropic Console](https://console.anthropic.com) 获取
- **浏览器代理** — 测试前通过 Burp 代理访问目标，积累流量

## 工作流程

```
Burp 流量 → 自动提取接口 + 参数 + 凭证 → 端点打分排序
         → Agent 按优先级逐个测试（未授权/越权/注入/...）
         → 确认漏洞（含 curl PoC） + 测试清单打钩
```

## 核心特性

### 智能接口发现
- **BurpMCP 集成** — 自动拉取代理历史和站点地图
- **JS 提取器** — 从 JS 文件中提取隐藏 API（FindSomething + 雪瞳风格）
- **预处理过滤** — 自动跳过图片/CSS/字体等静态资源

### 三大分析引擎
- **敏感信息检测** — 700+ 规则，覆盖云密钥/JWT/PII/数据库连接串
- **指纹识别** — Shiro/Swagger/Druid/JWT 等自动识别 + 跟进 URL
- **CaA 参数字典** — 从流量中学习参数名/值，为裸接口提供 Fuzz 参数

### AI Agent
- 自动分析接口业务含义，不无脑套 payload
- 端点按风险评分排序，优先测试高危接口
- `lookup_params` 查原始参数和凭证，遇到认证直接复用
- Pending 不为 0 拒绝收工，确保穷尽

### 测试清单
- 每个接口显示测试历史和 AI 思考过程
- 点击接口查看详细分析
- 漏洞按严重程度排序

### 灵活定制
- **Agent 行为定制** — 预设模板（金融/IDOR专项/未授权/激进模式）或手写
- **自定义规则** — 追加 API 提取正则 / 敏感信息检测规则

## 项目结构

```
DeepPierce/
├── DeepPierce/
│   ├── agent/          # AI Agent 核心（提示词/工具/主循环）
│   ├── enrich/         # 三大引擎（敏感信息/指纹/字典）
│   ├── crawler/        # JS 提取器
│   ├── bridge/         # BurpMCP 客户端
│   ├── gui/            # PySide6 界面
│   └── config.py       # 配置管理
├── pyproject.toml
└── README.md
```

## License

MIT
