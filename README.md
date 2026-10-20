# 日志分析平台

基于大语言模型(LLM)的 WAF 日志智能分析平台,支持对雷池(SafeLine)等 WAF 设备日志的采集、解析与自动化分析,并生成可读性强的分析报告。

## 功能特性

- **多 LLM 支持**:Claude / OpenAI / Ollama,可灵活切换
- **WAF 设备适配**:内置雷池(SafeLine)适配器,可扩展其他设备
- **智能分析流水线**:基于 LangGraph 的多智能体分析
- **分析能力**:
  - 覆盖率计算
  - IP 画像
  - 攻击模式提取
  - 扫描器检测
  - 子网分组
- **报告生成**:自动生成 Word(docx)分析报告
- **可视化看板**:React + Ant Design 前端

## 技术栈

| 层 | 技术 |
| --- | --- |
| 后端 | Python / FastAPI / SQLAlchemy / PostgreSQL / Redis / LangGraph |
| 前端 | React 19 / Vite / TypeScript / Ant Design |
| LLM | Claude / OpenAI / Ollama |
| 部署 | Docker Compose |

## 目录结构

```
.
├── backend/           # FastAPI 后端
│   └── app/
│       ├── agents/        # LangGraph 分析智能体
│       ├── analyzers/     # 各类分析器
│       ├── llm/           # LLM 适配(Claude / OpenAI / Ollama)
│       ├── waf_adapters/  # WAF 设备适配器
│       ├── api/           # 路由
│       ├── models/        # 数据模型
│       └── services/      # 业务服务
├── frontend/          # React 前端
└── docker-compose.yml # 容器编排
```

## 快速开始

### 环境要求

- Docker 与 Docker Compose
- LLM API Key(任选其一):
  - `ANTHROPIC_API_KEY`
  - `OPENAI_API_KEY`

### 启动

```bash
export ANTHROPIC_API_KEY=sk-ant-xxx   # 或 OPENAI_API_KEY
docker compose up -d --build
```

启动后访问:

- 前端:http://localhost:3000
- 后端 API:http://localhost:8000

## 配置

主要环境变量:

| 变量 | 说明 |
| --- | --- |
| `WAF_DATABASE_URL` | PostgreSQL 连接串 |
| `WAF_REDIS_URL` | Redis 连接串 |
| `ANTHROPIC_API_KEY` | Anthropic API Key |
| `OPENAI_API_KEY` | OpenAI API Key |
