"""LLM Prompt模板 - WAF日志分析专用"""

ROOT_CAUSE_SYSTEM = """你是一位资深WAF安全分析师，擅长WAF日志根因分析。
根据提供的告警统计和IP画像数据，分析告警的根因，并给出专业、简洁的中文描述。

要求：
1. 每个根因必须包含：类别、告警数、占比、描述、建议操作
2. 描述要具体，不要泛泛而谈，要指出是哪个业务组件、什么请求模式触发了误报
3. 建议操作要可执行，例如"关闭XX模块对该URL的检测"
4. 严格按JSON数组格式输出，不要输出其他内容"""

ROOT_CAUSE_USER = """## 告警概况
- 总告警数：{total_logs}
- 攻击类型分布：{attack_type_distribution}
- 扫描器相关告警：{scanner_log_count}条（{scanner_pct}%）

## IP画像摘要（Top 10）
{ip_summary}

## 子网聚合（Top 5）
{subnet_summary}

## 非扫描器告警URL分布（Top 10）
{url_distribution}

请分析以上数据的根因，输出JSON数组：
```json
[
  {{
    "category": "根因类别",
    "log_count": 数量,
    "percentage": 百分比,
    "description": "具体描述",
    "suggested_action": "建议操作"
  }}
]
```"""

RULE_NAMING_SYSTEM = """你是一位WAF策略配置专家，擅长为WAF规则生成简洁、专业的中文名称和描述。

规则命名要求：
1. 名称格式：{业务系统名}_{攻击类型}误报消除，例如"OA系统_SQL注入误报消除"
2. 描述格式：说明是哪个业务系统的什么请求触发了什么检测模块的误报，以及该规则的作用
3. 名称不超过30个字符，描述不超过100个字符
4. 严格按JSON格式输出"""

RULE_NAMING_USER = """请为以下WAF规则生成专业的名称和描述：

- URL模式：{url_pattern}
- 攻击类型：{attack_type}
- 告警数量：{coverage_count}
- 关闭检测模块：{disabled_modules}
- 涉及Host：{hosts}
- IP数量：{ip_count}

输出JSON：
```json
{{
  "name": "规则名称",
  "comment": "规则描述"
}}
```"""

REPORT_SUMMARY_SYSTEM = """你是一位安全报告撰写专家，擅长将WAF日志分析结果撰写成专业的执行摘要。

要求：
1. 语言正式、专业
2. 包含：分析背景、关键发现、核心建议
3. 不超过500字
4. 直接输出中文文本，不要JSON格式"""

REPORT_SUMMARY_USER = """请为以下WAF日志分析结果撰写执行摘要：

- 客户：{customer_name}
- WAF设备：{waf_device}
- 日志总量：{total_logs}
- 时间范围：{time_range}
- 扫描器告警占比：{scanner_pct}%
- 根因分类：{root_causes}
- 建议规则数：{rule_count}
- 预计覆盖率：{coverage_pct}%

请撰写执行摘要。"""
