"""雷池SafeLine WAF适配器

基于mcp-safeline项目中的API调用模式。
支持两种规则API:
- /api/PolicyRuleAPI: 通用自定义规则
- /api/ModifyModulePolicyRuleAPI: 检测模块控制规则
"""

import httpx
import json
from typing import Optional
from .base import WAFAdapterBase


# 检测模块名称映射
MODULE_NAME_MAP = {
    "SQL注入检测": "m_sqli",
    "XSS检测": "m_xss",
    "命令注入检测": "m_cmd_injection",
    "文件包含检测": "m_file_include",
    "文件上传检测": "m_file_upload",
    "SSRF检测": "m_ssrf",
    "LDAP注入检测": "m_ldap",
    "机器人检测": "m_scanner",
    "情报模块": "情报模块",
    "服务器响应检测": "m_response",
    "代码执行检测": "m_code_exec",
    "代码注入检测": "m_code_injection",
    "XXE检测": "m_xxe",
    "反序列化检测": "m_deserialization",
}

# 反向映射
MODULE_ID_MAP = {v: k for k, v in MODULE_NAME_MAP.items()}


class SafeLineAdapter(WAFAdapterBase):
    """雷池SafeLine WAF适配器"""

    def _headers(self) -> dict:
        return {
            "API-TOKEN": self.api_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _client(self) -> httpx.Client:
        return httpx.Client(
            verify=self.verify_ssl,
            timeout=30.0,
        )

    async def test_connection(self) -> bool:
        try:
            with self._client() as client:
                resp = client.get(
                    f"{self.base_url}/api/ProfileAPI",
                    headers=self._headers(),
                )
                return resp.status_code == 200
        except Exception:
            return False

    async def list_rules(self, rule_type: str = "modify_module", **filters) -> list[dict]:
        """获取规则列表。

        Args:
            rule_type: "modify_module"(检测模块控制) 或 "policy"(通用)
        """
        endpoint = "/api/ModifyModulePolicyRuleAPI" if rule_type == "modify_module" else "/api/PolicyRuleAPI"
        params = {"count": filters.get("count", 100), "offset": filters.get("offset", 0)}
        if "is_enabled" in filters:
            params["is_enabled"] = filters["is_enabled"]

        with self._client() as client:
            resp = client.get(
                f"{self.base_url}{endpoint}",
                headers=self._headers(),
                params=params,
            )
            data = resp.json()
            if data.get("err") is not None:
                raise Exception(f"WAF API error: {data.get('msg', data.get('err'))}")
            items = data.get("data", {}).get("items", [])
            return items

    async def create_rule(self, rule: dict) -> dict:
        """创建检测模块控制规则。

        rule需包含: name, action, pattern, module_management, comment, is_enabled等
        """
        with self._client() as client:
            resp = client.post(
                f"{self.base_url}/api/ModifyModulePolicyRuleAPI",
                headers=self._headers(),
                json=rule,
            )
            data = resp.json()
            if data.get("err") is not None:
                raise Exception(f"创建规则失败: {data.get('msg', data.get('err'))}")
            return data.get("data", {})

    async def update_rule(self, rule_id: int, rule: dict) -> dict:
        """更新检测模块控制规则。"""
        rule["id"] = rule_id
        with self._client() as client:
            resp = client.put(
                f"{self.base_url}/api/ModifyModulePolicyRuleAPI",
                headers=self._headers(),
                json=rule,
            )
            data = resp.json()
            if data.get("err") is not None:
                raise Exception(f"更新规则失败: {data.get('msg', data.get('err'))}")
            return data.get("data", {})

    async def delete_rules(self, rule_ids: list[int]) -> None:
        """批量删除规则。"""
        with self._client() as client:
            resp = client.request(
                "DELETE",
                f"{self.base_url}/api/ModifyModulePolicyRuleAPI",
                headers=self._headers(),
                json={"id__in": rule_ids},
            )
            data = resp.json()
            if data.get("err") is not None:
                raise Exception(f"删除规则失败: {data.get('msg', data.get('err'))}")

    async def enable_rule(self, rule_id: int) -> dict:
        """启用规则。"""
        return await self.update_rule(rule_id, {"is_enabled": True})

    async def disable_rule(self, rule_id: int) -> dict:
        """禁用规则。"""
        return await self.update_rule(rule_id, {"is_enabled": False})

    async def export_rules(self, rule_ids: list[int]) -> bytes:
        """导出规则（获取规则详情后序列化）。"""
        all_rules = await self.list_rules()
        selected = [r for r in all_rules if r.get("id") in rule_ids]
        return json.dumps(selected, ensure_ascii=False, indent=2).encode("utf-8")

    async def import_rules(self, data: bytes) -> list[dict]:
        """导入规则。"""
        rules = json.loads(data)
        results = []
        for rule in rules:
            # 移除id和版本信息，让WAF自动分配
            rule.pop("id", None)
            rule.pop("version", None)
            rule.pop("create_time", None)
            rule.pop("last_update_time", None)
            result = await self.create_rule(rule)
            results.append(result)
        return results

    @staticmethod
    def build_modify_module_rule(
        comment: str,
        pattern: dict,
        disabled_modules: list[str],
        is_enabled: bool = False,
        **kwargs,
    ) -> dict:
        """构建检测模块控制规则请求体。

        Args:
            comment: 规则备注（如"DMAgent代理SQL查询触发SQL注入检测误报消除"）
            pattern: SafeLine Pattern DSL
            disabled_modules: 要关闭的检测模块中文名列表(如["SQL注入检测", "情报模块"])
            is_enabled: 是否启用
        """
        module_ids = [MODULE_NAME_MAP.get(m, m) for m in disabled_modules]

        rule = {
            "comment": comment,
            "action": "modify_module",
            "target": "logic_expr",
            "pattern": pattern,
            "module_management": {"enabled": [], "disabled": module_ids},
            "is_enabled": is_enabled,
            "attack_type": -1,
            "log_option": "Persistence",
            "websites": kwargs.get("websites", []),
            "session_method": kwargs.get("session_method", {"type": "src_ip", "param": ""}),
            "cron_config": kwargs.get("cron_config", {"type": "all", "start": "00:00", "end": "23:59", "days": []}),
            "percentage": kwargs.get("percentage", 100),
            "duration": kwargs.get("duration", 1),
            "priority": kwargs.get("priority", 0),
            "delay": kwargs.get("delay", 0),
            "punish_type": None,
            "punish_time": None,
            "forbidden_page_config": None,
            "modules_list": [],
            "risk_level": 0,
            "req_rule_id": "",
            "rsp_rule_id": "",
            "mark_flag": "",
            "custom_fsl": "",
            "ignore_skip_remaining": False,
            "hook": 0,
            "is_protected": False,
            "is_expired": False,
            "is_global": kwargs.get("is_global", False),
            "expire_time": 0,
        }
        return rule
