"""WAF设备适配层抽象基类"""

from abc import ABC, abstractmethod
from typing import Optional


class WAFRuleCreate:
    """创建规则的通用模型"""
    pass


class WAFRuleUpdate:
    """更新规则的通用模型"""
    pass


class WAFAdapterBase(ABC):
    """WAF设备适配器抽象基类"""

    def __init__(self, base_url: str, api_token: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.api_token = api_token
        self.verify_ssl = verify_ssl

    @abstractmethod
    async def test_connection(self) -> bool:
        """测试WAF设备连接"""
        ...

    @abstractmethod
    async def list_rules(self, **filters) -> list[dict]:
        """获取规则列表"""
        ...

    @abstractmethod
    async def create_rule(self, rule: dict) -> dict:
        """创建规则"""
        ...

    @abstractmethod
    async def update_rule(self, rule_id: int, rule: dict) -> dict:
        """更新规则"""
        ...

    @abstractmethod
    async def delete_rules(self, rule_ids: list[int]) -> None:
        """删除规则"""
        ...

    @abstractmethod
    async def enable_rule(self, rule_id: int) -> dict:
        """启用规则"""
        ...

    @abstractmethod
    async def disable_rule(self, rule_id: int) -> dict:
        """禁用规则"""
        ...

    @abstractmethod
    async def export_rules(self, rule_ids: list[int]) -> bytes:
        """导出规则"""
        ...

    @abstractmethod
    async def import_rules(self, data: bytes) -> list[dict]:
        """导入规则"""
        ...
