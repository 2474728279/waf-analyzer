"""WAF日志分析智能体平台 - API路由"""

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Optional
import uuid
import os
import json

from app.config import settings
from app.agents.graph import build_analysis_graph, AnalysisState

router = APIRouter()

# 内存存储（MVP阶段，后续迁移到数据库）
projects_db: dict = {}
analysis_results: dict = {}


class ProjectCreateRequest(BaseModel):
    name: str
    customer_name: str
    waf_device_ip: str
    waf_device_name: str = ""
    description: str = ""


class ProjectUpdateRequest(BaseModel):
    name: Optional[str] = None
    customer_name: Optional[str] = None
    waf_device_ip: Optional[str] = None
    waf_device_name: Optional[str] = None
    description: Optional[str] = None


class WAFDeviceConfig(BaseModel):
    name: str
    vendor: str = "safeline"
    base_url: str
    api_token: str
    verify_ssl: bool = False


class AnalysisRequest(BaseModel):
    project_id: str
    log_file_path: Optional[str] = None


class DeployRequest(BaseModel):
    project_id: str
    waf_device_id: str
    rule_indices: list[int] = []


# ========== 项目管理 ==========

@router.post("/projects")
async def create_project(req: ProjectCreateRequest):
    project_id = str(uuid.uuid4())[:8]
    project = {
        "id": project_id,
        "name": req.name,
        "customer_name": req.customer_name,
        "waf_device_ip": req.waf_device_ip,
        "waf_device_name": req.waf_device_name,
        "description": req.description,
        "status": "created",
        "total_logs": 0,
        "log_file_path": None,
    }
    projects_db[project_id] = project
    return project


@router.get("/projects")
async def list_projects():
    return list(projects_db.values())


@router.get("/projects/{project_id}")
async def get_project(project_id: str):
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="项目不存在")
    project = projects_db[project_id]
    result = analysis_results.get(project_id, {})
    return {**project, "analysis": result}


@router.put("/projects/{project_id}")
async def update_project(project_id: str, req: ProjectUpdateRequest):
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="项目不存在")
    project = projects_db[project_id]
    for k, v in req.model_dump(exclude_unset=True).items():
        project[k] = v
    return project


@router.delete("/projects/{project_id}")
async def delete_project(project_id: str):
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="项目不存在")
    del projects_db[project_id]
    analysis_results.pop(project_id, None)
    return {"detail": "已删除"}


class LogPathRequest(BaseModel):
    log_file_path: str


@router.post("/projects/{project_id}/upload")
async def upload_log(project_id: str, file: UploadFile = File(...)):
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="项目不存在")

    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    file_path = os.path.join(settings.UPLOAD_DIR, f"{project_id}_{file.filename}")

    # 流式写入，避免大文件撑爆内存
    with open(file_path, "wb") as f:
        while chunk := await file.read(1024 * 1024):  # 1MB chunks
            f.write(chunk)

    size = os.path.getsize(file_path)
    projects_db[project_id]["log_file_path"] = file_path
    projects_db[project_id]["status"] = "uploaded"

    return {"project_id": project_id, "file_path": file_path, "size": size}


@router.post("/projects/{project_id}/set-log-path")
async def set_log_path(project_id: str, req: LogPathRequest):
    """直接指定服务器本地日志文件路径，无需上传。适合大文件场景。"""
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="项目不存在")

    path = req.log_file_path
    if not os.path.exists(path):
        raise HTTPException(status_code=400, detail=f"文件不存在: {path}")

    projects_db[project_id]["log_file_path"] = path
    projects_db[project_id]["status"] = "uploaded"

    return {"project_id": project_id, "log_file_path": path}


# ========== 分析任务 ==========

@router.post("/analysis/start")
async def start_analysis(req: AnalysisRequest, background_tasks: BackgroundTasks):
    project_id = req.project_id
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="项目不存在")

    log_path = req.log_file_path or projects_db[project_id].get("log_file_path")
    if not log_path or not os.path.exists(log_path):
        raise HTTPException(status_code=400, detail="日志文件不存在")

    projects_db[project_id]["status"] = "analyzing"

    # 启动后台分析任务
    background_tasks.add_task(_run_analysis, project_id, log_path)

    return {"project_id": project_id, "status": "analyzing"}


async def _run_analysis(project_id: str, log_path: str):
    """在后台运行分析工作流。"""
    try:
        graph = build_analysis_graph()

        initial_state = {
            "project_id": project_id,
            "raw_log_path": log_path,
            "current_step": "starting",
        }

        result = await graph.ainvoke(initial_state)

        # 保存结果（去掉DataFrame，只保留可序列化的数据）
        serializable = {}
        for k, v in result.items():
            if k == "df_cache_key":
                continue
            if isinstance(v, pd.DataFrame):
                continue
            try:
                json.dumps(v)
                serializable[k] = v
            except (TypeError, ValueError):
                serializable[k] = str(v)

        analysis_results[project_id] = serializable
        projects_db[project_id]["status"] = "review"

        if "total_logs" in result:
            projects_db[project_id]["total_logs"] = result["total_logs"]

    except Exception as e:
        projects_db[project_id]["status"] = "failed"
        analysis_results[project_id] = {"error": str(e), "current_step": "failed"}


@router.get("/analysis/{project_id}/status")
async def get_analysis_status(project_id: str):
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="项目不存在")

    project = projects_db[project_id]
    result = analysis_results.get(project_id, {})

    return {
        "project_id": project_id,
        "status": project["status"],
        "current_step": result.get("current_step", ""),
        "total_logs": result.get("total_logs", 0),
        "scanner_ip_count": result.get("scanner_ip_count", 0),
        "proposed_rules_count": len(result.get("proposed_rules", [])),
    }


@router.get("/analysis/{project_id}/results")
async def get_analysis_results(project_id: str):
    if project_id not in analysis_results:
        raise HTTPException(status_code=404, detail="分析结果不存在")
    return analysis_results[project_id]


@router.get("/analysis/{project_id}/rules")
async def get_proposed_rules(project_id: str):
    result = analysis_results.get(project_id, {})
    return result.get("proposed_rules", [])


# ========== WAF设备管理 ==========

waf_devices: dict = {}


@router.post("/waf-devices")
async def add_waf_device(config: WAFDeviceConfig):
    device_id = str(uuid.uuid4())[:8]
    device = {
        "id": device_id,
        "name": config.name,
        "vendor": config.vendor,
        "base_url": config.base_url,
        "api_token": config.api_token,
        "verify_ssl": config.verify_ssl,
    }
    waf_devices[device_id] = device
    return device


@router.get("/waf-devices")
async def list_waf_devices():
    return list(waf_devices.values())


@router.post("/waf-devices/{device_id}/test")
async def test_waf_connection(device_id: str):
    if device_id not in waf_devices:
        raise HTTPException(status_code=404, detail="WAF设备不存在")

    device = waf_devices[device_id]
    if device["vendor"] == "safeline":
        from app.waf_adapters.safeline import SafeLineAdapter
        adapter = SafeLineAdapter(
            base_url=device["base_url"],
            api_token=device["api_token"],
            verify_ssl=device["verify_ssl"],
        )
        success = await adapter.test_connection()
        return {"connected": success}
    else:
        return {"connected": False, "error": f"不支持的WAF类型: {device['vendor']}"}


# ========== 报告生成 ==========

class ReportRequest(BaseModel):
    format: str = "markdown"  # "markdown" | "word"


@router.post("/reports/{project_id}/generate")
async def generate_report(project_id: str, req: ReportRequest = None):
    if project_id not in analysis_results:
        raise HTTPException(status_code=404, detail="分析结果不存在")

    result = analysis_results[project_id]
    project = projects_db.get(project_id, {})
    rules = result.get("proposed_rules", [])
    fmt = req.format if req else "markdown"

    os.makedirs(settings.REPORT_DIR, exist_ok=True)

    if fmt == "word":
        from app.utils.report_builder import generate_word_report
        report_path = os.path.join(settings.REPORT_DIR, f"{project_id}_report.docx")
        generate_word_report(project, result, report_path)
    else:
        md = _generate_markdown_report(project_id, result, rules)
        report_path = os.path.join(settings.REPORT_DIR, f"{project_id}_report.md")
        with open(report_path, "w") as f:
            f.write(md)

    return {"project_id": project_id, "report_path": report_path, "format": fmt}


@router.get("/reports/{project_id}/download")
async def download_report(project_id: str):
    """下载报告文件。"""
    from fastapi.responses import FileResponse

    if project_id not in analysis_results:
        raise HTTPException(status_code=404, detail="分析结果不存在")

    # 优先返回Word格式，其次Markdown
    for ext in [".docx", ".md"]:
        path = os.path.join(settings.REPORT_DIR, f"{project_id}_report{ext}")
        if os.path.exists(path):
            media_type = (
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                if ext == ".docx"
                else "text/markdown"
            )
            return FileResponse(path, media_type=media_type, filename=os.path.basename(path))

    raise HTTPException(status_code=404, detail="报告文件不存在")


def _generate_markdown_report(project_id: str, result: dict, rules: list) -> str:
    project = projects_db.get(project_id, {})
    total = result.get("total_logs", 0)
    dist = result.get("attack_type_distribution", {})
    root_causes = result.get("root_causes", [])
    scanner_count = result.get("scanner_log_count", 0)

    lines = [
        f"# WAF日志分析报告",
        f"",
        f"## 1. 概述",
        f"",
        f"| 项目 | 内容 |",
        f"|------|------|",
        f"| 客户名称 | {project.get('customer_name', '')} |",
        f"| WAF设备 | {project.get('waf_device_name', '')} ({project.get('waf_device_ip', '')}) |",
        f"| 日志总量 | {total} |",
        f"",
        f"## 2. 攻击类型分布",
        f"",
        f"| 攻击类型 | 告警数 | 占比 |",
        f"|----------|--------|------|",
    ]

    for at, count in sorted(dist.items(), key=lambda x: -x[1]):
        pct = f"{count/total*100:.1f}%" if total > 0 else "0%"
        lines.append(f"| {at} | {count} | {pct} |")

    lines.extend([
        f"",
        f"## 3. 根因分析",
        f"",
        f"| 根因类别 | 告警数 | 占比 |",
        f"|----------|--------|------|",
    ])
    for rc in root_causes:
        lines.append(f"| {rc.get('category', '')} | {rc.get('log_count', 0)} | {rc.get('percentage', 0):.1f}% |")

    lines.extend([
        f"",
        f"## 4. 建议规则（{len(rules)}条）",
        f"",
        f"| 序号 | 规则名称 | 关闭模块 | 覆盖告警 | 策略 |",
        f"|------|----------|----------|----------|------|",
    ])
    for i, rule in enumerate(rules[:50], 1):
        modules = ", ".join(rule.get("disabled_modules", []))
        lines.append(f"| {i} | {rule.get('name', '')} | {modules} | {rule.get('coverage_count', 0)} | {rule.get('strategy', '')} |")

    return "\n".join(lines)


# 需要pandas import
import pandas as pd
