"""Bridges API router — endpoints for framework bridge operations.

Supports OpenClaw, LangChain, CrewAI, AutoGen, Semantic Kernel, and Pydantic AI
agent import, security scanning, discovery, health, and framework status.
"""
from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.deps import get_current_entity
from src.api.rate_limit import rate_limit_reads, rate_limit_writes
from src.database import get_db
from src.models import Entity

router = APIRouter(prefix="/bridges", tags=["bridges"])


# --- Request/Response schemas ---


class OpenClawManifest(BaseModel):
    """OpenClaw agent manifest for import."""

    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(default="", max_length=5000)
    capabilities: list[str] = Field(default_factory=list)
    version: str = Field(default="1.0.0")
    skills: list[dict[str, Any]] = Field(default_factory=list)


class LangChainManifest(BaseModel):
    """LangChain agent manifest for import."""

    name: str = Field(default="LangChain Agent", max_length=100)
    description: str = Field(default="", max_length=5000)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    agent_type: str = Field(default="zero_shot")
    model: str = Field(default="unknown")
    version: str = Field(default="1.0.0")
    code: str = Field(default="")  # Optional code to scan


class CrewAIManifest(BaseModel):
    """CrewAI agent manifest for import."""

    name: str = Field(default="CrewAI Agent", max_length=100)
    description: str = Field(default="", max_length=5000)
    agents: list[dict[str, Any]] = Field(default_factory=list)
    tasks: list[dict[str, Any]] = Field(default_factory=list)
    process: str = Field(default="sequential")
    version: str = Field(default="1.0.0")
    code: str = Field(default="")  # Optional code to scan


class VulnerabilityOut(BaseModel):
    pattern: str
    severity: str
    location: str
    match: str


class ScanResultOut(BaseModel):
    id: str
    entity_id: str
    framework: str
    scan_result: str
    vulnerabilities: list[VulnerabilityOut]
    scanned_at: str


class ImportResult(BaseModel):
    entity_id: str
    display_name: str
    framework_source: str
    framework_trust_modifier: float
    scan: ScanResultOut


class RescanRequest(BaseModel):
    """Manifest for rescanning an entity."""

    skills: list[dict[str, Any]] = Field(default_factory=list)


class LangChainRescanRequest(BaseModel):
    """Manifest for rescanning a LangChain entity."""

    tools: list[dict[str, Any]] = Field(default_factory=list)
    code: str = Field(default="")


class CrewAIRescanRequest(BaseModel):
    """Manifest for rescanning a CrewAI entity."""

    agents: list[dict[str, Any]] = Field(default_factory=list)
    tasks: list[dict[str, Any]] = Field(default_factory=list)
    code: str = Field(default="")


class AutoGenManifest(BaseModel):
    """AutoGen agent manifest for import."""

    name: str = Field(default="AutoGen Agent", max_length=100)
    description: str = Field(default="", max_length=5000)
    agents: list[dict[str, Any]] = Field(default_factory=list)
    oai_config: dict[str, Any] = Field(default_factory=dict)
    code_execution_config: dict[str, Any] = Field(default_factory=dict)
    version: str = Field(default="1.0.0")
    code: str = Field(default="")


class AutoGenRescanRequest(BaseModel):
    """Manifest for rescanning an AutoGen entity."""

    agents: list[dict[str, Any]] = Field(default_factory=list)
    code_execution_config: dict[str, Any] = Field(default_factory=dict)
    code: str = Field(default="")


class SemanticKernelManifest(BaseModel):
    """Semantic Kernel agent manifest for import."""

    name: str = Field(default="Semantic Kernel Agent", max_length=100)
    description: str = Field(default="", max_length=5000)
    plugins: list[dict[str, Any]] = Field(default_factory=list)
    planner_config: dict[str, Any] = Field(default_factory=dict)
    kernel_config: dict[str, Any] = Field(default_factory=dict)
    version: str = Field(default="1.0.0")
    code: str = Field(default="")


class SemanticKernelRescanRequest(BaseModel):
    """Manifest for rescanning a Semantic Kernel entity."""

    plugins: list[dict[str, Any]] = Field(default_factory=list)
    planner_config: dict[str, Any] = Field(default_factory=dict)
    code: str = Field(default="")


class PydanticAIManifest(BaseModel):
    """Pydantic AI agent manifest for import."""

    name: str = Field(default="Pydantic AI Agent", max_length=100)
    description: str = Field(default="", max_length=5000)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    result_type: str | None = Field(default=None)
    deps_type: str | None = Field(default=None)
    model: str = Field(default="unknown")
    system_prompt: str = Field(default="")
    retries: int = Field(default=1)
    version: str = Field(default="1.0.0")
    code: str = Field(default="")


class PydanticAIRescanRequest(BaseModel):
    """Manifest for rescanning a Pydantic AI entity."""

    tools: list[dict[str, Any]] = Field(default_factory=list)
    system_prompt: str = Field(default="")
    code: str = Field(default="")


class BridgeCapability(BaseModel):
    """Capability info for a single framework bridge."""

    framework: str
    capabilities: list[str]
    import_schema: dict[str, Any]
    status: str


class DiscoveryResponse(BaseModel):
    """Response for bridge discovery endpoint."""

    frameworks: list[BridgeCapability]


class BridgeHealthOut(BaseModel):
    """Health status for a single framework bridge."""

    framework: str
    status: str
    module_loaded: bool
    version: str


class FrameworkStatusOut(BaseModel):
    supported_frameworks: list[str]
    entity_counts: dict[str, int]
    scan_results: dict[str, int]


# --- Helper ---


def _scan_to_out(scan) -> ScanResultOut:
    """Convert a FrameworkSecurityScan model to response schema."""
    vulns = scan.vulnerabilities or []
    return ScanResultOut(
        id=str(scan.id),
        entity_id=str(scan.entity_id),
        framework=scan.framework,
        scan_result=scan.scan_result,
        vulnerabilities=[
            VulnerabilityOut(
                pattern=v.get("pattern", ""),
                severity=v.get("severity", ""),
                location=v.get("location", ""),
                match=v.get("match", ""),
            )
            for v in vulns
        ],
        scanned_at=scan.scanned_at.isoformat() if scan.scanned_at else "",
    )


# --- OpenClaw Endpoints ---


@router.post(
    "/openclaw/import",
    response_model=ImportResult,
    dependencies=[Depends(rate_limit_writes)],
)
async def import_openclaw_agent(
    manifest: OpenClawManifest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Import an OpenClaw agent manifest into AgentAvow.

    Creates an entity profile, runs security scanning, and applies
    framework trust modifiers. The importing user becomes the agent operator.
    """
    from src.audit import log_action
    from src.bridges.openclaw.registry import import_openclaw_agent as do_import

    agent, scan = await do_import(
        db=db,
        manifest=manifest.model_dump(),
        operator_entity=current_entity,
    )

    await log_action(
        db,
        action="bridges.openclaw.import",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=agent.id,
        details={
            "agent_name": agent.display_name,
            "scan_result": scan.scan_result,
            "framework": "openclaw",
        },
    )

    return ImportResult(
        entity_id=str(agent.id),
        display_name=agent.display_name,
        framework_source=agent.framework_source or "openclaw",
        framework_trust_modifier=agent.framework_trust_modifier or 1.0,
        scan=_scan_to_out(scan),
    )


@router.get(
    "/openclaw/scan/{entity_id}",
    response_model=ScanResultOut,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_scan_result(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get the latest security scan result for an entity."""
    from src.bridges.openclaw.registry import get_latest_scan

    scan = await get_latest_scan(db, entity_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="No scan found for this entity")

    return _scan_to_out(scan)


@router.post(
    "/openclaw/rescan/{entity_id}",
    response_model=ScanResultOut,
    dependencies=[Depends(rate_limit_writes)],
)
async def rescan_entity(
    entity_id: uuid.UUID,
    body: RescanRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a rescan of an entity with updated skills.

    Only the operator or an admin can rescan an entity.
    A clean rescan removes the trust penalty (sets modifier to 1.0).
    """
    from src.audit import log_action
    from src.bridges.openclaw.registry import rescan_entity as do_rescan

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Authorization: must be operator or admin
    if entity.operator_id != current_entity.id and not current_entity.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to rescan this entity")

    manifest = {"skills": body.skills}
    scan = await do_rescan(db, entity, manifest)

    await log_action(
        db,
        action="bridges.openclaw.rescan",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=entity_id,
        details={
            "scan_result": scan.scan_result,
            "framework": entity.framework_source or "openclaw",
        },
    )

    return _scan_to_out(scan)


# --- OpenClaw Skill Execution ---


class OpenClawSkillRequest(BaseModel):
    """Request to execute an OpenClaw skill."""

    skill_name: str = Field(..., max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)


class OpenClawSkillResponse(BaseModel):
    """Response from an OpenClaw skill execution."""

    skill_name: str
    result: dict[str, Any]


@router.post(
    "/openclaw/execute",
    response_model=OpenClawSkillResponse,
    dependencies=[Depends(rate_limit_writes)],
)
async def execute_openclaw_skill(
    body: OpenClawSkillRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Execute an OpenClaw skill call against AgentAvow.

    The authenticated entity is the caller — all operations are performed
    as that entity with its trust level applied.
    """
    from src.bridges.openclaw.adapter import OpenClawError, translate_skill_call

    try:
        result = await translate_skill_call(
            body.skill_name, body.arguments, current_entity, db,
        )
    except OpenClawError as exc:
        raise HTTPException(
            status_code=400,
            detail={"code": exc.code, "message": exc.message},
        )

    return OpenClawSkillResponse(skill_name=body.skill_name, result=result)


@router.get(
    "/openclaw/skills",
    dependencies=[Depends(rate_limit_reads)],
)
async def list_openclaw_skills():
    """List supported OpenClaw skill names."""
    from src.bridges.openclaw.adapter import get_supported_skills

    skills = get_supported_skills()
    return {"skills": skills, "count": len(skills)}


# --- LangChain Endpoints ---


@router.post(
    "/langchain/import",
    response_model=ImportResult,
    dependencies=[Depends(rate_limit_writes)],
)
async def import_langchain_agent(
    manifest: LangChainManifest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Import a LangChain agent manifest into AgentAvow.

    Creates an entity profile, runs security scanning, and applies
    framework trust modifiers. The importing user becomes the agent operator.
    """
    from src.audit import log_action
    from src.bridges.langchain.registry import import_langchain_agent as do_import

    agent, scan = await do_import(
        db=db,
        manifest=manifest.model_dump(),
        operator_entity=current_entity,
    )

    await log_action(
        db,
        action="bridges.langchain.import",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=agent.id,
        details={
            "agent_name": agent.display_name,
            "scan_result": scan.scan_result,
            "framework": "langchain",
        },
    )

    return ImportResult(
        entity_id=str(agent.id),
        display_name=agent.display_name,
        framework_source=agent.framework_source or "langchain",
        framework_trust_modifier=agent.framework_trust_modifier or 1.0,
        scan=_scan_to_out(scan),
    )


@router.get(
    "/langchain/scan/{entity_id}",
    response_model=ScanResultOut,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_langchain_scan(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get the latest security scan result for a LangChain entity."""
    from src.bridges.langchain.registry import get_latest_scan

    scan = await get_latest_scan(db, entity_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="No scan found for this entity")

    return _scan_to_out(scan)


@router.post(
    "/langchain/rescan/{entity_id}",
    response_model=ScanResultOut,
    dependencies=[Depends(rate_limit_writes)],
)
async def rescan_langchain_entity(
    entity_id: uuid.UUID,
    body: LangChainRescanRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a rescan of a LangChain entity with updated tools/code.

    Only the operator or an admin can rescan an entity.
    A clean rescan removes the trust penalty (sets modifier to 1.0).
    """
    from src.audit import log_action
    from src.bridges.langchain.registry import rescan_entity as do_rescan

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Authorization: must be operator or admin
    if entity.operator_id != current_entity.id and not current_entity.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to rescan this entity")

    manifest = {"tools": body.tools, "code": body.code}
    scan = await do_rescan(db, entity, manifest)

    await log_action(
        db,
        action="bridges.langchain.rescan",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=entity_id,
        details={
            "scan_result": scan.scan_result,
            "framework": entity.framework_source or "langchain",
        },
    )

    return _scan_to_out(scan)


# --- CrewAI Endpoints ---


@router.post(
    "/crewai/import",
    response_model=ImportResult,
    dependencies=[Depends(rate_limit_writes)],
)
async def import_crewai_agent(
    manifest: CrewAIManifest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Import a CrewAI manifest into AgentAvow.

    Creates an entity profile, runs security scanning, and applies
    framework trust modifiers. The importing user becomes the agent operator.
    """
    from src.audit import log_action
    from src.bridges.crewai.registry import import_crewai_agent as do_import

    agent, scan = await do_import(
        db=db,
        manifest=manifest.model_dump(),
        operator_entity=current_entity,
    )

    await log_action(
        db,
        action="bridges.crewai.import",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=agent.id,
        details={
            "agent_name": agent.display_name,
            "scan_result": scan.scan_result,
            "framework": "crewai",
        },
    )

    return ImportResult(
        entity_id=str(agent.id),
        display_name=agent.display_name,
        framework_source=agent.framework_source or "crewai",
        framework_trust_modifier=agent.framework_trust_modifier or 1.0,
        scan=_scan_to_out(scan),
    )


@router.get(
    "/crewai/scan/{entity_id}",
    response_model=ScanResultOut,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_crewai_scan(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get the latest security scan result for a CrewAI entity."""
    from src.bridges.crewai.registry import get_latest_scan

    scan = await get_latest_scan(db, entity_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="No scan found for this entity")

    return _scan_to_out(scan)


@router.post(
    "/crewai/rescan/{entity_id}",
    response_model=ScanResultOut,
    dependencies=[Depends(rate_limit_writes)],
)
async def rescan_crewai_entity(
    entity_id: uuid.UUID,
    body: CrewAIRescanRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a rescan of a CrewAI entity with updated agents/tasks/code.

    Only the operator or an admin can rescan an entity.
    A clean rescan removes the trust penalty (sets modifier to 1.0).
    """
    from src.audit import log_action
    from src.bridges.crewai.registry import rescan_entity as do_rescan

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Authorization: must be operator or admin
    if entity.operator_id != current_entity.id and not current_entity.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to rescan this entity")

    manifest = {"agents": body.agents, "tasks": body.tasks, "code": body.code}
    scan = await do_rescan(db, entity, manifest)

    await log_action(
        db,
        action="bridges.crewai.rescan",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=entity_id,
        details={
            "scan_result": scan.scan_result,
            "framework": entity.framework_source or "crewai",
        },
    )

    return _scan_to_out(scan)


# --- Status Endpoint ---


@router.get(
    "/status",
    response_model=FrameworkStatusOut,
    dependencies=[Depends(rate_limit_reads)],
)
async def bridge_status(
    db: AsyncSession = Depends(get_db),
):
    """List supported frameworks and entity counts per framework.

    Public endpoint — no authentication required for status check.
    """
    from src.bridges.openclaw.registry import get_framework_stats

    stats = await get_framework_stats(db)
    # Ensure all frameworks are listed
    stats["supported_frameworks"] = [
        "mcp", "openclaw", "langchain", "crewai", "autogen", "semantic_kernel",
        "pydantic_ai",
    ]
    return FrameworkStatusOut(**stats)


# --- AutoGen Endpoints ---


@router.post(
    "/autogen/import",
    response_model=ImportResult,
    dependencies=[Depends(rate_limit_writes)],
)
async def import_autogen_agent(
    manifest: AutoGenManifest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Import an AutoGen agent manifest into AgentAvow.

    Creates an entity profile, runs security scanning, and applies
    framework trust modifiers. The importing user becomes the agent operator.
    """
    from src.audit import log_action
    from src.bridges.autogen.registry import import_autogen_agent as do_import

    agent, scan = await do_import(
        db=db,
        manifest=manifest.model_dump(),
        operator_entity=current_entity,
    )

    await log_action(
        db,
        action="bridges.autogen.import",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=agent.id,
        details={
            "agent_name": agent.display_name,
            "scan_result": scan.scan_result,
            "framework": "autogen",
        },
    )

    return ImportResult(
        entity_id=str(agent.id),
        display_name=agent.display_name,
        framework_source=agent.framework_source or "autogen",
        framework_trust_modifier=agent.framework_trust_modifier or 1.0,
        scan=_scan_to_out(scan),
    )


@router.get(
    "/autogen/scan/{entity_id}",
    response_model=ScanResultOut,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_autogen_scan(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get the latest security scan result for an AutoGen entity."""
    from src.bridges.autogen.registry import get_latest_scan

    scan = await get_latest_scan(db, entity_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="No scan found for this entity")

    return _scan_to_out(scan)


@router.post(
    "/autogen/rescan/{entity_id}",
    response_model=ScanResultOut,
    dependencies=[Depends(rate_limit_writes)],
)
async def rescan_autogen_entity(
    entity_id: uuid.UUID,
    body: AutoGenRescanRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a rescan of an AutoGen entity with updated agents/code.

    Only the operator or an admin can rescan an entity.
    A clean rescan removes the trust penalty (sets modifier to 1.0).
    """
    from src.audit import log_action
    from src.bridges.autogen.registry import rescan_entity as do_rescan

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Authorization: must be operator or admin
    if entity.operator_id != current_entity.id and not current_entity.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to rescan this entity")

    manifest = {
        "agents": body.agents,
        "code_execution_config": body.code_execution_config,
        "code": body.code,
    }
    scan = await do_rescan(db, entity, manifest)

    await log_action(
        db,
        action="bridges.autogen.rescan",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=entity_id,
        details={
            "scan_result": scan.scan_result,
            "framework": entity.framework_source or "autogen",
        },
    )

    return _scan_to_out(scan)


# --- Semantic Kernel Endpoints ---


@router.post(
    "/semantic-kernel/import",
    response_model=ImportResult,
    dependencies=[Depends(rate_limit_writes)],
)
async def import_sk_agent(
    manifest: SemanticKernelManifest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Import a Semantic Kernel agent manifest into AgentAvow.

    Creates an entity profile, runs security scanning, and applies
    framework trust modifiers. The importing user becomes the agent operator.
    """
    from src.audit import log_action
    from src.bridges.semantic_kernel.registry import import_sk_agent as do_import

    agent, scan = await do_import(
        db=db,
        manifest=manifest.model_dump(),
        operator_entity=current_entity,
    )

    await log_action(
        db,
        action="bridges.semantic_kernel.import",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=agent.id,
        details={
            "agent_name": agent.display_name,
            "scan_result": scan.scan_result,
            "framework": "semantic_kernel",
        },
    )

    return ImportResult(
        entity_id=str(agent.id),
        display_name=agent.display_name,
        framework_source=agent.framework_source or "semantic_kernel",
        framework_trust_modifier=agent.framework_trust_modifier or 1.0,
        scan=_scan_to_out(scan),
    )


@router.get(
    "/semantic-kernel/scan/{entity_id}",
    response_model=ScanResultOut,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_sk_scan(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get the latest security scan result for a Semantic Kernel entity."""
    from src.bridges.semantic_kernel.registry import get_latest_scan

    scan = await get_latest_scan(db, entity_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="No scan found for this entity")

    return _scan_to_out(scan)


@router.post(
    "/semantic-kernel/rescan/{entity_id}",
    response_model=ScanResultOut,
    dependencies=[Depends(rate_limit_writes)],
)
async def rescan_sk_entity(
    entity_id: uuid.UUID,
    body: SemanticKernelRescanRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a rescan of a Semantic Kernel entity with updated plugins/code.

    Only the operator or an admin can rescan an entity.
    A clean rescan removes the trust penalty (sets modifier to 1.0).
    """
    from src.audit import log_action
    from src.bridges.semantic_kernel.registry import rescan_entity as do_rescan

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Authorization: must be operator or admin
    if entity.operator_id != current_entity.id and not current_entity.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to rescan this entity")

    manifest = {
        "plugins": body.plugins,
        "planner_config": body.planner_config,
        "code": body.code,
    }
    scan = await do_rescan(db, entity, manifest)

    await log_action(
        db,
        action="bridges.semantic_kernel.rescan",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=entity_id,
        details={
            "scan_result": scan.scan_result,
            "framework": entity.framework_source or "semantic_kernel",
        },
    )

    return _scan_to_out(scan)


# --- Pydantic AI Endpoints ---


@router.post(
    "/pydantic-ai/import",
    response_model=ImportResult,
    dependencies=[Depends(rate_limit_writes)],
)
async def import_pydantic_ai_agent(
    manifest: PydanticAIManifest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Import a Pydantic AI agent manifest into AgentAvow.

    Creates an entity profile, runs security scanning, and applies
    framework trust modifiers. The importing user becomes the agent operator.
    """
    from src.audit import log_action
    from src.bridges.pydantic_ai.registry import import_pydantic_ai_agent as do_import

    agent, scan = await do_import(
        db=db,
        manifest=manifest.model_dump(),
        operator_entity=current_entity,
    )

    await log_action(
        db,
        action="bridges.pydantic_ai.import",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=agent.id,
        details={
            "agent_name": agent.display_name,
            "scan_result": scan.scan_result,
            "framework": "pydantic_ai",
        },
    )

    return ImportResult(
        entity_id=str(agent.id),
        display_name=agent.display_name,
        framework_source=agent.framework_source or "pydantic_ai",
        framework_trust_modifier=agent.framework_trust_modifier or 1.0,
        scan=_scan_to_out(scan),
    )


@router.get(
    "/pydantic-ai/scan/{entity_id}",
    response_model=ScanResultOut,
    dependencies=[Depends(rate_limit_reads)],
)
async def get_pydantic_ai_scan(
    entity_id: uuid.UUID,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Get the latest security scan result for a Pydantic AI entity."""
    from src.bridges.pydantic_ai.registry import get_latest_scan

    scan = await get_latest_scan(db, entity_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="No scan found for this entity")

    return _scan_to_out(scan)


@router.post(
    "/pydantic-ai/rescan/{entity_id}",
    response_model=ScanResultOut,
    dependencies=[Depends(rate_limit_writes)],
)
async def rescan_pydantic_ai_entity(
    entity_id: uuid.UUID,
    body: PydanticAIRescanRequest,
    current_entity: Entity = Depends(get_current_entity),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a rescan of a Pydantic AI entity with updated tools/code.

    Only the operator or an admin can rescan an entity.
    A clean rescan removes the trust penalty (sets modifier to 1.0).
    """
    from src.audit import log_action
    from src.bridges.pydantic_ai.registry import rescan_entity as do_rescan

    entity = await db.get(Entity, entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")

    # Authorization: must be operator or admin
    if entity.operator_id != current_entity.id and not current_entity.is_admin:
        raise HTTPException(status_code=403, detail="Not authorized to rescan this entity")

    manifest = {
        "tools": body.tools,
        "system_prompt": body.system_prompt,
        "code": body.code,
    }
    scan = await do_rescan(db, entity, manifest)

    await log_action(
        db,
        action="bridges.pydantic_ai.rescan",
        entity_id=current_entity.id,
        resource_type="entity",
        resource_id=entity_id,
        details={
            "scan_result": scan.scan_result,
            "framework": entity.framework_source or "pydantic_ai",
        },
    )

    return _scan_to_out(scan)


# --- Discovery & Health Endpoints ---


@router.get(
    "/discover",
    response_model=DiscoveryResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def bridge_discover():
    """Discover all supported framework bridges with capabilities and import schemas.

    Public endpoint — no authentication required.
    """
    from src.bridges.health import get_bridge_discovery

    frameworks = get_bridge_discovery()
    return DiscoveryResponse(
        frameworks=[BridgeCapability(**f) for f in frameworks],
    )


@router.get(
    "/health",
    response_model=list[BridgeHealthOut],
    dependencies=[Depends(rate_limit_reads)],
)
async def bridge_health():
    """Check health status of all bridge modules.

    Public endpoint — no authentication required.
    """
    from src.bridges.health import check_bridge_health

    results = check_bridge_health()
    return [BridgeHealthOut(**r) for r in results]
