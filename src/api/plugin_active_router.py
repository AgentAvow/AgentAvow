"""POST /api/v1/public/plugin/active: the Claude Code plugin's once-a-day "active" request.

The plugin's session-start hook (plugins/agentavow-trust/scripts/agentavow_precheck.py,
0.1.41 and later) sends it at most once per UTC day so the admin dashboard can count the
machines the plugin protects, including the many session starts that answer from the
local cache and send no scan. It carries the anonymous install ID header
(X-AgentAvow-Install), a User-Agent of ``agentavow-active/<version>`` and a JSON body of
``{"version": "0.1.41", "app": "desktop|cli|sdk|cloud|other"}``. Nothing else is read.
Recording and storage live in src/install_activity (keyed hash only, no IP).

It answers 204 whatever it was sent, so the endpoint reveals nothing, and it sits outside
/public/scan so it is never counted as a scan or a plugin check.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request, Response

from src.api.rate_limit import _get_client_ip, rate_limit_analytics
from src.install_activity import PING_MAX_BODY, handle_active_ping

router = APIRouter(prefix="/public/plugin", tags=["public-plugin"])


@router.post("/active", status_code=204, response_class=Response,
             dependencies=[Depends(rate_limit_analytics)], include_in_schema=False)
async def plugin_active(request: Request) -> Response:
    try:
        body = b""
        async for chunk in request.stream():
            body += chunk
            if len(body) > PING_MAX_BODY:
                body = b""
                break
        await handle_active_ping(request.headers, body, _get_client_ip(request))
    except Exception:
        pass  # never an error back to the plugin
    return Response(status_code=204)
