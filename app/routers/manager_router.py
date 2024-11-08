from fastapi import APIRouter, Depends, HTTPException, Header
from fastapi.responses import JSONResponse
import httpx
import os

router = APIRouter(prefix="/incident-management/manager", tags=["Manager"])

QUERY_INCIDENT_SERVICE_URL = os.getenv('QUERY_INCIDENT_SERVICE_URL', 'http://localhost:8006/incident-query')

async def proxy_request(
    endpoint: str, 
    method: str = "GET", 
    headers: dict = None, 
    params: dict = None
):
    """
    Proxies a request to the incident-query service.
    """
    url = f"{QUERY_INCIDENT_SERVICE_URL}{endpoint}"
    try:
        async with httpx.AsyncClient() as client:
            response = await client.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
            )
            return JSONResponse(
                status_code=response.status_code,
                content=response.json(),
            )
    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to connect to incident-query service: {exc}"
        )

@router.get("/assigned-incidents")
async def proxy_assigned_incidents(authorization: str = Header(None)):
    """
    Proxy the `assigned-incidents` endpoint to the incident-query microservice.
    """
    headers = {"Authorization": authorization}
    return await proxy_request("/manager/assigned-incidents", headers=headers)

@router.get("/daily-stats")
async def proxy_daily_stats(authorization: str = Header(None)):
    """
    Proxy the `daily-stats` endpoint to the incident-query microservice.
    """
    headers = {"Authorization": authorization}
    return await proxy_request("/manager/daily-stats", headers=headers)

@router.get("/high-priority-assigned-incidents")
async def proxy_high_priority_assigned_incidents(authorization: str = Header(None)):
    """
    Proxy the `high-priority-assigned-incidents` endpoint to the incident-query microservice.
    """
    headers = {"Authorization": authorization}
    return await proxy_request("/manager/high-priority-assigned-incidents", headers=headers)
