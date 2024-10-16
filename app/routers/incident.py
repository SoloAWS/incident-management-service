# incident.py (router)
from fastapi import APIRouter, Depends, HTTPException, Header
from ..schemas.incident import UserCompanyRequest, IncidentsResponse, CreateIncidentRequest, CreateIncidentResponse
import jwt
import requests
import os

router = APIRouter(prefix="/incident-management", tags=["Incidents"])

INCIDENT_SERVICE_COMMAND_URL = os.getenv("INCIDENT_SERVICE_COMMAND_URL", "http://192.168.68.111:8003/incident-command-receptor")

SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'secret_key')
ALGORITHM = "HS256"

def get_current_user(token: str = Header(None)):
    if token is None:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None

def create_incident_in_database(incident_data: dict, token: str):
    api_url = INCIDENT_SERVICE_COMMAND_URL
    endpoint = "/"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(f"{api_url}{endpoint}", headers=headers, json=incident_data)
    return response.json(), response.status_code

@router.post("/", response_model=CreateIncidentResponse, status_code=201)
async def create_incident(
    incident: CreateIncidentRequest,
    current_user: dict = Depends(get_current_user)
):
    token = jwt.encode(current_user, SECRET_KEY, algorithm=ALGORITHM)
    incident_data = incident.dict()
    response_data, status_code = create_incident_in_database(incident_data, token)
    
    if status_code != 201:
        raise HTTPException(status_code=status_code, detail=response_data)
    
    return CreateIncidentResponse(**response_data)