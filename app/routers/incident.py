# incident.py (router)
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Header, File, UploadFile, Form
from ..schemas.incident import IncidentChannel, IncidentPriority, IncidentState, UserCompanyRequest, IncidentsResponse, CreateIncidentRequest, CreateIncidentResponse
import jwt
import requests
import os
import json
from typing import Optional

router = APIRouter(prefix="/incident-management", tags=["Incidents"])

INCIDENT_SERVICE_COMMAND_URL = os.getenv("INCIDENT_SERVICE_COMMAND_URL", "http://192.168.68.111:8003/incident-command")

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

def create_incident_in_database(incident_data: CreateIncidentRequest, token: str):
    api_url = INCIDENT_SERVICE_COMMAND_URL
    endpoint = "/"
    headers = {
        "token": f"{token}",
        "Content-Type": "application/json"
    }
    
    data = incident_data.model_dump_json()
    
    response = requests.post(f"{api_url}{endpoint}", headers=headers, data=data)
    return response.json(), response.status_code

def create_incident_in_database_user(incident_data: dict, token: str, file: Optional[UploadFile] = None):
    api_url = INCIDENT_SERVICE_COMMAND_URL
    endpoint = "/user-incident"
    headers = {
        "token": f"{token}",
    }
    
     # Convert UUID to strings
    incident_data['user_id'] = str(incident_data['user_id'])
    incident_data['company_id'] = str(incident_data['company_id'])
    
    # Prepare form data
    form_data = {
        "user_id": incident_data['user_id'],
        "company_id": incident_data['company_id'],
        "description": incident_data['description'],
        "state": incident_data['state'],
        "channel": incident_data['channel'],
        "priority": incident_data['priority']
    }
    
    files = None
    if file:
        files = {"file": (file.filename, file.file, file.content_type)}
    
    response = requests.post(f"{api_url}{endpoint}", headers=headers, data=form_data, files=files)
    return response.json(), response.status_code

@router.post("/", response_model=CreateIncidentResponse, status_code=201)
async def create_incident(
    incident: CreateIncidentRequest,
    current_user: dict = Depends(get_current_user)
):
    token = jwt.encode(current_user, SECRET_KEY, algorithm=ALGORITHM)
    response_data, status_code = create_incident_in_database(incident, token)

    if status_code != 201:
        raise HTTPException(status_code=status_code, detail=response_data)
    
    return CreateIncidentResponse(**response_data)

@router.post("/user-incident", response_model=CreateIncidentResponse, status_code=201)
async def create_incident(
    user_id: str = Form(...),
    company_id: str = Form(...),
    description: str = Form(...),
    state: str = Form(IncidentState.OPEN.value),
    channel: str = Form(IncidentChannel.MOBILE.value),
    priority: str = Form(IncidentPriority.MEDIUM.value),
    file: Optional[UploadFile] = File(None),
    #current_user: dict = Depends(get_current_user)
):
    incident_data = CreateIncidentRequest(
        user_id=user_id,
        company_id=company_id,
        description=description,
        state=state,
        channel=channel,
        priority=priority
    )

    #token = jwt.encode(current_user, SECRET_KEY, algorithm=ALGORITHM)
    
    response_data, status_code = create_incident_in_database_user(incident_data.dict(), 'token', file)
    
    if status_code != 201:
        raise HTTPException(status_code=status_code, detail=response_data)
    
    return CreateIncidentResponse(**response_data)