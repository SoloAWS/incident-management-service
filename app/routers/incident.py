# incident.py (router)
from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, Header, File, UploadFile, Form
from ..schemas.incident import IncidentChannel, IncidentPriority, IncidentState, IncidentHistory, UserCompanyRequest, IncidentsResponse, CreateIncidentRequest, CreateIncidentResponse, IncidentsDetailResponse, IncidentDetailResponse, UserDetailsResponse, ManagerDetailsResponse, IncidentDetailWithUsersResponse,IncidentUserResponse, IncidentsUserListResponse
import jwt
import requests
import os
import json
from typing import Optional

router = APIRouter(prefix="/incident-management", tags=["Incidents"])

INCIDENT_SERVICE_COMMAND_URL = os.getenv("INCIDENT_SERVICE_COMMAND_URL", "http://192.168.68.111:8003/incident-command-receptor")
QUERY_INCIDENT_SERVICE_URL = os.getenv("QUERY_INCIDENT_SERVICE_URL", "http://192.168.68.111:8006/incident-query")
USER_SERVICE_URL = os.getenv("USER_SERVICE_URL", "http://192.168.68.111:8002/user")

SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'secret_key')
ALGORITHM = "HS256"

def get_current_user(authorization: str = Header(None)):
    if authorization is None:
        return None
    try:
        token = authorization.replace('Bearer ', '') if authorization.startswith('Bearer ') else authorization
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None
    
def get_user_incidents_from_database(token: str):
    api_url = QUERY_INCIDENT_SERVICE_URL
    endpoint = "/incidents-user"
    headers = {
        "Authorization": f"{token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(f"{api_url}{endpoint}", headers=headers)
        return response.json(), response.status_code
    except requests.exceptions.RequestException as e:
        return {"error": f"Failed to connect to incident service: {str(e)}"}, 500

def get_item_by_id_from_database(token: str, id: str, api_url: str):
    endpoint = f"/{id}"
    headers = {
        "Authorization": f"{token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(f"{api_url}{endpoint}", headers=headers)
        return response.json(), response.status_code
    except requests.exceptions.RequestException as e:
        return {"error": f"Failed to connect to {api_url} service: {str(e)}"}, 500
  
def get_incidents_from_database(token: str):
    api_url = QUERY_INCIDENT_SERVICE_URL
    endpoint = "/all-incidents"
    headers = {
        "Authorization": f"{token}",
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.get(f"{api_url}{endpoint}", headers=headers)
        return response.json(), response.status_code
    except requests.exceptions.RequestException as e:
        return {"error": f"Failed to connect to incident service: {str(e)}"}, 500

def get_company_names_from_service(token: str, company_ids: list):
    api_url = USER_SERVICE_URL
    endpoint = "/company/get-by-id"
    headers = {
        "Authorization": f"{token}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "company_ids": company_ids
    }

    try:
        response = requests.post(f"{api_url}{endpoint}", headers=headers, json=payload)
        return response.json(), response.status_code
    except requests.exceptions.RequestException as e:
        return {"error": f"Failed to connect to company service: {str(e)}"}, 500

def create_incident_in_database(incident_data: CreateIncidentRequest, token: str):
    api_url = INCIDENT_SERVICE_COMMAND_URL
    endpoint = "/"
    headers = {
        "Authorization": f"{token}",
        "Content-Type": "application/json"
    }
    
    data = incident_data.model_dump_json()
    
    response = requests.post(f"{api_url}{endpoint}", headers=headers, data=data)
    return response.json(), response.status_code

def create_incident_in_database_user(incident_data: dict, token: str, file: Optional[UploadFile] = None):
    api_url = INCIDENT_SERVICE_COMMAND_URL
    endpoint = "/user-incident"
    headers = {
        "Authorization": f"{token}",
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

@router.post("/create", response_model=CreateIncidentResponse, status_code=201)
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
    current_user: dict = Depends(get_current_user)
):
    incident_data = CreateIncidentRequest(
        user_id=user_id,
        company_id=company_id,
        description=description,
        state=state,
        channel=channel,
        priority=priority
    )

    token = jwt.encode(current_user, SECRET_KEY, algorithm=ALGORITHM)
    
    response_data, status_code = create_incident_in_database_user(incident_data.dict(), token, file)
    
    if status_code != 201:
        raise HTTPException(status_code=status_code, detail=response_data)
    
    return CreateIncidentResponse(**response_data)


@router.get("/all-incidents", response_model=IncidentsDetailResponse)
async def get_incidents(
    current_user: dict = Depends(get_current_user)
):
    token = jwt.encode(current_user, SECRET_KEY, algorithm=ALGORITHM)
    response_data, status_code = get_incidents_from_database(token)

    if status_code != 200:
        raise HTTPException(status_code=status_code, detail=response_data)
    
    if not response_data:
        return IncidentsDetailResponse(incidents=[])
    
    company_ids = list(set(incident['company_id'] for incident in response_data))

    companies_data, company_status_code = get_company_names_from_service(token, company_ids)
    
    if company_status_code != 200:
        company_names = {str(company_id): "Unknown" for company_id in company_ids}
    else:
        company_names = {str(company['company_id']): company['name'] for company in companies_data}
        
    detailed_incidents = []
    for incident in response_data:
        detailed_incident = IncidentDetailResponse(
            id=incident['id'],
            description=incident['description'],
            state=incident['state'],
            channel=incident['channel'],
            priority=incident['priority'],
            creation_date=incident['creation_date'],
            user_id=incident['user_id'],
            company_id=incident['company_id'],
            company_name=company_names.get(str(incident['company_id']), "Unknown"),
            manager_id=incident['manager_id']
        )
        detailed_incidents.append(detailed_incident)
    
    
    return IncidentsDetailResponse(incidents=detailed_incidents)

@router.get("/{incident_id}", response_model=IncidentDetailWithUsersResponse)
async def get_incident_by_id(
    incident_id: UUID,
    current_user: dict = Depends(get_current_user)
):
    token = jwt.encode(current_user, SECRET_KEY, algorithm=ALGORITHM)
    
    incident_data, status_code = get_item_by_id_from_database(token, str(incident_id), QUERY_INCIDENT_SERVICE_URL)
    
    if status_code != 200:
        raise HTTPException(status_code=status_code, detail=incident_data)
    
    company_ids = [incident_data['company_id']]
    companies_data, company_status_code = get_company_names_from_service(token, company_ids)
    
    company_name = "Unknown"
    if company_status_code == 200:
        company_names = {str(company['company_id']): company['name'] for company in companies_data}
        company_name = company_names.get(str(incident_data['company_id']), "Unknown")
    
    user_data, user_status_code = get_item_by_id_from_database(token, incident_data['user_id'], f"{USER_SERVICE_URL}/user")
    user_details = UserDetailsResponse(**user_data) if user_status_code == 200 else None
    
    manager_details = None
    if incident_data.get('manager_id'):
        manager_data, manager_status_code = get_item_by_id_from_database(token, incident_data['manager_id'], f"{USER_SERVICE_URL}/manager")
        if manager_status_code == 200:
            manager_details = ManagerDetailsResponse(**manager_data)
            
    history_records = [
        IncidentHistory(
            description=record['description'],
            created_at=record['created_at']
        ) for record in incident_data.get('history', [])
    ]
    
    detailed_incident = IncidentDetailWithUsersResponse(
        id=incident_data['id'],
        description=incident_data['description'],
        state=incident_data['state'],
        channel=incident_data['channel'],
        priority=incident_data['priority'],
        creation_date=incident_data['creation_date'],
        user_id=incident_data['user_id'],
        user_details=user_details,
        company_id=incident_data['company_id'],
        company_name=company_name,
        manager_id=incident_data.get('manager_id'),
        manager_details=manager_details,
        history=history_records
    )
    
    return detailed_incident

@router.get("/incidents-user", response_model=IncidentsUserListResponse)
async def get_user_incidents_summary(
    current_user: dict = Depends(get_current_user)
):
    token = jwt.encode(current_user, SECRET_KEY, algorithm=ALGORITHM)
    
    incidents_data, status_code = get_user_incidents_from_database(token)
    
    if status_code != 200:
        raise HTTPException(status_code=status_code, detail=incidents_data)
    
    if not incidents_data:
        return IncidentsUserListResponse(incidents=[])
    
    company_ids = list(set(incident['company_id'] for incident in incidents_data))
    
    companies_data, company_status_code = get_company_names_from_service(token, company_ids)
    
    company_names = {}
    if company_status_code == 200:
        company_names = {
            str(company['company_id']): company['name'] 
            for company in companies_data
        }
    
    incidents_summary = []
    for incident in incidents_data:
        company_name = company_names.get(str(incident['company_id']), "Unknown")
        
        incident_summary = IncidentUserResponse(
            creation_date=incident['creation_date'],
            state=incident['state'],
            priority=incident['priority'],
            description=incident['description'],
            company_name=company_name
        )
        incidents_summary.append(incident_summary)
    
    return IncidentsUserListResponse(incidents=incidents_summary)