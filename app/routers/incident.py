# incident.py (router)
from fastapi import APIRouter, Depends, HTTPException
from ..schemas.incident import UserCompanyRequest, IncidentsResponse, CreateIncidentRequest, CreateIncidentResponse
import jwt
import requests
import os

router = APIRouter(prefix="/incident-management", tags=["Incidents"])

# URL of the microservice that actually accesses the database
DATABASE_SERVICE_URL = os.getenv("DATABASE_SERVICE_URL", "http://localhost:8003/incident")

SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'secret_key')
ALGORITHM = "HS256"

def get_current_user(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_incidents_from_database(user_id: str, company_id: str, token: str):
    api_url = DATABASE_SERVICE_URL
    endpoint = "/user-incidents"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    data = {
        "user_id": user_id,
        "company_id": company_id
    }
    response = requests.post(f"{api_url}{endpoint}", headers=headers, json=data)
    return response.json(), response.status_code

def create_incident_in_database(incident_data: dict, token: str):
    api_url = DATABASE_SERVICE_URL
    endpoint = "/"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    response = requests.post(f"{api_url}{endpoint}", headers=headers, json=incident_data)
    return response.json(), response.status_code

@router.post("/user-incidents", response_model=IncidentsResponse)
async def get_user_incidents(
    request: UserCompanyRequest,
   # current_user: dict = Depends(get_current_user)
):
    #token = jwt.encode(current_user, SECRET_KEY, algorithm=ALGORITHM)
    incidents_data, status_code = get_incidents_from_database(
        str(request.user_id), 
        str(request.company_id), 
        'token'
    )
    
    if status_code != 200:
        raise HTTPException(status_code=status_code, detail=incidents_data)
    
    return IncidentsResponse(**incidents_data)

@router.post("/incidents", response_model=CreateIncidentResponse)
async def create_incident(
    incident: CreateIncidentRequest,
    #current_user: dict = Depends(get_current_user)
):
    #token = jwt.encode(current_user, SECRET_KEY, algorithm=ALGORITHM)
    incident_data = incident.dict()
    response_data, status_code = create_incident_in_database(incident_data, 'token')
    
    if status_code != 201:
        raise HTTPException(status_code=status_code, detail=response_data)
    
    return CreateIncidentResponse(**response_data)