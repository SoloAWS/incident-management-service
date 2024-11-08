# incident.py
from fastapi import UploadFile, File
from pydantic import BaseModel, Field
from uuid import UUID
from datetime import datetime
from typing import List, Optional
from enum import Enum

class IncidentState(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    ESCALATED = "escalated"

class IncidentChannel(str, Enum):
    PHONE = "phone"
    EMAIL = "email"
    CHAT = "chat"
    MOBILE = "mobile"

class IncidentPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

class IncidentResponse(BaseModel):
    id: UUID
    description: str
    state: IncidentState
    channel: IncidentChannel
    priority: IncidentPriority
    creation_date: datetime
    user_id: UUID
    company_id: UUID
    manager_id: UUID
    
class IncidentDetailResponse(BaseModel):
    id: UUID
    description: str
    state: IncidentState
    channel: IncidentChannel
    priority: IncidentPriority
    creation_date: datetime
    user_id: UUID
    company_id: UUID
    company_name: Optional[str] = None
    manager_id: Optional[UUID] = None

class UserCompanyRequest(BaseModel):
    user_id: UUID
    company_id: UUID

class IncidentsResponse(BaseModel):
    incidents: List[IncidentResponse]
    
class IncidentsDetailResponse(BaseModel):
    incidents: List[IncidentDetailResponse]

class CreateIncidentRequest(BaseModel):
    user_id: str
    company_id: str
    description: str
    state: IncidentState = Field(default=IncidentState.OPEN)
    channel: IncidentChannel
    priority: IncidentPriority

class CreateIncidentResponse(BaseModel):
    id: UUID
    user_id: UUID
    company_id: UUID
    description: str
    state: IncidentState = Field(default=IncidentState.OPEN)
    channel: IncidentChannel
    priority: IncidentPriority
    creation_date: datetime
    
class UserDetailsResponse(BaseModel):
    id: UUID
    username: str
    first_name: str
    last_name: str
    document_id: Optional[str] = None
    document_type: Optional[str] = None
    birth_date: Optional[str] = None
    phone_number: Optional[str] = None
    importance: Optional[int] = None
    allow_call: Optional[bool] = None
    allow_sms: Optional[bool] = None
    allow_email: Optional[bool] = None
    registration_date: datetime

class ManagerDetailsResponse(BaseModel):
    id: UUID
    username: str
    first_name: str
    last_name: str
    
class IncidentHistory(BaseModel):
    description: str
    created_at: datetime

class IncidentDetailWithUsersResponse(BaseModel):
    id: UUID
    description: str
    state: IncidentState
    channel: IncidentChannel
    priority: IncidentPriority
    creation_date: datetime
    user_id: UUID
    user_details: Optional[UserDetailsResponse] = None
    company_id: UUID
    company_name: Optional[str] = None
    manager_id: Optional[UUID] = None
    manager_details: Optional[ManagerDetailsResponse] = None
    history: List[IncidentHistory] 
    
class IncidentUserResponse(BaseModel):
    creation_date: datetime
    state: IncidentState
    priority: IncidentPriority
    description: str
    company_name: str

class IncidentsUserListResponse(BaseModel):
    incidents: List[IncidentUserResponse]