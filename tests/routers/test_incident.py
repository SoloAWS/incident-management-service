# test_incident.py
import os
from fastapi.testclient import TestClient
from fastapi import HTTPException, status
from unittest.mock import patch, MagicMock
import pytest
import jwt
from uuid import uuid4
from app.main import app
from app.routers.incident import create_incident_in_database, get_current_user, router as incident_router
from app.schemas.incident import CreateIncidentRequest, CreateIncidentResponse

client = TestClient(app)

SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'secret_key')
ALGORITHM = "HS256"

@pytest.fixture
def mock_create_incident():
    with patch('app.routers.incident.create_incident_in_database') as mock:
        yield mock

@pytest.fixture
def mock_get_current_user():
    with patch('app.routers.incident.get_current_user') as mock:
        mock.return_value = {'sub': 'test_user', 'user_type': 'manager'}
        yield mock

@pytest.fixture
def mock_jwt_encode():
    with patch('app.routers.incident.jwt.encode') as mock:
        mock.return_value = 'mocked_token'
        yield mock

def test_create_incident_success(mock_create_incident, mock_get_current_user, mock_jwt_encode):
    
    token_data = {
        "sub": str(str(uuid4())),
        "user_type": "company"
    }
    
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
         
    mock_response_data = {
        "id": str(uuid4()),
        "user_id": str(uuid4()),
        "company_id": str(uuid4()),
        "description": "Test incident",
        "state": "open",
        "channel": "phone",
        "priority": "medium",
        "creation_date": "2023-01-01T00:00:00"
    }
    mock_create_incident.return_value = (mock_response_data, 201)

    request_data = {
        "user_id": str(uuid4()),
        "company_id": str(uuid4()),
        "description": "Test incident",
        "state": "open",
        "channel": "phone",
        "priority": "medium"
    }

    response = client.post(
        "/incident-management/",
        json=request_data,
        headers={"token": token}
    )

    print(f"Response status code: {response.status_code}")
    print(f"Response content: {response.content}")

    assert response.status_code == 201, f"Expected 201, but got {response.status_code}. Response: {response.content}"
    assert "id" in response.json()
    assert response.json()["description"] == "Test incident"

def test_create_incident_failure(mock_create_incident, mock_get_current_user, mock_jwt_encode):
    mock_create_incident.return_value = ({"detail": "Error creating incident"}, 400)

    response = client.post(
        "/incident-management/",
        json={
            "user_id": str(uuid4()),
            "company_id": str(uuid4()),
            "description": "Test incident",
            "state": "open",
            "channel": "phone",
            "priority": "medium"
        },
        headers={"Authorization": "Bearer test_token"}
    )

    assert response.status_code == 400

def test_create_incident_invalid_input():
   
    token_data = {
        "sub": str(str(uuid4())),
        "user_type": "company"
    }
    
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    
    response = client.post(
        "/incident-management/",
        json={
            "company_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
            "description": "Sample incident description 4",
            "state": "open",
            "channel": "phone",
            "priority": "medium"
        }, 
        headers={"token": token}
    )

    print(response.json());
    assert response.status_code == 400 

@pytest.mark.asyncio
async def test_create_incident_function(mock_create_incident, mock_jwt_encode):
    mock_create_incident.return_value = ({
        "id": str(uuid4()),
        "user_id": str(uuid4()),
        "company_id": str(uuid4()),
        "description": "Test incident",
        "state": "open",
        "channel": "phone",
        "priority": "medium",
        "creation_date": "2023-01-01T00:00:00"
    }, 201)

    incident = CreateIncidentRequest(
        user_id=str(uuid4()),
        company_id=str(uuid4()),
        description="Test incident",
        state="open",
        channel="phone",
        priority="medium"
    )

    current_user = {'sub': 'test_user', 'user_type': 'manager'}
    response = await incident_router.routes[0].endpoint(incident, current_user)
    
    assert isinstance(response, CreateIncidentResponse)
    assert response.description == "Test incident"
    mock_jwt_encode.assert_called_once_with(current_user, 'secret_key', algorithm="HS256")

def test_get_current_user_valid_token():
    with patch('app.routers.incident.jwt.decode') as mock_decode:
        mock_decode.return_value = {'sub': 'test_user', 'user_type': 'manager'}
        user = get_current_user('valid_token')
        assert user == {'sub': 'test_user', 'user_type': 'manager'}