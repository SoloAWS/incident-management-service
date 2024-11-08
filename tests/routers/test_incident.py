# test_incident.py
import os
from fastapi.testclient import TestClient
from fastapi import HTTPException, status
from unittest.mock import patch, MagicMock
import pytest
import jwt
from uuid import uuid4
from app.main import app
from app.routers.incident import create_incident_in_database, get_current_user, get_user_incidents_from_database, router as incident_router
from app.schemas.incident import CreateIncidentRequest, CreateIncidentResponse

client = TestClient(app)

SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'secret_key')
ALGORITHM = "HS256"
INCIDENT_SERVICE_COMMAND_URL = "http://192.168.68.111:8003/incident-command-receptor"
QUERY_INCIDENT_SERVICE_URL = "http://192.168.68.111:8006/incident-query"
USER_SERVICE_URL = "http://192.168.68.111:8002/user"

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

def create_token():
    token_data = {
        "sub": str(str(uuid4())),
        "user_type": "company"
    }
    return jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)


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
        "/incident-management/create",
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
        "/incident-management/create",
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
        "/incident-management/create",
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

def test_get_current_user_valid_token():
    with patch('app.routers.incident.jwt.decode') as mock_decode:
        mock_decode.return_value = {'sub': 'test_user', 'user_type': 'manager'}
        user = get_current_user('valid_token')
        assert user == {'sub': 'test_user', 'user_type': 'manager'}

def test_get_incidents_empty():
    with patch('app.routers.incident.get_incidents_from_database') as mock_get_incidents:
        mock_get_incidents.return_value = ([], 200)

        response = client.get(
            "/incident-management/all-incidents",
            headers={"authorization": create_token()}
        )

        assert response.status_code == 200
        assert response.json() == {"incidents": []}
        

@pytest.fixture
def mock_get_incidents():
    with patch('app.routers.incident.get_incidents_from_database') as mock:
        yield mock

@pytest.fixture
def mock_get_company_names():
    with patch('app.routers.incident.get_company_names_from_service') as mock:
        yield mock

@pytest.fixture
def mock_get_item_by_id():
    with patch('app.routers.incident.get_item_by_id_from_database') as mock:
        yield mock

def test_get_incidents_success(mock_get_incidents, mock_get_company_names):
    # Mock incident data
    incidents_data = [{
        'id': str(uuid4()),
        'description': 'Test incident',
        'state': 'open',
        'channel': 'phone',
        'priority': 'medium',
        'creation_date': '2024-01-01T00:00:00',
        'user_id': str(uuid4()),
        'company_id': str(uuid4()),
        'manager_id': str(uuid4())
    }]
    
    # Mock company data
    company_data = [{
        'company_id': incidents_data[0]['company_id'],
        'name': 'Test Company'
    }]
    
    mock_get_incidents.return_value = (incidents_data, 200)
    mock_get_company_names.return_value = (company_data, 200)

    response = client.get(
        "/incident-management/all-incidents",
        headers={"authorization": create_token()}
    )

    assert response.status_code == 200
    assert len(response.json()['incidents']) == 1
    assert response.json()['incidents'][0]['company_name'] == 'Test Company'

def test_get_incidents_failed_company_lookup(mock_get_incidents, mock_get_company_names):
    incidents_data = [{
        'id': str(uuid4()),
        'description': 'Test incident',
        'state': 'open',
        'channel': 'phone',
        'priority': 'medium',
        'creation_date': '2024-01-01T00:00:00',
        'user_id': str(uuid4()),
        'company_id': str(uuid4()),
        'manager_id': str(uuid4())
    }]
    
    mock_get_incidents.return_value = (incidents_data, 200)
    mock_get_company_names.return_value = ({"error": "Failed to get company names"}, 500)

    response = client.get(
        "/incident-management/all-incidents",
        headers={"authorization": create_token()}
    )

    assert response.status_code == 200
    assert response.json()['incidents'][0]['company_name'] == 'Unknown'

def test_create_incident_user_success():
    test_file = MagicMock()
    test_file.filename = "test.txt"
    test_file.content_type = "text/plain"
    
    with patch('app.routers.incident.create_incident_in_database_user') as mock_create:
        mock_create.return_value = ({
            "id": str(uuid4()),
            "user_id": str(uuid4()),
            "company_id": str(uuid4()),
            "description": "Test user incident",
            "state": "open",
            "channel": "mobile",
            "priority": "medium",
            "creation_date": "2024-01-01T00:00:00"
        }, 201)

        response = client.post(
            "/incident-management/user-incident",
            data={
                "user_id": str(uuid4()),
                "company_id": str(uuid4()),
                "description": "Test user incident",
                "state": "open",
                "channel": "mobile",
                "priority": "medium"
            },
            files={"file": ("test.txt", b"test content", "text/plain")},
            headers={"authorization": create_token()}
        )

        assert response.status_code == 201
        assert response.json()["description"] == "Test user incident"

def test_get_current_user_invalid_token():
    with patch('app.routers.incident.jwt.decode') as mock_decode:
        mock_decode.side_effect = jwt.PyJWTError()
        from app.routers.incident import get_current_user
        result = get_current_user('invalid_token')
        assert result is None

def test_get_current_user_no_token():
    from app.routers.incident import get_current_user
    result = get_current_user(None)
    assert result is None
    
def test_get_user_incidents_from_database_success():
    mock_response = MagicMock()
    mock_response.json.return_value = [
        {
            "creation_date": "2024-01-01T00:00:00",
            "state": "open",
            "priority": "medium",
            "description": "Test incident",
            "company_id": str(uuid4())
        }
    ]
    mock_response.status_code = 200
    
    with patch('app.routers.incident.requests.get') as mock_get:
        mock_get.return_value = mock_response
        
        result, status_code = get_user_incidents_from_database('test_token')
        
        mock_get.assert_called_once_with(
            f"{QUERY_INCIDENT_SERVICE_URL}/incidents-user",
            headers={
                "Authorization": "test_token",
                "Content-Type": "application/json"
            }
        )
        
        assert status_code == 200
        assert isinstance(result, list)
        assert len(result) == 1
        assert result[0]["state"] == "open"
        assert result[0]["priority"] == "medium"
        assert "creation_date" in result[0]
        assert "description" in result[0]
        assert "company_id" in result[0]
        
def test_get_user_incidents_summary_service_error(mock_get_current_user, mock_jwt_encode):
    with patch('app.routers.incident.get_user_incidents_from_database') as mock_get_incidents:
        # Mock error response from incident service
        error_response = {
            "error": "Failed to retrieve incidents",
            "detail": "Internal server error"
        }
        mock_get_incidents.return_value = (error_response, 500)

        response = client.get(
            "/incident-management/incidents-user",
            headers={"authorization": create_token()}
        )

        assert response.status_code == 400
        
def test_get_incidents_success_with_all_fields(mock_get_incidents, mock_get_company_names):
    # Mock incident data with all fields
    incidents_data = [{
        'id': str(uuid4()),
        'description': 'Test incident',
        'state': 'open',
        'channel': 'phone',
        'priority': 'medium',
        'creation_date': '2024-01-01T00:00:00',
        'user_id': str(uuid4()),
        'company_id': str(uuid4()),
        'manager_id': str(uuid4())
    }]
    
    company_data = [{
        'company_id': incidents_data[0]['company_id'],
        'name': 'Test Company'
    }]
    
    mock_get_incidents.return_value = (incidents_data, 200)
    mock_get_company_names.return_value = (company_data, 200)

    response = client.get(
        "/incident-management/all-incidents",
        headers={"authorization": create_token()}
    )

    assert response.status_code == 200
    response_data = response.json()['incidents'][0]
    assert response_data['company_name'] == 'Test Company'
    assert response_data['description'] == 'Test incident'
    assert response_data['state'] == 'open'
    assert response_data['channel'] == 'phone'
    assert response_data['priority'] == 'medium'
    assert 'creation_date' in response_data
    assert 'user_id' in response_data
    assert 'company_id' in response_data
    assert 'manager_id' in response_data

def test_get_incident_by_id_success(mock_get_item_by_id, mock_get_company_names):
    # Mock incident data
    incident_id = str(uuid4())
    user_id = str(uuid4())
    company_id = str(uuid4())
    manager_id = str(uuid4())
    
    incident_data = {
        'id': incident_id,
        'description': 'Test incident',
        'state': 'open',
        'channel': 'phone',
        'priority': 'medium',
        'creation_date': '2024-01-01T00:00:00',
        'user_id': user_id,
        'company_id': company_id,
        'manager_id': manager_id,
        'history': [
            {
                'description': 'Incident created',
                'created_at': '2024-01-01T00:00:00'
            }
        ]
    }
    
    user_data = {
        'id': user_id,
        'username': 'testuser',
        'first_name': 'Test',
        'last_name': 'User',
        'registration_date': '2024-01-01T00:00:00'
    }
    
    manager_data = {
        'id': manager_id,
        'username': 'testmanager',
        'first_name': 'Test',
        'last_name': 'Manager'
    }
    
    company_data = [{
        'company_id': company_id,
        'name': 'Test Company'
    }]

    # Configure mock responses
    mock_get_item_by_id.side_effect = [
        (incident_data, 200),  # First call for incident
        (user_data, 200),      # Second call for user
        (manager_data, 200)    # Third call for manager
    ]
    mock_get_company_names.return_value = (company_data, 200)

    response = client.get(
        f"/incident-management/{incident_id}",
        headers={"authorization": create_token()}
    )

    assert response.status_code == 200
    response_data = response.json()
    assert response_data['description'] == 'Test incident'
    assert response_data['company_name'] == 'Test Company'
    assert response_data['user_details']['username'] == 'testuser'
    assert response_data['manager_details']['username'] == 'testmanager'
    assert len(response_data['history']) == 1
    assert response_data['history'][0]['description'] == 'Incident created'

def test_get_incident_by_id_not_found(mock_get_item_by_id):
    incident_id = str(uuid4())
    error_response = {"detail": "Incident not found"}
    mock_get_item_by_id.return_value = (error_response, 404)

    response = client.get(
        f"/incident-management/{incident_id}",
        headers={"authorization": create_token()}
    )

    assert response.status_code == 404

def test_get_incident_by_id_user_not_found(mock_get_item_by_id, mock_get_company_names):
    incident_id = str(uuid4())
    incident_data = {
        'id': incident_id,
        'description': 'Test incident',
        'state': 'open',
        'channel': 'phone',
        'priority': 'medium',
        'creation_date': '2024-01-01T00:00:00',
        'user_id': str(uuid4()),
        'company_id': str(uuid4()),
        'manager_id': None,
        'history': []
    }
    
    mock_get_item_by_id.side_effect = [
        (incident_data, 200),          # Incident data success
        ({"detail": "Not found"}, 404) # User data not found
    ]
    mock_get_company_names.return_value = ([], 404)

    response = client.get(
        f"/incident-management/{incident_id}",
        headers={"authorization": create_token()}
    )

    assert response.status_code == 200
    response_data = response.json()
    assert response_data['user_details'] is None
    assert response_data['company_name'] == 'Unknown'