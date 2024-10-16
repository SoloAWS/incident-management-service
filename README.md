# Incident Management Service

This microservice provides a simple API for incident management.

## Setup

1. Clone the repository:

   ```
   git clone https://github.com/SoloAWS/incident-management-service.git
   cd incident-management-service
   ```

2. Create and activate a virtual environment:

   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Running the Service

To run the service locally:

```
uvicorn app.main:app --reload --port 8000
```

The service will be available at `http://localhost:8000`.

## API Endpoints

- `GET /`: Returns a "Hello World" message
- `GET /health`: Health check endpoint

## Docker

To build and run the Docker container:

```
docker build -t incident-management-service .
docker run -p 8000:8000 incident-management-service
```
