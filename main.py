# incident-management-service/main.py

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class Incident(BaseModel):
    user_id: int

@app.get("/incident-management")
async def incident_management_root():
    return {"message": "Incident Management Nueva cuenta"}

@app.get("/incident-management/health")
async def health():
    return {"status": "OK"}

@app.post("/incident-management/incidents")
async def create_incident(incident: Incident):
    # Here you would typically save the incident to a database
    return {"message": f"Incident created for user {incident.user_id}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)