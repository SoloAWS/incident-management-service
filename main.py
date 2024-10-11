from fastapi import FastAPI

app = FastAPI()

@app.get("/incident-management")
async def incident_management_root():
    return {"message": "Incident Management Hello World"}

@app.get("/incident-management/health")
async def health():
    return {"status": "OK"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)