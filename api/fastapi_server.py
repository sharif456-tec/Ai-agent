from fastapi import FastAPI
from datetime import datetime

app = FastAPI(title="AI Security Command Center")

@app.get('/api/health')
def health():
    return {"agent":"online","time":datetime.utcnow().isoformat()}

@app.post('/api/scan')
def scan():
    return {"status":"queued","message":"Security scan started"}
