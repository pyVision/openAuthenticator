from datetime import datetime

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import pyotp

app = FastAPI(title="openAuthenticator")

class TOTPCreate(BaseModel):
    label: str
    login_id: str
    secret: str
    issuer: str | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

# In-memory store mapping user -> labels -> TOTP entries
_totps: dict[str, dict[str, TOTPCreate]] = {}

@app.post("/users/{user}/totp")
def add_totp(user: str, data: TOTPCreate):
    user_totps = _totps.setdefault(user, {})
    if data.label in user_totps:
        raise HTTPException(status_code=400, detail="TOTP already exists")
    user_totps[data.label] = data
    return {"message": f"Added {data.label}"}

@app.delete("/users/{user}/totp/{label}")
def delete_totp(user: str, label: str):
    user_totps = _totps.get(user)
    if not user_totps or label not in user_totps:
        raise HTTPException(status_code=404, detail="TOTP not found")
    del user_totps[label]
    return {"message": f"Deleted {label}"}

@app.get("/users/{user}/totp")
def list_totps(user: str):
    return list(_totps.get(user, {}).values())

@app.get("/users/{user}/totp/{label}")
def get_totp(user: str, label: str):
    entry = _totps.get(user, {}).get(label)
    if not entry:
        raise HTTPException(status_code=404, detail="TOTP not found")
    return entry

@app.get("/users/{user}/totp/{label}/code")
def get_current_code(user: str, label: str):
    entry = _totps.get(user, {}).get(label)
    if not entry:
        raise HTTPException(status_code=404, detail="TOTP not found")
    totp = pyotp.TOTP(entry.secret)
    return {"label": label, "code": totp.now()}
