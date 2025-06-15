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
    period: int = 30  # Default to 30 seconds per RFC 6238
    created_at: datetime = Field(default_factory=datetime.utcnow)

# In-memory store mapping user -> labels -> TOTP entries
_totps: dict[str, dict[str, TOTPCreate]] = {}

@app.post("/users/{user}/totp")
def add_totp(user: str, data: TOTPCreate):
    user_totps = _totps.setdefault(user, {})
    if data.label in user_totps:
        raise HTTPException(status_code=400, detail="TOTP already exists")
    
    # Try to parse URI if secret looks like a otpauth:// URI
    if data.secret.startswith('otpauth://totp/'):
        try:
            # Extract parameters from the URI
            import urllib.parse
            uri = data.secret
            parsed = urllib.parse.urlparse(uri)
            params = dict(urllib.parse.parse_qsl(parsed.query))
            
            # Extract the actual secret and other parameters
            if 'secret' in params:
                data.secret = params['secret']
            if 'period' in params:
                data.period = int(params['period'])
            if 'issuer' in params:
                data.issuer = params['issuer']
        except Exception as e:
            # If parsing fails, keep the original data
            print(f"Error parsing TOTP URI: {e}")
    
    # Clean and validate the secret key
    try:
        # Remove spaces, make uppercase and strip padding if present
        data.secret = data.secret.replace(" ", "").upper().rstrip('=')
        
        # Validate that the secret is actually valid base32
        test_totp = pyotp.TOTP(data.secret)
        # Generate a code to check if it works (will raise ValueError if invalid)
        test_totp.now()
        
        user_totps[data.label] = data
        return {"message": f"Added {data.label}"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid TOTP secret: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating TOTP: {str(e)}")

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
    
    try:
        # Clean the secret to ensure it's valid base32
        secret = entry.secret.replace(" ", "").upper().rstrip('=')
        
        # Use the period from the entry, or default to 30 seconds
        period = getattr(entry, "period", 30)
        totp = pyotp.TOTP(secret, interval=period)
        
        # Calculate remaining time for this TOTP code based on the period
        now = datetime.utcnow()
        remaining = period - (now.timestamp() % period)
        progress = (period - remaining) / period  # Progress from 0 to 1
        
        return {
            "label": label, 
            "code": totp.now(),
            "remaining_seconds": remaining,
            "progress": progress,
            "period": period  # Include the period in the response
        }
    except ValueError as e:
        # If there's a problem with the secret format
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid TOTP secret for {label}: {str(e)}. Please delete and re-add this entry."
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating TOTP code: {str(e)}")
