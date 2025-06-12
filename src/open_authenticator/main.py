from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, EmailStr
from typing import Optional
import datetime
from pathlib import Path

from .otp_handler import OTPHandler
from .init_application import initialization_result

app = FastAPI()

otp_handler = OTPHandler()

class OTPGenerationRequest(BaseModel):
    email: EmailStr
    operation: str
    force_new: bool = False

class OTPGenerationResponse(BaseModel):
    status: str
    message: str
    email: EmailStr
    created_at: Optional[str] = None
    expires_in: Optional[str] = None
    existing_code: Optional[bool] = False

class OTPVerificationRequest(BaseModel):
    email: EmailStr
    otp: str
    operation: Optional[str] = None

class OTPVerificationResponse(BaseModel):
    status: str
    message: str

class OTPInfoResponse(BaseModel):
    email: EmailStr
    otp: str
    created: str
    expiry: str
    verified: str

@app.post("/api/otp/generate", response_model=OTPGenerationResponse)
async def generate_otp(request: OTPGenerationRequest):
    otp, created_time, is_new = otp_handler.generate_otp(request.email, request.operation, request.force_new)
    if is_new or request.force_new:
        email_sent = otp_handler.send_otp_email(request.email, otp, request.operation, created_time)
        if email_sent:
            creation_date = datetime.datetime.fromisoformat(created_time).strftime("%Y-%m-%d %H:%M:%S")
            expiry_days = int(initialization_result["env_vars"].get("OTP_EXPIRY_DAYS", 30))
            debug_info = f" For testing: {otp}" if initialization_result["debug_mode"] else ""
            return JSONResponse(content={
                "status": "success",
                "message": f"Verification code has been sent to {request.email}.{debug_info} Please check your email and enter the code to continue.",
                "email": request.email,
                "created_at": creation_date,
                "expires_in": f"{expiry_days} days"
            })
        else:
            return JSONResponse(content={
                "status": "warning",
                "message": "OTP generated, but there was an issue sending the email. Please try again or contact support.",
                "email": request.email
            })
    else:
        creation_date = datetime.datetime.fromisoformat(created_time).strftime("%Y-%m-%d %H:%M:%S")
        expiry_days = int(initialization_result["env_vars"].get("OTP_EXPIRY_DAYS", 30))
        return JSONResponse(content={
            "status": "info",
            "message": f"A verification code was already sent to {request.email} on {creation_date}. It remains valid for {expiry_days} days. Please check your email or request a new code if needed.",
            "email": request.email,
            "created_at": creation_date,
            "expires_in": f"{expiry_days} days",
            "existing_code": True
        })

@app.post("/api/otp/verify", response_model=OTPVerificationResponse)
async def verify_otp(request: OTPVerificationRequest):
    success, message = otp_handler.verify_otp(request.email, request.otp)
    if success:
        return {"status": "success", "message": message}
    return JSONResponse(content={"status": "error", "message": message}, status_code=400)


@app.get("/api/otp/list/{email}", response_model=OTPInfoResponse)
async def list_otp(email: EmailStr):
    info = otp_handler.get_otp_info(email)
    if info:
        return {
            "email": info.get("email"),
            "otp": info.get("otp"),
            "created": info.get("created"),
            "expiry": info.get("expiry"),
            "verified": info.get("verified"),
        }
    return JSONResponse(content={"message": "No OTP found"}, status_code=404)

@app.get("/", response_class=HTMLResponse)
async def index():
    with open(Path(__file__).parent / "templates" / "index.html", "r") as f:
        return HTMLResponse(content=f.read())
