from __future__ import annotations
from datetime import datetime
import os
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import pyotp

from .kdbx_manager import KdbxManager

VAULT_DIR = Path(os.environ.get("VAULT_DIR", "./vaults"))
VAULT_DIR.mkdir(parents=True, exist_ok=True)
VAULT_PASSWORD = os.environ.get("VAULT_PASSWORD", "ChangeMe!")


def _get_manager(user: str) -> KdbxManager:
    """Open or create a vault for the given user."""
    manager = KdbxManager(log_level=logging.ERROR)
    vault_path = VAULT_DIR / f"{user}.kdbx"
    if vault_path.exists():
        manager.open_database(str(vault_path), password=VAULT_PASSWORD)
    else:
        manager.create_database(str(vault_path), password=VAULT_PASSWORD)
    return manager


def _entry_to_totp(entry) -> TOTPCreate | None:
    """Convert a KDBX entry to ``TOTPCreate`` if possible."""
    secret = entry.get_custom_property("2fa")
    if not secret:
        return None

    issuer = entry.get_custom_property("issuer")
    period = entry.get_custom_property("period")
    created = entry.get_custom_property("created_at")
    created_dt = datetime.fromisoformat(created) if created else datetime.utcnow()

    return TOTPCreate(
        label=entry.title,
        login_id=entry.username or "",
        secret=secret,
        issuer=issuer,
        period=int(period) if period else 30,
        created_at=created_dt,
    )

app = FastAPI(title="openAuthenticator")

class TOTPCreate(BaseModel):
    label: str
    login_id: str
    secret: str
    issuer: str | None = None
    period: int = 30  # Default to 30 seconds per RFC 6238
    created_at: datetime = Field(default_factory=datetime.utcnow)


@app.post("/users/{user}/totp")
def add_totp(user: str, data: TOTPCreate):
    manager = _get_manager(user)
    try:
        if manager.find_entries(title=data.label):
            raise HTTPException(status_code=400, detail="TOTP already exists")

        # Try to parse URI if secret looks like a otpauth:// URI
        if data.secret.startswith('otpauth://totp/'):
            try:
                import urllib.parse
                uri = data.secret
                parsed = urllib.parse.urlparse(uri)
                params = dict(urllib.parse.parse_qsl(parsed.query))

                if 'secret' in params:
                    data.secret = params['secret']
                if 'period' in params:
                    data.period = int(params['period'])
                if 'issuer' in params:
                    data.issuer = params['issuer']
            except Exception as e:
                print(f"Error parsing TOTP URI: {e}")

        # Clean and validate the secret key
        data.secret = data.secret.replace(" ", "").upper().rstrip('=')
        test_totp = pyotp.TOTP(data.secret)
        test_totp.now()

        entry = manager.add_entry(
            title=data.label,
            username=data.login_id,
            password="",
        )
        manager.add_custom_field(entry, "2fa", data.secret, protect=True)
        manager.add_custom_field(entry, "period", str(data.period))
        manager.add_custom_field(entry, "created_at", data.created_at.isoformat())
        if data.issuer:
            manager.add_custom_field(entry, "issuer", data.issuer)

        manager.save()
        return {"message": f"Added {data.label}"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid TOTP secret: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating TOTP: {str(e)}")
    finally:
        manager.close()

@app.delete("/users/{user}/totp/{label}")
def delete_totp(user: str, label: str):
    manager = _get_manager(user)
    try:
        entries = manager.find_entries(title=label)
        if not entries:
            raise HTTPException(status_code=404, detail="TOTP not found")
        manager.delete_entry(entries[0])
        manager.save()
        return {"message": f"Deleted {label}"}
    finally:
        manager.close()

@app.get("/users/{user}/totp")
def list_totps(user: str):
    manager = _get_manager(user)
    try:
        results = []
        for entry in manager.find_entries():
            totp = _entry_to_totp(entry)
            if totp:
                results.append(totp)
        return results
    finally:
        manager.close()

@app.get("/users/{user}/totp/{label}")
def get_totp(user: str, label: str):
    manager = _get_manager(user)
    try:
        entries = manager.find_entries(title=label)
        if not entries:
            raise HTTPException(status_code=404, detail="TOTP not found")
        totp = _entry_to_totp(entries[0])
        if not totp:
            raise HTTPException(status_code=404, detail="TOTP not found")
        return totp
    finally:
        manager.close()

@app.get("/users/{user}/totp/{label}/code")
def get_current_code(user: str, label: str):
    manager = _get_manager(user)
    try:
        entries = manager.find_entries(title=label)
        if not entries:
            raise HTTPException(status_code=404, detail="TOTP not found")

        entry = entries[0]
        secret = entry.get_custom_property("2fa")
        period = entry.get_custom_property("period") or 30
        if not secret:
            raise HTTPException(status_code=404, detail="TOTP not found")

        secret = secret.replace(" ", "").upper().rstrip("=")
        period = int(period)
        totp = pyotp.TOTP(secret, interval=period)

        now = datetime.utcnow()
        remaining = period - (now.timestamp() % period)
        progress = (period - remaining) / period

        return {
            "label": label,
            "code": totp.now(),
            "remaining_seconds": remaining,
            "progress": progress,
            "period": period,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid TOTP secret for {label}: {str(e)}. Please delete and re-add this entry.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating TOTP code: {str(e)}")
    finally:
        manager.close()
