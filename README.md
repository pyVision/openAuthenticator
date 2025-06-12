# Open Authenticator

This is a simple FastAPI application demonstrating one-time password (OTP) based authentication. The OTP logic and client behaviour are adapted from the [domain-sentinel](https://github.com/pyVision/domain-sentinel) project.

## Running

Install dependencies using poetry and run the application with uvicorn:

```bash
poetry install
poetry run uvicorn open_authenticator.main:app --reload
```

Navigate to `http://localhost:8000` to test the OTP flow.
