# openAuthenticator

This project provides a small FastAPI application for managing Time-based One
Time Password (TOTP) secrets. Each TOTP entry stores useful account metadata
such as the login identifier, issuer and the creation date. Users can add,
delete, list and view the current code for their registered labels. The API
organizes TOTP data per user, so each endpoint is prefixed with `/users/{user}`.

Run the development server with:

```bash
PYTHONPATH=src python -m openauthenticator.main
```

The package itself lives under `src/openauthenticator`.

Example API usage:

```
POST   /users/alice/totp       # add a TOTP for user "alice"
GET    /users/alice/totp       # list Alice's TOTP entries
GET    /users/alice/totp/site/code
```
