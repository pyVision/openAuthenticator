import os
import importlib
from pathlib import Path
from src.open_authenticator import api

def test_add_totp_to_vault(tmp_path, monkeypatch):
    monkeypatch.setenv("VAULT_DIR", str(tmp_path))
    monkeypatch.setenv("VAULT_PASSWORD", "testpass")
    importlib.reload(api)

    data = api.TOTPCreate(label="example", login_id="user", secret="JBSWY3DPEHPK3PXP")
    api.add_totp("alice", data)

    manager = api._get_manager("alice")
    try:
        entries = manager.find_entries(title="example")
        assert entries, "Entry not created"
        entry = entries[0]
        assert entry.username == "user"
        assert entry.get_custom_property("2fa") == "JBSWY3DPEHPK3PXP"
    finally:
        manager.close()

