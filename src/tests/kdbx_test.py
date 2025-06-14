import os
import io
import uuid
import secrets
import logging
import tempfile
import datetime
import hashlib
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, BinaryIO


from src.open_authenticator.kdbx_manager import KdbxManager


def test_kdbx_manager():
    """Test function for KdbxManager functionality."""
    import tempfile
    import shutil
    
    # Create a temporary directory for testing
    test_dir = tempfile.mkdtemp()
    
    try:
        print("\n===== Testing KdbxManager =====")
        
        # Initialize manager
        print("\nInitializing KdbxManager...")
        manager = KdbxManager(log_level=logging.INFO)
        
        # Generate test database path
        test_db_path = os.path.join(test_dir, "test.kdbx")
        test_password = "TestPassword123!"
        
        # Test database creation
        print("\nCreating test database...")
        manager.create_database(test_db_path, test_password)
        
        # Get database metadata
        print("\nGetting database metadata...")
        metadata = manager.get_database_metadata()
        print(f"KDBX Version: {metadata['kdbx_version']}")
        print(f"Cipher: {metadata['cipher']}")
        print(f"KDF Type: {metadata['kdf']['type']}")
        print(f"Entries: {metadata['statistics']['entries']}")
        print(f"Groups: {metadata['statistics']['groups']}")
        
        # Add entries
        print("\nAdding entries...")
        banking_group = manager.find_group("Banking")
        
        # Generate secure password
        print("Generating secure password...")
        secure_password = manager.generate_password(length=24, special=True)
        print(f"Generated password: {secure_password}")
        
        # Add entry
        print("Adding banking entry...")
        bank_entry = manager.add_entry(
            title="Test Bank Account",
            username="testuser",
            password=secure_password,
            url="https://test-bank.example.com",
            notes="Test bank account notes",
            group_name="Banking",
            tags=["banking", "test"]
        )
        
        # Add another entry
        print("Adding email entry...")
        email_entry = manager.add_entry(
            title="Test Email",
            username="test@example.com",
            password=manager.generate_password(),
            url="https://mail.example.com",
            group_name="Email Accounts"
        )
        
        # Add custom field
        print("\nAdding custom field...")
        manager.add_custom_field(bank_entry, "Account Number", "123456789", protect=True)
        
        # Add an attachment
        print("\nCreating and attaching a test file...")
        test_file_path = os.path.join(test_dir, "test_attachment.txt")
        with open(test_file_path, "w") as f:
            f.write("This is a test attachment file.")
            
        manager.attach_file(bank_entry, test_file_path)
        
        # Save database
        print("\nSaving database...")
        manager.save()
        
        # Close and reopen database
        print("\nClosing and reopening database...")
        manager.close()
        manager.open_database(test_db_path, test_password)
        
        # Find entries
        print("\nFinding entries...")
        found_entries = manager.find_entries(title="Test Bank Account")
        if found_entries:
            print(f"Found entry: {found_entries[0].title}")
            
            # Get attachment
            print("\nRetrieving attachment...")
            attachment_data = manager.get_attachment(found_entries[0], "test_attachment.txt")
            if attachment_data:
                print(f"Attachment content: {attachment_data.decode('utf-8')}")
                
                # Save attachment
                saved_attachment_path = os.path.join(test_dir, "saved_attachment.txt")
                print(f"Saving attachment to: {saved_attachment_path}")
                manager.save_attachment(found_entries[0], "test_attachment.txt", saved_attachment_path)
                
        # Update entry
        print("\nUpdating entry...")
        if found_entries:
            manager.update_entry(
                found_entries[0],
                url="https://updated-bank.example.com",
                notes="Updated notes for test"
            )
            
        # Export to CSV
        print("\nExporting to CSV...")
        csv_path = os.path.join(test_dir, "export.csv")
        manager.export_to_csv(csv_path, include_passwords=False)
        
        # Test complete
        print("\n===== Test completed successfully =====")
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\nTest failed: {str(e)}")
        
    finally:
        # Clean up
        if manager.kdbx is not None:
            manager.close()
            
        shutil.rmtree(test_dir)
        print("\nTest cleanup complete.")


if __name__ == "__main__":
    test_kdbx_manager()