
"""
KdbxManager - A comprehensive class for managing KeePass KDBX databases
Copyright (c) 2025 - Example implementation for educational purposes
"""

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

try:
    from pykeepass import PyKeePass, create_database
    from pykeepass.entry import Entry
    from pykeepass.group import Group
    from pykeepass.exceptions import CredentialsError, HeaderChecksumError
except ImportError:
    raise ImportError("Required libraries not found. Install with: pip install pykeepass")


class KdbxEncryptionType(Enum):
    """Supported encryption types for KDBX files."""
    AES256 = "aes256"
    CHACHA20 = "chacha20"


class KdbxKeyDerivation(Enum):
    """Key derivation functions supported in KDBX."""
    ARGON2 = "argon2"
    AES_KDF = "aes-kdf"


class KdbxError(Exception):
    """Base exception for all KDBX-related errors."""
    pass


class KdbxAuthError(KdbxError):
    """Authentication error for KDBX operations."""
    pass


class KdbxFileError(KdbxError):
    """File-related error for KDBX operations."""
    pass


class KdbxFormatError(KdbxError):
    """Format-related error for KDBX operations."""
    pass


class KdbxManager:
    """
    Comprehensive manager for KeePass KDBX database files.
    
    This class provides a high-level interface for working with KDBX files,
    including creating, opening, modifying, and searching password databases.
    It supports KDBX4 format with Argon2 key derivation.
    """
    
    def __init__(self, log_level: int = logging.INFO):
        """
        Initialize the KDBX Manager.
        
        Args:
            log_level: The logging level to use (default: logging.INFO)
        """
        self.logger = self._setup_logging(log_level)
        self.kdbx = None
        self.filepath = None
        self.is_modified = False
        self.keyfile_path = None
        self.transform_rounds = 10  # Default for AES-KDF
        self.memory_in_bytes = 64 * 1024 * 1024  # Default 64MB for Argon2
        self.parallelism = max(1, os.cpu_count() or 2)  # Default parallelism

    def _setup_logging(self, log_level: int) -> logging.Logger:
        """Set up logging for the KdbxManager."""
        logger = logging.getLogger("KdbxManager")
        logger.setLevel(log_level)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger

    def create_database(
        self,
        filepath: str,
        password: str = None,
        keyfile: str = None,
        encryption: KdbxEncryptionType = KdbxEncryptionType.AES256,
        kdf: KdbxKeyDerivation = KdbxKeyDerivation.ARGON2,
        overwrite: bool = False
    ) -> bool:
        """
        Create a new KDBX database file.
        
        Args:
            filepath: Path where the database file will be created
            password: Master password for the database
            keyfile: Path to keyfile (optional)
            encryption: Encryption algorithm to use
            kdf: Key derivation function to use
            overwrite: Whether to overwrite existing file
            
        Returns:
            True if database was created successfully
            
        Raises:
            KdbxFileError: If file exists and overwrite is False
            KdbxError: If database creation fails
        """
        if password is None and keyfile is None:
            raise KdbxAuthError("Either password or keyfile must be provided")
            
        filepath = os.path.abspath(filepath)
        
        if os.path.exists(filepath) and not overwrite:
            raise KdbxFileError(f"File {filepath} already exists and overwrite is False")
            
        try:
            # Create parent directories if they don't exist
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Create initial database
            self.kdbx = create_database(filepath, password=password, keyfile=keyfile)
            self.filepath = filepath
            self.keyfile_path = keyfile
            
            # Configure KDF based on selection
            if kdf == KdbxKeyDerivation.ARGON2:
                self._configure_argon2_kdf(
                    iterations=10,
                    memory=self.memory_in_bytes,
                    parallelism=self.parallelism
                )
            else:
                self._configure_aes_kdf(rounds=self.transform_rounds)
            
            # Add default groups
            self.add_group("Email Accounts")
            self.add_group("Banking")
            self.add_group("Social Media")
            self.add_group("Work")
            
            # Save the configured database
            self.save()
            self.logger.info(f"Created new KDBX database at {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create database: {str(e)}")
            raise KdbxError(f"Failed to create database: {str(e)}")

    def open_database(self, filepath: str, password: str = None, keyfile: str = None) -> bool:
        """
        Open an existing KDBX database.
        
        Args:
            filepath: Path to the KDBX file
            password: Master password
            keyfile: Path to keyfile (optional)
            
        Returns:
            True if database was opened successfully
            
        Raises:
            KdbxFileError: If file doesn't exist
            KdbxAuthError: If credentials are invalid
            KdbxError: For other errors
        """
        if password is None and keyfile is None:
            raise KdbxAuthError("Either password or keyfile must be provided")
            
        filepath = os.path.abspath(filepath)
        
        if not os.path.exists(filepath):
            raise KdbxFileError(f"Database file {filepath} does not exist")
            
        try:
            self.kdbx = PyKeePass(filepath, password=password, keyfile=keyfile)
            self.filepath = filepath
            self.keyfile_path = keyfile
            self.is_modified = False
            self.logger.info(f"Opened database: {filepath}")
            return True
            
        except CredentialsError:
            self.logger.error("Invalid credentials provided")
            raise KdbxAuthError("Invalid credentials provided")
            
        except HeaderChecksumError:
            self.logger.error("Database header is corrupted")
            raise KdbxFormatError("Database header is corrupted")
            
        except Exception as e:
            self.logger.error(f"Failed to open database: {str(e)}")
            raise KdbxError(f"Failed to open database: {str(e)}")

    def save(self, filepath: str = None) -> bool:
        """
        Save the database, optionally to a new location.
        
        Args:
            filepath: Optional new location to save to
            
        Returns:
            True if saved successfully
            
        Raises:
            KdbxError: If save fails
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            save_path = filepath if filepath else self.filepath
            self.kdbx.save(save_path)
            
            if filepath and filepath != self.filepath:
                self.filepath = filepath
                
            self.is_modified = False
            self.logger.info(f"Saved database to {save_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save database: {str(e)}")
            raise KdbxError(f"Failed to save database: {str(e)}")

    def close(self) -> bool:
        """
        Close the currently open database.
        
        Returns:
            True if closed successfully
        """
        if self.kdbx is None:
            return True
            
        self.kdbx = None
        self.filepath = None
        self.is_modified = False
        self.logger.info("Database closed")
        return True

    def add_group(self, name: str, parent_group: Union[str, Group] = None) -> Group:
        """
        Add a new group to the database.
        
        Args:
            name: Name of the new group
            parent_group: Parent group name or object (default: root group)
            
        Returns:
            The newly created Group object
            
        Raises:
            KdbxError: If the database is not open or group creation fails
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            # Determine parent group
            parent = None
            if parent_group is None:
                parent = self.kdbx.root_group
            elif isinstance(parent_group, str):
                parent = self.find_group(parent_group)
                if parent is None:
                    parent = self.kdbx.root_group
            else:
                parent = parent_group
                
            # Create group
            group = self.kdbx.add_group(parent, name)
            self.is_modified = True
            self.logger.info(f"Added group '{name}'")
            return group
            
        except Exception as e:
            self.logger.error(f"Failed to add group '{name}': {str(e)}")
            raise KdbxError(f"Failed to add group: {str(e)}")

    def find_group(self, name: str, search_path: str = None) -> Optional[Group]:
        """
        Find a group by name.
        
        Args:
            name: Name of the group to find
            search_path: Optional path to search in (e.g. 'Root/Work')
            
        Returns:
            Group object if found, None otherwise
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        # If path is specified, traverse the path
        if search_path:
            parts = search_path.strip('/').split('/')
            current = self.kdbx.root_group
            
            for part in parts:
                found = False
                for group in current.subgroups:
                    if group.name == part:
                        current = group
                        found = True
                        break
                        
                if not found:
                    return None
                    
            # Search in the specified path
            for group in current.subgroups:
                if group.name == name:
                    return group
                    
            return None
            
        # Search in whole database
        try:
            return self.kdbx.find_groups(name=name, first=True)
        except Exception:
            return None

    def add_entry(
        self,
        title: str,
        username: str,
        password: str,
        url: str = None,
        notes: str = None,
        group_name: str = None,
        tags: List[str] = None,
        expires: bool = False,
        expiry_time: datetime.datetime = None,
        icon: int = None
    ) -> Entry:
        """
        Add a new entry to the database.
        
        Args:
            title: Title of the entry
            username: Username value
            password: Password value
            url: URL value (optional)
            notes: Notes (optional)
            group_name: Group to add the entry to (default: root group)
            tags: List of tags (optional)
            expires: Whether the entry expires
            expiry_time: Expiration datetime (if expires is True)
            icon: Icon ID (optional)
            
        Returns:
            The newly created Entry object
            
        Raises:
            KdbxError: If the database is not open or entry creation fails
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            # Find the group
            group = None
            if group_name:
                group = self.find_group(group_name)
                
            if group is None:
                group = self.kdbx.root_group
                
            # Create entry
            entry = self.kdbx.add_entry(
                group,
                title,
                username,
                password,
                url=url,
                notes=notes,
                icon=icon
            )
            
            # Set tags
            if tags:
                entry.tags = tags
                
            # Set expiry
            if expires:
                entry.expires = True
                if expiry_time:
                    entry.expiry_time = expiry_time
                else:
                    # Default: 30 days from now
                    entry.expiry_time = datetime.datetime.now() + datetime.timedelta(days=30)
                    
            self.is_modified = True
            self.logger.info(f"Added entry '{title}'")
            return entry
            
        except Exception as e:
            self.logger.error(f"Failed to add entry '{title}': {str(e)}")
            raise KdbxError(f"Failed to add entry: {str(e)}")

    def find_entries(
        self,
        title: str = None,
        username: str = None,
        url: str = None,
        notes: str = None,
        uuid: str = None,
        tags: List[str] = None,
        group: Union[str, Group] = None
    ) -> List[Entry]:
        """
        Find entries matching the specified criteria.
        
        Args:
            title: Title to search for (optional)
            username: Username to search for (optional)
            url: URL to search for (optional)
            notes: Notes to search for (optional)
            uuid: UUID to search for (optional)
            tags: List of tags to search for (optional)
            group: Group name or object to search in (optional)
            
        Returns:
            List of matching Entry objects
            
        Raises:
            KdbxError: If the database is not open
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            # Convert uuid string to UUID object if provided
            uuid_obj = None
            if uuid:
                try:
                    import uuid as uuid_module
                    uuid_obj = uuid_module.UUID(uuid)
                except ValueError:
                    return []  # Invalid UUID
            
            # Find the group if a name was provided
            group_obj = None
            if isinstance(group, str):
                group_obj = self.find_group(group)
                if group_obj is None:
                    return []  # Group not found
            elif group:
                group_obj = group
                
            # Find entries - omit the uuid parameter if uuid_obj is None
            search_params = {
                'title': title,
                'username': username,
                #'url': url,
                #'notes': notes,
                #'tags': tags,
                #'group': group_obj
            }
            
            # Only include uuid parameter if a valid UUID object exists
            if uuid_obj is not None:
                search_params['uuid'] = uuid_obj
                
            entries = self.kdbx.find_entries(**search_params)
            
            return entries
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.logger.error(f"Error searching for entries: {str(e)}")
            return []

    def update_entry(
        self,
        entry: Entry,
        title: str = None,
        username: str = None,
        password: str = None,
        url: str = None,
        notes: str = None,
        tags: List[str] = None,
        expires: bool = None,
        expiry_time: datetime.datetime = None
    ) -> bool:
        """
        Update an existing entry.
        
        Args:
            entry: The Entry object to update
            title: New title (optional)
            username: New username (optional)
            password: New password (optional)
            url: New URL (optional)
            notes: New notes (optional)
            tags: New tags (optional)
            expires: Whether the entry expires (optional)
            expiry_time: New expiration datetime (optional)
            
        Returns:
            True if updated successfully
            
        Raises:
            KdbxError: If the database is not open or update fails
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            # Update fields if provided
            if title is not None:
                entry.title = title
                
            if username is not None:
                entry.username = username
                
            if password is not None:
                entry.password = password
                
            if url is not None:
                entry.url = url
                
            if notes is not None:
                entry.notes = notes
                
            if tags is not None:
                entry.tags = tags
                
            if expires is not None:
                entry.expires = expires
                
            if expiry_time is not None and expires:
                entry.expiry_time = expiry_time
                
            # Mark as modified
            self.is_modified = True
            self.logger.info(f"Updated entry '{entry.title}'")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update entry: {str(e)}")
            raise KdbxError(f"Failed to update entry: {str(e)}")

    def delete_entry(self, entry: Entry) -> bool:
        """
        Delete an entry from the database.
        
        Args:
            entry: The Entry object to delete
            
        Returns:
            True if deleted successfully
            
        Raises:
            KdbxError: If the database is not open or deletion fails
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            title = entry.title
            self.kdbx.delete_entry(entry)
            self.is_modified = True
            self.logger.info(f"Deleted entry '{title}'")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete entry: {str(e)}")
            raise KdbxError(f"Failed to delete entry: {str(e)}")

    def move_entry(self, entry: Entry, destination_group: Group) -> bool:
        """
        Move an entry to a different group.
        
        Args:
            entry: The Entry object to move
            destination_group: The destination Group
            
        Returns:
            True if moved successfully
            
        Raises:
            KdbxError: If the database is not open or move fails
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            self.kdbx.move_entry(entry, destination_group)
            self.is_modified = True
            self.logger.info(
                f"Moved entry '{entry.title}' to group '{destination_group.name}'"
            )
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to move entry: {str(e)}")
            raise KdbxError(f"Failed to move entry: {str(e)}")

    def attach_file(
        self,
        entry: Entry,
        filepath: str,
        attachment_name: str = None,
        binary_data: bytes = None
    ) -> bool:
        """
        Attach a file to an entry.
        
        Args:
            entry: The Entry object to attach the file to
            filepath: Path to the file to attach, or name to use for binary data
            attachment_name: Name to use for the attachment (default: filename)
            binary_data: Binary data to attach instead of reading from file
            
        Returns:
            True if attached successfully
            
        Raises:
            KdbxError: If the database is not open or attachment fails
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            # Determine attachment name
            if attachment_name is None:
                attachment_name = os.path.basename(filepath)
                
            # Get file data
            data = binary_data
            if data is None:
                if not os.path.exists(filepath):
                    raise KdbxFileError(f"File not found: {filepath}")
                with open(filepath, 'rb') as f:
                    data = f.read()
                    
            # Attach file - add binary to database first, then attach to entry
            # The pykeepass library requires the binary ID and filename
            binary_id = self.kdbx.add_binary(data)
            entry.add_attachment(filename=attachment_name, id=str(binary_id))
            self.is_modified = True
            self.logger.info(
                f"Attached file '{attachment_name}' to entry '{entry.title}'"
            )
            return True
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.logger.error(f"Failed to attach file: {str(e)}")
            raise KdbxError(f"Failed to attach file: {str(e)}")

    def get_attachment(self, entry: Entry, attachment_name: str) -> Optional[bytes]:
        """
        Get the binary content of an attachment.
        
        Args:
            entry: The Entry object with the attachment
            attachment_name: Name of the attachment
            
        Returns:
            Binary content of the attachment, or None if not found
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            # Look through attachments to find the one with the matching filename
            for attachment in entry.attachments:
                #print(attachment.filename, attachment.id,attachment_name)
                if attachment.filename == attachment_name:
                    # Get the binary content using the reference ID
                    # PyKeePass stores binaries in a list accessed by ID
                    binary_id = int(attachment.id)
                    return self.kdbx.binaries[binary_id]
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get attachment: {str(e)}")
            return None

    def save_attachment(
        self,
        entry: Entry,
        attachment_name: str,
        output_path: str
    ) -> bool:
        """
        Save an attachment to disk.
        
        Args:
            entry: The Entry object with the attachment
            attachment_name: Name of the attachment
            output_path: Path to save the attachment to
            
        Returns:
            True if saved successfully
            
        Raises:
            KdbxError: If the database is not open or save fails
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            # Find the attachment with the matching filename
            attachment_data = None
            for attachment in entry.attachments:
                if attachment.filename == attachment_name:
                    binary_id = int(attachment.id)
                    attachment_data = self.kdbx.binaries[binary_id]
                    break
                    
            if attachment_data is None:
                raise KdbxError(f"Attachment '{attachment_name}' not found")
                
            # Ensure output directory exists
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            # Save attachment
            with open(output_path, 'wb') as f:
                f.write(attachment_data)
                
            self.logger.info(f"Saved attachment '{attachment_name}' to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save attachment: {str(e)}")
            raise KdbxError(f"Failed to save attachment: {str(e)}")

    def delete_attachment(self, entry: Entry, attachment_name: str) -> bool:
        """
        Delete an attachment from an entry.
        
        Args:
            entry: The Entry object with the attachment
            attachment_name: Name of the attachment
            
        Returns:
            True if deleted successfully
            
        Raises:
            KdbxError: If the database is not open or deletion fails
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            # Find the attachment with the matching filename
            attachment_to_delete = None
            for attachment in entry.attachments:
                if attachment.filename == attachment_name:
                    attachment_to_delete = attachment
                    break
                    
            if attachment_to_delete is None:
                raise KdbxError(f"Attachment '{attachment_name}' not found")
                
            # We need to find the Binary element and remove it
            binary_element = entry._element.xpath(
                f'Binary/Key[text()="{attachment_name}"]/..'
            )
            if binary_element and len(binary_element) > 0:
                entry._element.remove(binary_element[0])
                self.is_modified = True
                self.logger.info(
                    f"Deleted attachment '{attachment_name}' from entry '{entry.title}'"
                )
                return True
            else:
                raise KdbxError(f"Failed to find attachment element for '{attachment_name}'")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete attachment: {str(e)}")
            raise KdbxError(f"Failed to delete attachment: {str(e)}")

    def generate_password(
        self,
        length: int = 20,
        lowercase: bool = True,
        uppercase: bool = True,
        digits: bool = True,
        special: bool = True,
        exclude_chars: str = "",
        ensure_all_classes: bool = True
    ) -> str:
        """
        Generate a secure password.
        
        Args:
            length: Length of the password
            lowercase: Include lowercase letters
            uppercase: Include uppercase letters
            digits: Include digits
            special: Include special characters
            exclude_chars: Characters to exclude
            ensure_all_classes: Ensure at least one character from each included class
            
        Returns:
            Generated password
        """
        # Define character sets
        chars = ""
        required_chars = []
        
        if lowercase:
            lowercase_chars = "abcdefghijklmnopqrstuvwxyz"
            chars += lowercase_chars
            if ensure_all_classes:
                required_chars.append(secrets.choice(lowercase_chars))
                
        if uppercase:
            uppercase_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            chars += uppercase_chars
            if ensure_all_classes:
                required_chars.append(secrets.choice(uppercase_chars))
                
        if digits:
            digit_chars = "0123456789"
            chars += digit_chars
            if ensure_all_classes:
                required_chars.append(secrets.choice(digit_chars))
                
        if special:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/~"
            chars += special_chars
            if ensure_all_classes:
                required_chars.append(secrets.choice(special_chars))
                
        # Remove excluded characters
        for c in exclude_chars:
            chars = chars.replace(c, "")
            
        if not chars:
            raise ValueError("No characters available after exclusions")
            
        # Generate password
        if ensure_all_classes and required_chars:
            if len(required_chars) > length:
                raise ValueError(
                    f"Password length ({length}) is too short to include all required character classes"
                )
                
            # Fill remaining characters
            remaining_length = length - len(required_chars)
            password_chars = [secrets.choice(chars) for _ in range(remaining_length)]
            password_chars.extend(required_chars)
            secrets.SystemRandom().shuffle(password_chars)
            password = ''.join(password_chars)
        else:
            password = ''.join(secrets.choice(chars) for _ in range(length))
            
        return password

    def export_to_csv(self, output_path: str, include_passwords: bool = False) -> bool:
        """
        Export the database to a CSV file.
        
        Args:
            output_path: Path to save the CSV file
            include_passwords: Whether to include passwords in the export
            
        Returns:
            True if exported successfully
            
        Raises:
            KdbxError: If the database is not open or export fails
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                # Write header
                header = ["Group", "Title", "Username", "URL", "Notes", "Tags"]
                if include_passwords:
                    header.insert(3, "Password")
                    
                f.write(','.join([f'"{h}"' for h in header]) + '\n')
                
                # Write entries
                for entry in self.kdbx.entries:
                    # Skip history entries
                    if hasattr(entry, 'is_history_entry') and entry.is_history_entry:
                        continue
                        
                    # Get group path
                    group_path = self._get_group_path(entry.group)
                    
                    # Format fields for CSV
                    title = self._csv_escape(entry.title)
                    username = self._csv_escape(entry.username)
                    url = self._csv_escape(entry.url)
                    notes = self._csv_escape(entry.notes)
                    tags = self._csv_escape(', '.join(entry.tags) if entry.tags else '')
                    
                    # Build row
                    row = [
                        f'"{group_path}"',
                        f'"{title}"',
                        f'"{username}"'
                    ]
                    
                    if include_passwords:
                        row.append(f'"{self._csv_escape(entry.password)}"')
                        
                    row.extend([
                        f'"{url}"',
                        f'"{notes}"',
                        f'"{tags}"'
                    ])
                    
                    f.write(','.join(row) + '\n')
                    
            self.logger.info(f"Exported database to {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export database: {str(e)}")
            raise KdbxError(f"Failed to export database: {str(e)}")

    def _csv_escape(self, value: str) -> str:
        """Escape a string for CSV output."""
        if value is None:
            return ""
        return value.replace('"', '""').replace('\n', '\\n')

    def _get_group_path(self, group: Group) -> str:
        """Get the full path of a group."""
        if group is None:
            return ""
            
        path = []
        current = group
        
        # Traverse up to build path
        while current:
            if current == self.kdbx.root_group:
                path.insert(0, "Root")
                break
                
            path.insert(0, current.name)
            current = current.parentgroup
            
        return '/'.join(path)

    def _configure_argon2_kdf(self, iterations: int, memory: int, parallelism: int) -> bool:
        """
        Configure Argon2 key derivation function parameters.
        
        Args:
            iterations: Number of iterations
            memory: Memory usage in bytes
            parallelism: Parallelism factor
            
        Returns:
            True if configured successfully
        """
        if self.kdbx is None:
            return False
            
        try:
            # Get KDF parameters
            kdf_params = self.kdbx.kdbx.header.kdf_parameters
            
            # Update parameters
            kdf_params[b'i'] = iterations
            kdf_params[b'm'] = memory
            kdf_params[b'p'] = parallelism
            
            self.is_modified = True
            self.logger.info(
                f"Configured Argon2 KDF: {iterations} iterations, {memory/1024/1024:.1f}MB memory, "
                f"{parallelism} parallelism"
            )
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to configure Argon2 KDF: {str(e)}")
            return False

    def _configure_aes_kdf(self, rounds: int) -> bool:
        """
        Configure AES key derivation function parameters.
        
        Args:
            rounds: Number of transformation rounds
            
        Returns:
            True if configured successfully
        """
        if self.kdbx is None:
            return False
            
        try:
            # Check if using AES-KDF
            kdf_params = self.kdbx.kdbx.header.kdf_parameters
            
            # Set transformation rounds
            kdf_params[b'r'] = rounds
            
            self.is_modified = True
            self.logger.info(f"Configured AES-KDF: {rounds} rounds")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to configure AES-KDF: {str(e)}")
            return False

    def change_credentials(
        self,
        new_password: str = None,
        new_keyfile: str = None,
        current_password: str = None,
        current_keyfile: str = None
    ) -> bool:
        """
        Change the credentials (password and/or keyfile) for the database.
        
        Args:
            new_password: New password (None to keep current)
            new_keyfile: Path to new keyfile (None to keep current)
            current_password: Current password (required if database was opened with password)
            current_keyfile: Path to current keyfile (required if database was opened with keyfile)
            
        Returns:
            True if credentials changed successfully
            
        Raises:
            KdbxAuthError: If current credentials are invalid
            KdbxError: If credentials change fails
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            # Verify current credentials
            filepath = self.filepath
            temp_kdbx = None
            
            try:
                temp_kdbx = PyKeePass(
                    filepath,
                    password=current_password,
                    keyfile=current_keyfile
                )
            except CredentialsError:
                raise KdbxAuthError("Current credentials are invalid")
                
            # Determine new credentials
            password = new_password if new_password is not None else current_password
            keyfile = new_keyfile if new_keyfile is not None else current_keyfile
            
            # Change credentials
            self.kdbx.password = password
            self.kdbx.keyfile = keyfile
            
            # Save with new credentials
            self.save()
            
            # Update instance variables if needed
            if new_keyfile is not None:
                self.keyfile_path = new_keyfile
                
            self.logger.info("Changed database credentials")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to change credentials: {str(e)}")
            raise KdbxError(f"Failed to change credentials: {str(e)}")

    def add_custom_field(self, entry: Entry, key: str, value: str, protect: bool = False) -> bool:
        """
        Add a custom field to an entry.
        
        Args:
            entry: The Entry object to add the field to
            key: Field name
            value: Field value
            protect: Whether to encrypt the field value
            
        Returns:
            True if added successfully
            
        Raises:
            KdbxError: If the database is not open or field addition fails
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            entry.set_custom_property(key, value, protect=protect)
            self.is_modified = True
            self.logger.info(f"Added custom field '{key}' to entry '{entry.title}'")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add custom field: {str(e)}")
            raise KdbxError(f"Failed to add custom field: {str(e)}")

    def get_database_metadata(self) -> Dict:
        """
        Get metadata about the current database.
        
        Returns:
            Dictionary with database metadata
            
        Raises:
            KdbxError: If no database is open
        """
        if self.kdbx is None:
            raise KdbxError("No database is open")
            
        try:
            # Get header information
            header = self.kdbx.kdbx.header
            
            # Determine KDBX version
            try:
                # Try direct attribute access first
                version = f"{header.major_version}.{header.minor_version}"
            except AttributeError:
                # Fall back to dictionary-style access or hardcoded defaults
                major = getattr(header, 'major_version', 4)  # Default to version 4
                minor = getattr(header, 'minor_version', 0)  # Default to version 0
                version = f"{major}.{minor}"
            
            # Get KDF information
            kdf_params = getattr(header, 'kdf_parameters', {})
            kdf_type = "Unknown"
            kdf_info = {}
            
            if b'$UUID' in kdf_params:
                kdf_uuid = kdf_params[b'$UUID']
                
                # Argon2 UUID: 14AAF7C6-BC0A-4D98-B93F-036A395CF6B1
                argon2_uuid = bytes([
                    0x14, 0xAA, 0xF7, 0xC6, 0xBC, 0x0A, 0x4D, 0x98,
                    0xB9, 0x3F, 0x03, 0x6A, 0x39, 0x5C, 0xF6, 0xB1
                ])
                
                # AES UUID: C9D9F39A-628A-4460-BF74-0D08C18A4FEA
                aes_uuid = bytes([
                    0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60,
                    0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA
                ])
                
                if kdf_uuid == argon2_uuid:
                    kdf_type = "Argon2"
                    if b'i' in kdf_params:
                        kdf_info["iterations"] = kdf_params[b'i']
                    if b'm' in kdf_params:
                        kdf_info["memory"] = f"{kdf_params[b'm'] / (1024*1024):.2f} MB"
                    if b'p' in kdf_params:
                        kdf_info["parallelism"] = kdf_params[b'p']
                elif kdf_uuid == aes_uuid:
                    kdf_type = "AES-KDF"
                    if b'r' in kdf_params:
                        kdf_info["rounds"] = kdf_params[b'r']
            
            # Get cipher information
            cipher_type = "Unknown"
            cipher_uuid = getattr(header, 'cipher_id', None)

            # AES UUID: 31C1F2E6-BF71-4350-BE58-05216AFC5AFF
            aes_uuid = bytes([
                0x31, 0xC1, 0xF2, 0xE6, 0xBF, 0x71, 0x43, 0x50,
                0xBE, 0x58, 0x05, 0x21, 0x6A, 0xFC, 0x5A, 0xFF
            ])
            
            if cipher_uuid == aes_uuid:
                cipher_type = "AES-256"
                
            # Count entries and groups
            entry_count = len(self.kdbx.entries)
            group_count = len(self.kdbx.groups)
            
            # Get database name and description
            db_name = self.kdbx.filename
            db_desc = ""
            
            if hasattr(self.kdbx, 'database_description'):
                db_desc = self.kdbx.database_description
                
            # Count attachments
            attachment_count = 0
            attachment_size = 0
            for entry in self.kdbx.entries:
                if hasattr(entry, 'attachments') and entry.attachments:
                    attachment_count += len(entry.attachments)
                    attachment_size += sum(len(data) for data in entry.attachments.values())
                    
            # Get file size
            file_size = os.path.getsize(self.filepath) if os.path.exists(self.filepath) else 0
            
            # Build metadata dictionary
            metadata = {
                "file_path": self.filepath,
                "file_size": f"{file_size / 1024:.2f} KB",
                "database_name": db_name,
                "database_description": db_desc,
                "kdbx_version": version,
                "cipher": cipher_type,
                "kdf": {
                    "type": kdf_type,
                    **kdf_info
                },
                "statistics": {
                    "entries": entry_count,
                    "groups": group_count,
                    "attachments": {
                        "count": attachment_count,
                        "size": f"{attachment_size / 1024:.2f} KB" if attachment_size > 0 else "0 KB"
                    }
                },
                "keyfile_used": self.keyfile_path is not None
            }
            
            return metadata
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.logger.error(f"Failed to get database metadata: {str(e)}")
            raise KdbxError(f"Failed to get database metadata: {str(e)}")#