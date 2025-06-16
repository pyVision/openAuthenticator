"""
ChaCha20 Stream Cipher Implementation

This module provides a Python implementation of the ChaCha20 stream cipher
using the cryptography library.
"""

import os
from typing import Tuple, Optional, Union, cast

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import ChaCha20 as ChaCha20Algorithm


class ChaCha20:
    """
    ChaCha20 stream cipher implementation using the cryptography library.
    
    This class provides methods to encrypt and decrypt data using the ChaCha20
    stream cipher algorithm designed by Daniel J. Bernstein.
    """
    
    def __init__(self, key: bytes, nonce: Optional[bytes] = None,counter=None):
        """
        Initialize a ChaCha20 cipher instance.
        
        Args:
            key: A 32-byte (256-bit) key
            nonce: An optional 16-byte (128-bit) nonce. If not provided, a random one will be generated
        
        Raises:
            ValueError: If key is not 32 bytes or nonce is not 16 bytes
        """
        if len(key) != 32:
            raise ValueError("ChaCha20 key must be 32 bytes (256 bits)")
            
        self.key = key
        
        # The cryptography library expects a 16-byte nonce for ChaCha20
        if nonce is None:
            self.nonce = os.urandom(16)
        else:
            if len(nonce) != 16:
                raise ValueError("ChaCha20 nonce must be 16 bytes (128 bits) for the cryptography library")
            self.nonce = nonce

        if counter is None:
            self.counter = 1
        else:
            if not isinstance(counter, int) or counter < 1:
                raise ValueError("Counter must be a positive integer")
            self.counter = counter



    def encrypt(self, plaintext: Union[bytes, str]) -> Tuple[bytes, bytes, int]:
        """
        Encrypt data using ChaCha20.
        
        Args:
            plaintext: The data to encrypt (bytes or string)
            counter: Initial counter value (defaults to 1)
            
        Returns:
            A tuple containing (ciphertext, nonce, final counter)
            
        Note:
            The nonce and counter should be stored alongside the ciphertext
            for decryption.
        """
        # Convert string to bytes if needed
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Create ChaCha20 algorithm with key, nonce, and counter
        # ChaCha20Algorithm expects a 32-byte key and a 16-byte nonce, where the first 4 bytes are the counter (little-endian)
        if len(self.nonce) != 16:
            raise ValueError("ChaCha20 nonce must be 16 bytes (128 bits) for the cryptography library")
        nonce_with_counter = self.counter.to_bytes(4, 'little') + self.nonce[4:]


        algorithm = ChaCha20Algorithm(self.key, nonce_with_counter)
        cipher = Cipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        
        # Encrypt the plaintext
        ciphertext = encryptor.update(plaintext) 
        
        # Calculate the final counter value for use in subsequent operations
        # Each block is 64 bytes, so we need to calculate how many blocks were used
        blocks_used = (len(plaintext) + 63) // 64  # Ceiling division
        final_counter = self.counter + blocks_used
        
        return ciphertext, self.nonce, final_counter
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Decrypt data using ChaCha20.
        
        Args:
            ciphertext: The data to decrypt
            counter: Initial counter value (defaults to 1)
            
        Returns:
            The decrypted data as bytes
        """
        # Create ChaCha20 algorithm with key, nonce, and counter

        if len(self.nonce) != 16:
            raise ValueError("ChaCha20 nonce must be 16 bytes (128 bits) for the cryptography library")
        nonce_with_counter = self.counter.to_bytes(4, 'little') + self.nonce[4:]

        algorithm = ChaCha20Algorithm(self.key, nonce_with_counter)
        cipher = Cipher(algorithm, mode=None)
        decryptor = cipher.decryptor()
        
        # Decrypt the ciphertext
        plaintext = decryptor.update(ciphertext) 
        
        return plaintext


class ChaCha20Poly1305:
    """
    ChaCha20-Poly1305 authenticated encryption implementation using the cryptography library.
    
    This class provides methods to encrypt and authenticate data using the
    ChaCha20-Poly1305 AEAD (Authenticated Encryption with Associated Data) scheme.
    """
    
    def __init__(self, key: bytes):
        """
        Initialize a ChaCha20-Poly1305 instance.
        
        Args:
            key: A 32-byte (256-bit) key
        """
        if len(key) != 32:
            raise ValueError("ChaCha20-Poly1305 key must be 32 bytes (256 bits)")
        
        self.key = key
        
        try:
            # Import here to avoid issues if cryptography is not installed
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305 as CryptoChaCha20Poly1305
            self._cipher = CryptoChaCha20Poly1305(key)
        except ImportError:
            raise ImportError(
                "The cryptography library is required for ChaCha20Poly1305. "
                "Install it with: pip install cryptography"
            )
    
    def encrypt(self, plaintext: Union[bytes, str], associated_data: bytes = b"") -> Tuple[bytes, bytes]:
        """
        Encrypt and authenticate data.
        
        Args:
            plaintext: The data to encrypt
            associated_data: Additional data to authenticate but not encrypt
            
        Returns:
            A tuple containing (ciphertext with tag, nonce)
        """
        # Convert string to bytes if needed
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
            
        # Generate a random 12-byte nonce (96 bits)
        # ChaCha20Poly1305 in the cryptography library uses a 12-byte nonce
        nonce = os.urandom(12)
        
        # Encrypt and authenticate the plaintext
        ciphertext = self._cipher.encrypt(nonce, plaintext, associated_data)
        
        return ciphertext, nonce
    
    def decrypt(self, ciphertext: bytes, nonce: bytes, 
                associated_data: bytes = b"") -> bytes:
        """
        Decrypt and verify data.
        
        Args:
            ciphertext: The encrypted data with authentication tag
            nonce: The nonce used during encryption
            associated_data: Additional authenticated data
            
        Returns:
            The decrypted data
            
        Raises:
            ValueError: If authentication fails
        """
        try:
            # Decrypt and verify the ciphertext
            plaintext = self._cipher.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except Exception as e:
            raise ValueError(f"Authentication failed: {str(e)}")


# Utility functions for hex conversion
def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to a hex string."""
    return data.hex()

def hex_to_bytes(hex_string: str) -> bytes:
    """Convert a hex string to bytes."""
    return bytes.fromhex(hex_string)


def ensure_cryptography_installed():
    """
    Check if the cryptography library is installed and provide installation instructions if not.
    
    Raises:
        ImportError: If cryptography is not installed
    """
    try:
        import cryptography
        return True
    except ImportError:
        raise ImportError(
            "The cryptography library is required for this module. "
            "Install it with: pip install cryptography"
        )
