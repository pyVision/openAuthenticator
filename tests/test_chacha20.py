import os
import unittest
from src.open_authenticator.chacha20 import (
    ChaCha20, ChaCha20Poly1305, ensure_cryptography_installed
)

class TestChaCha20(unittest.TestCase):
    def setUp(self):
        try:
            ensure_cryptography_installed()
        except ImportError as e:
            self.skipTest(f"Skipping tests: {str(e)}")

    def test_basic_encryption_decryption(self):
        """Basic Encryption/Decryption Test."""
        key = os.urandom(32)
        nonce = os.urandom(16)
        cipher = ChaCha20(key, nonce)
        plaintext = b"Hello, ChaCha20!"
        ciphertext, _, _ = cipher.encrypt(plaintext)
        decipher = ChaCha20(key, nonce)
        decrypted = decipher.decrypt(ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_nonce_handling(self):
        """Nonce Handling Test."""
        key = os.urandom(32)
        plaintext = b"Same plaintext"
        nonce1 = os.urandom(16)
        nonce2 = os.urandom(16)
        cipher1 = ChaCha20(key, nonce1)
        cipher2 = ChaCha20(key, nonce2)
        ct1, _, _ = cipher1.encrypt(plaintext)
        ct2, _, _ = cipher2.encrypt(plaintext)
        self.assertNotEqual(ct1, ct2)
        # Decrypt to verify correctness
        self.assertEqual(ChaCha20(key, nonce1).decrypt(ct1), plaintext)
        self.assertEqual(ChaCha20(key, nonce2).decrypt(ct2), plaintext)

    def test_counter_handling(self):
        """Counter Handling Test."""
        key = os.urandom(32)
        nonce = os.urandom(16)
        plaintext = b"Counter test message"
        cipher1 = ChaCha20(key, nonce,counter=1)
        cipher2 = ChaCha20(key, nonce,counter=2)
        ct1, _, _ = cipher1.encrypt(plaintext)
        ct2, _, _ = cipher2.encrypt(plaintext)
        self.assertNotEqual(ct1, ct2)
        # Decrypt to verify correctness
        self.assertEqual(ChaCha20(key, nonce,counter=1).decrypt(ct1), plaintext)
        self.assertEqual(ChaCha20(key, nonce,counter=2).decrypt(ct2), plaintext)

    def test_edge_cases(self):
        """Edge Case Tests: empty, short, and large messages."""
        key = os.urandom(32)
        nonce = os.urandom(16)
        # Empty plaintext
        cipher = ChaCha20(key, nonce)
        ct, _, _ = cipher.encrypt(b"")
        self.assertEqual(ChaCha20(key, nonce).decrypt(ct), b"")
        # Very short message
        short = b"x"
        ct, _, _ = cipher.encrypt(short)
        self.assertEqual(ChaCha20(key, nonce).decrypt(ct), short)
        # Large message
        large = os.urandom(10**6)
        ct, _, _ = cipher.encrypt(large)
        self.assertEqual(ChaCha20(key, nonce).decrypt(ct), large)

    def test_error_handling(self):
        """Error Handling Tests: wrong key, nonce, tampered ciphertext."""
        key = os.urandom(32)
        nonce = os.urandom(16)
        plaintext = b"Sensitive data"
        cipher = ChaCha20(key, nonce)
        ct, _, _ = cipher.encrypt(plaintext)
        # Wrong key
        wrong_key = os.urandom(32)
        decrypted = ChaCha20(wrong_key, nonce).decrypt(ct)
        # If decryption does not raise, ensure the result is not the original plaintext
        self.assertNotEqual(decrypted, plaintext, "Decryption with wrong key should not yield original plaintext")
        # Wrong nonce
        wrong_nonce = os.urandom(16)
        decrypted_wrong_nonce = ChaCha20(key, wrong_nonce).decrypt(ct)
        self.assertNotEqual(decrypted_wrong_nonce, plaintext, "Decryption with wrong nonce should not yield original plaintext")
        # Tampered ciphertext
        tampered = bytearray(ct)
        tampered[0] ^= 0xFF
        decrypted_tampered = ChaCha20(key, nonce).decrypt(bytes(tampered))
        self.assertNotEqual(decrypted_tampered, plaintext, "Tampered ciphertext should not decrypt to original plaintext")


class TestChaCha20Poly1305(unittest.TestCase):
    def setUp(self):
        try:
            ensure_cryptography_installed()
        except ImportError as e:
            self.skipTest(f"Skipping tests: {str(e)}")

    def test_authenticated_encryption(self):
        """ChaCha20-Poly1305 Authenticated Encryption Test."""
        key = os.urandom(32)
        aead = ChaCha20Poly1305(key)
        plaintext = b"Authenticated message"
        aad = b"header"
        ciphertext, nonce = aead.encrypt(plaintext, aad)
        decrypted = aead.decrypt(ciphertext, nonce, aad)
        self.assertEqual(decrypted, plaintext)
        # Tamper with ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0x01
        with self.assertRaises(ValueError):
            aead.decrypt(bytes(tampered), nonce, aad)
        # Tamper with AAD
        with self.assertRaises(ValueError):
            aead.decrypt(ciphertext, nonce, b"wrong header")

    def test_error_handling(self):
        """Error Handling Tests for Poly1305: wrong key, nonce, tampered ciphertext."""
        key = os.urandom(32)
        aead = ChaCha20Poly1305(key)
        plaintext = b"Poly1305 sensitive"
        aad = b"aad"
        ciphertext, nonce = aead.encrypt(plaintext, aad)
        # Wrong key
        wrong_key = os.urandom(32)
        aead_wrong = ChaCha20Poly1305(wrong_key)
        with self.assertRaises(ValueError):
            aead_wrong.decrypt(ciphertext, nonce, aad)
        # Wrong nonce
        wrong_nonce = os.urandom(12)
        with self.assertRaises(ValueError):
            aead.decrypt(ciphertext, wrong_nonce, aad)
        # Tampered ciphertext
        tampered = bytearray(ciphertext)
        tampered[-1] ^= 0x01
        with self.assertRaises(ValueError):
            aead.decrypt(bytes(tampered), nonce, aad)

if __name__ == "__main__":
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
