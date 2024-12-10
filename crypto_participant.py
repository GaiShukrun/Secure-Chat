# crypto_participant.py
import random
from math import gcd
import os
# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.primitives import padding
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# from cryptography.hazmat.primitives import hashes
from aes import AES

class CryptoParticipant:
    def __init__(self, name):
        self.name = name
        print(f"\n{'='*50}")
        print(f"Initializing {name}'s Cryptographic Parameters")
        print(f"{'='*50}")
        
        print("\nStep 1: RSA Key Generation")
        print("-" * 30)
        
        # Generate two prime numbers for RSA
        self.p = self._generate_prime(100, 500)
        print(f"Generated first prime p: {self.p}")
        print(f"Verifying p is prime: {self._is_prime(self.p)}")
        
        self.q = self._generate_prime(100, 500)
        print(f"Generated second prime q: {self.q}")
        print(f"Verifying q is prime: {self._is_prime(self.q)}")
        
        # Calculate RSA modulus n
        self.n = self.p * self.q
        print(f"\nRSA modulus n = p * q: {self.n}")
        
        # Calculate Euler's totient function φ(n)
        self.phi = (self.p - 1) * (self.q - 1)
        print(f"Euler's totient φ(n) = (p-1)(q-1): {self.phi}")
        
        # Choose public exponent e
        self.e = self._choose_e()
        print(f"\nChosen public exponent e: {self.e}")
        print(f"Verified gcd(e,φ(n)) = {gcd(self.e, self.phi)} (must be 1)")
        
        # Calculate private exponent d
        self.d = self._mod_inverse(self.e, self.phi)
        print(f"\nCalculated private exponent d: {self.d}")
        print(f"Verifying e*d ≡ 1 (mod φ(n)): {(self.e * self.d) % self.phi} (must be 1)")
        
        # Initialize DH parameters
        print("\nStep 2: Initializing DH Parameters")
        print("-" * 30)
        self.dh_base = None     # g
        self.dh_modulus = None  # p
        self.dh_private = None  # a or b
        self.dh_public = None   # A or B
        
        # Initialize AES key
        print("\nStep 3: Preparing for AES")
        print("-" * 30)
        self.aes_key = None

    def _is_prime(self, n):
        """Check if a number is prime"""
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    def _generate_prime(self, start, end):
        """Generate a prime number within range"""
        attempts = 0
        while True:
            attempts += 1
            candidate = random.randint(start, end)
            if self._is_prime(candidate):
                print(f"Found prime after {attempts} attempts")
                return candidate

    def _choose_e(self):
        """Choose public exponent e where 1 < e < φ(n) and gcd(e, φ(n)) = 1"""
        print("\nSelecting public exponent e:")
        print("Requirements: 1 < e < φ(n) and gcd(e,φ(n)) = 1")
        attempts = 0
        for e in range(3, self.phi):
            attempts += 1
            if gcd(e, self.phi) == 1:
                print(f"Found valid e after testing {attempts} numbers")
                return e
        raise ValueError("No valid e found")

    def _mod_inverse(self, e, phi):
        """Calculate private exponent d using Extended Euclidean Algorithm"""
        print("\nCalculating private exponent d using Extended Euclidean Algorithm")
        print(f"Need to find d where e*d ≡ 1 (mod φ(n))")
        
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            print(f"GCD step: a={a}, b={b}, gcd={gcd}, x={x}, y={y}")
            return gcd, x, y

        _, d, _ = extended_gcd(e, phi)
        d = d % phi
        if d < 0:
            d += phi
        return d

    def set_dh_parameters(self, base, modulus):
        """Set Diffie-Hellman parameters"""
        print(f"\n{self.name}: Setting up Diffie-Hellman parameters")
        self.dh_base = base       # g
        self.dh_modulus = modulus # p
        print(f"Base (g): {base}")
        print(f"Modulus (p): {modulus}")

    def generate_dh_private(self):
        """Generate private DH value (a or b)"""
        print(f"\n{self.name}: Generating DH private value")
        self.dh_private = random.randint(2, self.dh_modulus - 2)
        print(f"Private value generated: {self.dh_private}")

    def calculate_dh_public(self):
        """Calculate DH public value (g^a mod p or g^b mod p)"""
        print(f"\n{self.name}: Calculating DH public value")
        print(f"Formula: g^private mod p")
        print(f"Values: {self.dh_base}^{self.dh_private} mod {self.dh_modulus}")
        self.dh_public = pow(self.dh_base, self.dh_private, self.dh_modulus)
        print(f"Calculated public value: {self.dh_public}")
        return self.dh_public

    def rsa_encrypt(self, message, other_e, other_n):
        """Encrypt using RSA: message^e mod n"""
        print(f"\n{self.name}: Performing RSA encryption")
        print(f"Formula: message^e mod n")
        print(f"Message: {message}")
        print(f"Using public key (e,n): ({other_e}, {other_n})")
        encrypted = pow(message, other_e, other_n)
        print(f"Encrypted value: {encrypted}")
        return encrypted

    def rsa_decrypt(self, ciphertext):
        """Decrypt using RSA: ciphertext^d mod n"""
        print(f"\n{self.name}: Performing RSA decryption")
        print(f"Formula: ciphertext^d mod n")
        print(f"Ciphertext: {ciphertext}")
        print(f"Using private key d: {self.d}")
        decrypted = pow(ciphertext, self.d, self.n)
        print(f"Decrypted value: {decrypted}")
        return decrypted

    def calculate_shared_secret(self, other_public):
        """Calculate DH shared secret"""
        print(f"\n{self.name}: Calculating DH shared secret")
        print(f"Formula: (other_public)^private mod p")
        print(f"Values: {other_public}^{self.dh_private} mod {self.dh_modulus}")
        shared_secret = pow(other_public, self.dh_private, self.dh_modulus)
        print(f"Calculated shared secret: {shared_secret}")
        return shared_secret

    # def derive_aes_key(self, shared_secret):
    #     """Derive AES key from shared secret"""
    #     print(f"\n{self.name}: Deriving AES key from shared secret")
    #     print(f"Using shared secret: {shared_secret}")
    #     hkdf = HKDF(
    #         algorithm=hashes.SHA256(),
    #         length=16,  # 16 bytes = 128 bits for AES-128
    #         salt=None,
    #         info=b'AES key derivation',
    #     )
    #     self.aes_key = hkdf.derive(str(shared_secret).encode())
    #     print(f"Derived AES key (hex): {self.aes_key.hex()}")
    #     return self.aes_key

    # def aes_encrypt(self, plaintext):
    #     """Encrypt using AES-128 in CBC mode"""
    #     print(f"\n{self.name}: Performing AES encryption")
    #     print(f"Original message: {plaintext}")

    #     # Generate IV
    #     iv = os.urandom(16)
    #     print(f"Generated IV (hex): {iv.hex()}")

    #     # Pad the plaintext
    #     padder = padding.PKCS7(128).padder()
    #     padded_data = padder.update(plaintext.encode()) + padder.finalize()
    #     print(f"Padded data (hex): {padded_data.hex()}")

    #     # Encrypt
    #     cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
    #     encryptor = cipher.encryptor()
    #     ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    #     print(f"Ciphertext (hex): {ciphertext.hex()}")

    #     # Combine IV and ciphertext
    #     full_message = iv + ciphertext
    #     print(f"Full encrypted message (hex): {full_message.hex()}")
    #     return full_message

    # def aes_decrypt(self, ciphertext):
    #     """Decrypt using AES-128 in CBC mode"""
    #     print(f"\n{self.name}: Performing AES decryption")
    #     print(f"Received encrypted message (hex): {ciphertext.hex()}")

    #     # Split IV and ciphertext
    #     iv = ciphertext[:16]
    #     actual_ciphertext = ciphertext[16:]
    #     print(f"Extracted IV (hex): {iv.hex()}")
    #     print(f"Extracted ciphertext (hex): {actual_ciphertext.hex()}")

    #     # Decrypt
    #     cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
    #     decryptor = cipher.decryptor()
    #     padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    #     print(f"Decrypted padded data (hex): {padded_plaintext.hex()}")

    #     # Remove padding
    #     unpadder = padding.PKCS7(128).unpadder()
    #     plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    #     message = plaintext.decode()
    #     print(f"Final decrypted message: {message}")
    #     return message



#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ for AES  3333333333333333

    def calculate_shared_secret(self, other_public):
        """Calculate DH shared secret"""
        print(f"\n{self.name}: Calculating DH shared secret")
        print(f"Formula: (other_public)^private mod p")
        print(f"Values: {other_public}^{self.dh_private} mod {self.dh_modulus}")
        shared_secret = pow(other_public, self.dh_private, self.dh_modulus)
        print(f"Calculated shared secret: {shared_secret}")
        return shared_secret

    def derive_aes_key(self, shared_secret):
        """Derive AES key from shared secret"""
        print(f"\n{self.name}: Deriving AES key from shared secret")
        print(f"Using shared secret: {shared_secret}")
        
        # Ensure we have exactly 16 bytes
        key_bytes = []
        temp = shared_secret
        for _ in range(16):# 128 bits 
            key_bytes.append(temp & 0xFF)
            temp >>= 8
        
        self.aes_key = bytes(key_bytes)
        self.aes = AES()
        print(f"Derived AES key (hex): {self.aes_key.hex()}")
        return self.aes_key

    def aes_encrypt(self, plaintext):
        """Encrypt using AES implementation"""
        print(f"\n{self.name}: Performing AES encryption")
        print(f"Original message: {plaintext}")

        # Generate IV
        iv = os.urandom(16)
        print(f"Generated IV (hex): {iv.hex()}")

        # Convert plaintext to bytes and pad
        msg_bytes = plaintext.encode()
        padding_length = 16 - (len(msg_bytes) % 16)
        padded_data = msg_bytes + bytes([padding_length] * padding_length)
        print(f"Padded data (hex): {padded_data.hex()}")

        # Encrypt the data
        prev_block = iv
        encrypted_blocks = []
        
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            # XOR with previous ciphertext block (CBC mode)
            block = bytes(x ^ y for x, y in zip(block, prev_block))
            # Encrypt block
            state = [[block[row * 4 + col] for col in range(4)] for row in range(4)]
            encrypted_state = self.aes.encrypt(state, list(self.aes_key))
            encrypted_block = bytes(sum(encrypted_state, []))
            encrypted_blocks.append(encrypted_block)
            prev_block = encrypted_block
        
        ciphertext = b''.join(encrypted_blocks)
        full_message = iv + ciphertext
        print(f"Full encrypted message (hex): {full_message.hex()}")
        return full_message

    def aes_decrypt(self, ciphertext):
        """Decrypt using AES implementation"""
        print(f"\n{self.name}: Performing AES decryption")
        print(f"Received encrypted message (hex): {ciphertext.hex()}")

        # Split IV and ciphertext
        iv = ciphertext[:16]
        actual_ciphertext = ciphertext[16:]
        print(f"Extracted IV (hex): {iv.hex()}")
        print(f"Extracted ciphertext (hex): {actual_ciphertext.hex()}")

        # Decrypt all blocks
        prev_block = iv
        decrypted_blocks = []
        
        for i in range(0, len(actual_ciphertext), 16):
            block = actual_ciphertext[i:i+16]
            # Convert to state matrix
            state = [[block[row * 4 + col] for col in range(4)] for row in range(4)]
            # Decrypt block
            decrypted_state = self.aes.decrypt(state, list(self.aes_key))
            decrypted_block = bytes(sum(decrypted_state, []))
            # XOR with previous ciphertext block (CBC mode)
            plain_block = bytes(x ^ y for x, y in zip(decrypted_block, prev_block))
            decrypted_blocks.append(plain_block)
            prev_block = block

        # Combine blocks and remove padding
        plaintext = b''.join(decrypted_blocks)
        padding_length = plaintext[-1]
        message = plaintext[:-padding_length].decode()
        print(f"Final decrypted message: {message}")
        return message