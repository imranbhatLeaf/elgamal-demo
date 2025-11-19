#----------------------------------------------
# Simple ElGamal Digital Signature
# ---------------------------------------------------

import random
from hashlib import sha256
from math import gcd

# -------------------------------
# Hash the message into an integer
# -------------------------------
def hash_message(message, q):
    h = int(sha256(message.encode()).hexdigest(), 16)
    return h % q

# -------------------------------
# Compute modular inverse
# -------------------------------
def mod_inverse(a, m):
    """Return inverse of a mod m using Extended Euclid"""
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        a, m = m, a % m
        x0, x1 = x1 - q * x0, x0
    return x1 % m0

# -------------------------------
# Key Generation
# -------------------------------
def generate_keys(q, a):
    XA = random.randint(1, q - 1)        # private key
    YA = pow(a, XA, q)                   # public key
    return XA, (q, a, YA)

# -------------------------------
# Signing
# -------------------------------
def sign_message(message, XA, q, a):
    m = hash_message(message, q)

    # pick K such that gcd(K, q−1) = 1
    while True:
        K = random.randint(1, q - 2)
        if gcd(K, q - 1) == 1:
            break

    S1 = pow(a, K, q)
    K_inv = mod_inverse(K, q - 1)
    S2 = (K_inv * (m - XA * S1)) % (q - 1)

    return (S1, S2)

# -------------------------------
# Verification
# -------------------------------
def verify_signature(message, signature, q, a, YA):
    S1, S2 = signature
    m = hash_message(message, q)

    V1 = pow(a, m, q)
    V2 = (pow(YA, S1, q) * pow(S1, S2, q)) % q

    print(f"\nVerification Check:")
    print(f"V1 : {V1}")
    print(f"V2 : {V2}")
    return V1 == V2

# -------------------------------
# Demo
# -------------------------------
if __name__ == "__main__":
    # Small values for easy demonstration
    q = 10007      # prime
    a = 5       # primitive root

    print("=== ElGamal Digital Signature Demo ===")
    print(f"Prime (q): {q}")
    print(f"Primitive root (a): {a}")

    # Generate keys
    XA, public_key = generate_keys(q, a)
    q, a, YA = public_key

    print("\nPrivate key (XA):", XA)
    print("Public key (q, a, YA):", public_key)

    # Message to sign
    message = "Hello ElGamal"
    print("\nMessage:", message)

    # Sign the message
    signature = sign_message(message, XA, q, a)
    print("Signature (S1, S2):", signature)

    # Verify the signature
    is_valid = verify_signature(message, signature, q, a, YA)
    print("Signature valid?:", is_valid)