from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os



# def modular_inverse(a, p):
#     # Extended Euclidean Algorithm to find modular inverse
#     if a == 0:
#         return 0
#     lm, hm = 1, 0
#     low, high = a % p, p
#     while low > 1:
#         ratio = high // low
#         nm, new = hm - lm * ratio, high - low * ratio
#         hm, high, lm, low = lm, low, nm, new
#     return lm % p

# def curve25519_mult(n, point):
#     """ Perform scalar multiplication of point and integer n on Curve25519 """
#     p = 2**255 - 19
#     a = 486662
#     x1, z1 = point, 1
#     x2, z2 = 1, 0
#     for bit in reversed(bin(n)[2:]):
#         if bit == '1':
#             x2, z2, x1, z1 = x1, z1, (x1 * x2 - z1 * z2) % p, (x1 * z2 + z1 * x2 - 2 * a * z1 * z2) % p
#         x2, z2 = (x2**2 - z2**2) % p, (2 * x2 * z2 - a * z2**2) % p
#     return x1 * modular_inverse(z1, p) % p

# def generate_key_pair():
#     import os
#     private_key = int.from_bytes(os.urandom(32), 'little')
#     public_key = curve25519_mult(private_key, 9)
#     return private_key, public_key

# Example usage



# Constants
P = 2**255 - 19
A24 = 121666  # (486662 - 2) / 4

def clamped_scalar(scalar):
    scalar = list(scalar)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return bytes(scalar)

def cswap(swap, x_2, x_3):
    """Conditional swap based on the current bit."""
    dummy = swap * (x_2 - x_3)
    x_2 -= dummy
    x_3 += dummy
    return x_2, x_3

def curve25519(x, scalar):
    """Montgomery ladder for scalar multiplication on Curve25519."""
    x_1 = x
    x_2, z_2 = 1, 0
    x_3, z_3 = x, 1
    swap = 0

    scalar = clamped_scalar(scalar)

    for t in reversed(range(255)):
        k_t = (scalar[t // 8] >> (t % 8)) & 1
        swap ^= k_t
        x_2, x_3 = cswap(swap, x_2, x_3)
        z_2, z_3 = cswap(swap, z_2, z_3)
        swap = k_t
        
        A = (x_2 + z_2) % P
        AA = (A * A) % P
        B = (x_2 - z_2) % P
        BB = (B * B) % P
        E = (AA - BB) % P
        C = (x_3 + z_3) % P
        D = (x_3 - z_3) % P
        DA = (D * A) % P
        CB = (C * B) % P
        x_3 = ((DA + CB) ** 2) % P
        z_3 = (x_1 * ((DA - CB) ** 2) % P) % P
        x_2 = (AA * BB) % P
        z_2 = (E * (AA + (A24 * E) % P)) % P

    x_2, x_3 = cswap(swap, x_2, x_3)
    z_2, z_3 = cswap(swap, z_2, z_3)
    return (x_2 * pow(z_2, P - 2, P)) % P

def generate_key_pair():
    """Generates a public/private key pair."""
    private_key = os.urandom(32)
    public_key = curve25519(9, private_key)
    return private_key, public_key

# Example usage





# ======


# def generate_key_pair():
#     """Generate an ECC private key using the 25519 elliptical curve."""
#     return X25519PrivateKey.generate()

def derive_shared_secret(private_key, public_key):
    """Derive the shared secret using ECDH from a private and a public key."""
    return private_key.exchange(ec.ECDH(), public_key)

def hkdf_expand(shared_secret, length=32):
    """Expand the shared secret using HKDF."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=b'X3DH key agreement',
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

def perform_x3dh(sender_priv, sender_pub, receiver_priv, receiver_pub):
    """Perform the X3DH key exchange."""
    # DH1: Sender's ephemeral key with Receiver's long-term public key
    dh1 = derive_shared_secret(sender_priv, receiver_pub)

    # DH2: Receiver's long-term private key with Sender's ephemeral public key
    dh2 = derive_shared_secret(receiver_priv, sender_pub)

    # DH3: Sender's ephemeral private key with Receiver's ephemeral public key (not shown in parameters)
    # This step is usually included if both parties generate ephemeral keys for each session.

    # DH4: Sender's long-term private key with Receiver's long-term public key (optional additional step)
    # Not shown in parameters, but can be included for enhanced security.

    # Combine the secrets derived from DH exchanges
    combined_secret = dh1 + dh2  # DH3 and DH4 can be appended if used.

    # Derive the final shared secret key
    return hkdf_expand(combined_secret)

class DoubleRatchet:
    def __init__(self, shared_secret):
        # Initialize the root key and chain key using the shared secret from X3DH
        self.root_key, self.chain_key = self.init_keys(shared_secret)

    def init_keys(self, shared_secret):
        # Use HKDF to derive the initial root key and chain key from the shared secret
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'Double Ratchet Init',
            backend=default_backend()
        )
        keys = hkdf.derive(shared_secret)
        return keys[:32], keys[32:]

    def ratchet_step(self):
        # Symmetric ratchet step: derive new chain key from the current chain key
        self.chain_key = hmac.HMAC(self.chain_key, hashes.SHA256(), backend=default_backend())
        self.chain_key.update(b'0')  # Assume '0' as input for simplicity in updating chain keys
        self.chain_key = self.chain_key.finalize()

    def encrypt(self, plaintext):
        # Encrypt using the current chain key
        cipher = Cipher(algorithms.AES(self.chain_key), modes.GCM(b'\x00' * 12), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        self.ratchet_step()  # Update the chain key after each message
        return encryptor.tag, ciphertext

    def decrypt(self, tag, ciphertext):
        # Decrypt using the current chain key
        cipher = Cipher(algorithms.AES(self.chain_key), modes.GCM(b'\x00' * 12, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        self.ratchet_step()  # Update the chain key after each message
        return plaintext
    

def create_shared_key():
    sender_private_key, sender_public_key = generate_key_pair()
    print("Private Key:", sender_private_key)
    print("Public Key:", sender_public_key)

    # sender_private_key = generate_key_pair()
    # sender_public_key = sender_private_key.public_key()

    receiver_private_key, receiver_public_key = generate_key_pair()
    

    shared_secret = perform_x3dh(sender_private_key, sender_public_key, receiver_private_key, receiver_public_key)
    return shared_secret