import os
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import (
    encode_dss_signature, decode_dss_signature
)
from cryptography.exceptions import InvalidSignature

from Crypto.Cipher import AES

# liboqs (Falcon)
import oqs

# ---------- Helper functions ----------

def int_to_bytes(x: int, length_bytes: int) -> bytes:
    return x.to_bytes(length_bytes, byteorder='big')

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, byteorder='big')

def bits_to_bytes_ceil(b: int) -> int:
    return (b + 7) // 8

# AES-CTR based PRP (r -> rF)
def prp_aes_ctr(input_bytes: bytes, key: bytes = None, counter: bytes = None) -> bytes:
    if key is None:
        key = bytes(16)  # lambda_P = 128 bits
    if counter is None:
        counter = bytes(16)
    ctr_val = bytes_to_int(counter)
    cipher = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=ctr_val)
    keystream = cipher.encrypt(bytes(len(input_bytes)))
    return bytes([a ^ b for a, b in zip(input_bytes, keystream)])

# ---------- ECDSA functions ----------

def ecdsa_generate_key():
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    return priv, pub

def ecdsa_sign(message: bytes, priv) -> Tuple[bytes, bytes]:
    der_sig = priv.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    r_bytes = int_to_bytes(r, 32)  # 256 bits
    s_bytes = int_to_bytes(s, 32)
    return r_bytes, s_bytes

def ecdsa_verify(message: bytes, r_bytes: bytes, s_bytes: bytes, pub) -> bool:
    r = bytes_to_int(r_bytes)
    s = bytes_to_int(s_bytes)
    der = encode_dss_signature(r, s)
    try:
        pub.verify(der, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False

# ---------- Falcon wrapper ----------

class Falcon512:
    def __init__(self):
        self.alg = "Falcon-512"

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        sig = oqs.Signature(self.alg)
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        return sk, pk

    def sign(self, message: bytes, sk: bytes) -> bytes:
        sig = oqs.Signature(self.alg, secret_key=sk)
        return sig.sign(message)

    def verify(self, message: bytes, signature: bytes, pk: bytes) -> bool:
        sig = oqs.Signature(self.alg, pk)
        return sig.verify(message, signature, pk)

# ---------- Hybrid Falcon-ECDSA ----------

class HybridFalconECDSA:
    def __init__(self, lambda_p_bits: int = 128):
        self.lambda_p_bits = lambda_p_bits
        self.falcon = Falcon512()

    def generate_keypairs(self):
        e_priv, e_pub = ecdsa_generate_key()
        f_priv, f_pub = self.falcon.generate_keypair()
        return e_priv, e_pub, f_priv, f_pub

    def hybrid_sign(self, message: bytes, e_priv, f_priv) -> Tuple[bytes, bytes, bytes]:
        # ECDSA sign
        rE, sE = ecdsa_sign(message, e_priv)
        len_rE_bits = 256
        len_rF_bits = 320
        r_tau_len_bits = len_rF_bits - len_rE_bits
        r_tau = os.urandom(bits_to_bytes_ceil(r_tau_len_bits))
        r = rE + r_tau

        # rF via PRP
        rF = prp_aes_ctr(r, key=bytes(bits_to_bytes_ceil(self.lambda_p_bits)))
        rF = rF[:bits_to_bytes_ceil(len_rF_bits)]

        # Falcon sign
        sF = self.falcon.sign(message, f_priv)

        return r, sE, sF

    def hybrid_verify(self, message: bytes, signature: Tuple[bytes, bytes, bytes], e_pub, f_pub) -> bool:
        r, sE, sF = signature
        rE = r[:32]
        rF = prp_aes_ctr(r, key=bytes(bits_to_bytes_ceil(self.lambda_p_bits)))
        rF = rF[:40]
        ok_ecdsa = ecdsa_verify(message, rE, sE, e_pub)
        ok_falcon = self.falcon.verify(message, sF, f_pub)
        return ok_ecdsa and ok_falcon

# ---------- Demo ----------

def main():
    hybrid = HybridFalconECDSA()
    e_sk, e_pk, f_sk, f_pk = hybrid.generate_keypairs()
    message = b"Test hybrid signature for PQC"

    print("Signing message...")
    r, sE, sF = hybrid.hybrid_sign(message, e_sk, f_sk)
    print(f"r (hex, len={len(r)}): {r.hex()}")
    print(f"sE (hex, len={len(sE)}): {sE.hex()[:64]}... (truncated)")
    print(f"sF (hex, len={len(sF)}): {sF.hex()[:64]}... (truncated)")

    print("\nVerifying hybrid signature...")
    result = hybrid.hybrid_verify(message, (r, sE, sF), e_pk, f_pk)
    print("Verification result:", result)

if __name__ == "__main__":
    main()
