import hashlib,json,numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
GENESIS="0"*64
def digest(frame): return hashlib.sha256(np.ascontiguousarray(frame).tobytes()).hexdigest()
def link(prev,seq,fh,ts): return hashlib.sha256(json.dumps([prev,int(seq),fh,round(float(ts),6)],separators=(",",":")).encode()).hexdigest()
def keypair():
 k=Ed25519PrivateKey.generate()
 return (k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode(),k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode())
def sign(private,payload): return serialization.load_pem_private_key(private.encode(),None).sign(payload.encode()).hex()
def verify(public,payload,sig):
 try: serialization.load_pem_public_key(public.encode()).verify(bytes.fromhex(sig),payload.encode()); return True
 except Exception: return False
