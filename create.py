# Generate simulated UEFI Secure Boot databases for a Gigabyte motherboard
# PK, KEK, db: include self-signed X.509 certs using cryptography
# dbx: include SHA256 hash blacklist entries

import os
import uuid, struct, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta, timezone  


def gen_cert(subject_name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ])
    now = datetime.now(timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=100))
        .not_valid_after(now + timedelta(days=400))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)

def make_sig_list(sig_type_guid, cert_list):
    # GUID (16 bytes) + 3x UINT32 + header + entries
    header = b""
    SignatureHeaderSize = len(header)
    entries = []

    SignatureSize = 16 +  len(cert_list[0])  # Owner GUID + Cert

    for cert in cert_list:
        owner_guid = uuid.uuid4().bytes_le
        entries.append(owner_guid + cert)

    SignatureListSize = 28 + SignatureHeaderSize + len(entries) * SignatureSize
    
    out = b""
    out += sig_type_guid.bytes_le
    out += struct.pack("<III", SignatureListSize, SignatureHeaderSize, SignatureSize)
    out += header
    for e in entries:
        out += e
    return out

# UEFI signature GUIDs
EFI_CERT_X509_GUID = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
EFI_CERT_SHA256_GUID = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")

# Generate certs
pk_cert = gen_cert("Platform Key (PK)")
kek_cert = gen_cert("Key Exchange Key (KEK)")
db_cert1 = gen_cert("UEFI CA A (Sim)")
db_cert2 = gen_cert("UEFI CA B (Sim)")

# Create PK, KEK, db
PK_bin = make_sig_list(EFI_CERT_X509_GUID, [pk_cert])
KEK_bin = make_sig_list(EFI_CERT_X509_GUID, [kek_cert])
db_bin = make_sig_list(EFI_CERT_X509_GUID, [db_cert1, db_cert2])

# Create dbx (SHA256 blacklist)
def random_sha256():
    return hashlib.sha256(os.urandom(64)).digest()

dbx_entries = [random_sha256() for _ in range(10)]
# SHA256: signature size = 16 + 32
def make_dbx():
    header = b""
    SignatureHeaderSize = len(header)
    SignatureSize = 16 + 32

    entries = []
    for digest in dbx_entries:
        owner_guid = uuid.uuid4().bytes_le
        entries.append(owner_guid + digest)

    SignatureListSize = 28 + SignatureHeaderSize + len(entries) * SignatureSize
    
    out = b""
    out += EFI_CERT_SHA256_GUID.bytes_le
    out += struct.pack("<III", SignatureListSize, SignatureHeaderSize, SignatureSize)
    out += header
    for e in entries:
        out += e
    return out

dbx_bin = make_dbx()

# Save files
paths = {
    "PK.bin": PK_bin,
    "KEK.bin": KEK_bin,
    "db.bin": db_bin,
    "dbx.bin": dbx_bin
}

save_path = "C:/code/py"

for name, data in paths.items():
    with open(f"{save_path}/{name}", "wb") as f:
        f.write(data)
