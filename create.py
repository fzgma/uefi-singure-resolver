# 生成模拟的 UEFI 安全启动数据库
# PK、KEK、db：使用 cryptography 生成自签名 X.509 证书
# dbx：为 SHA256 哈希黑名单条目

import os
import uuid, struct, hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta, timezone

default_save_path = "."  # 默认使用运行目录

# 允许用户自定义生成路径（留空使用当前运行目录）
input_path = input(f"请输入生成文件的保存路径（留空使用当前运行目录）：").strip()
if input_path == "":
    save_path = os.getcwd()
else:
    save_path = input_path

# 规范为绝对路径并确保目录存在
save_path = os.path.abspath(save_path)
os.makedirs(save_path, exist_ok=True)
print(f"输出目录：{save_path}")

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


for name, data in paths.items():
    out_path = os.path.join(save_path, name)
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"已写入：{out_path}")
