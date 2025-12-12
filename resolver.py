#UEFI 安全启动数据库解析器
#解析 PK/KEK/DB/DBX 签名列表并导出证书信息到 CSV 文件

import struct
import uuid
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import csv

def parse_signature_list(data):
    offset = 0
    results = []

    while offset < len(data):

        # 至少要有 EFI_SIGNATURE_LIST 的固定头（28 bytes）
        if len(data) - offset < 28:
            break

        SignatureType = uuid.UUID(bytes_le=data[offset:offset+16])
        SignatureListSize, SignatureHeaderSize, SignatureSize = struct.unpack(
            "<III", data[offset+16:offset+28]
        )

        # 简单边界判断（部分主板可能产生损坏结构）
        if SignatureListSize < 28 or offset + SignatureListSize > len(data):
            break

        header_start = offset + 28
        header_end = header_start + SignatureHeaderSize
        header = data[header_start:header_end]

        entry_offset = header_end
        end_of_list = offset + SignatureListSize

        # 遍历结构内每个 SignatureData 条目
        while entry_offset + SignatureSize <= end_of_list:
            entry = data[entry_offset:entry_offset + SignatureSize]

            owner_guid = uuid.UUID(bytes_le=entry[:16])
            signature_data = entry[16:]

            info = {
                "SignatureType": str(SignatureType),
                "OwnerGUID": str(owner_guid),
                "is_x509": False,
                "subject": "",
                "issuer": "",
                "serial_number": "",
                "not_before": "",
                "not_after": "",
                "data_length": len(signature_data),
            }

            # ----------- 尝试解析 X.509（无弃用警告） -------------
            try:
                cert = x509.load_der_x509_certificate(signature_data, default_backend())
                info["is_x509"] = True
                info["subject"] = cert.subject.rfc4514_string()
                info["issuer"] = cert.issuer.rfc4514_string()
                info["serial_number"] = str(cert.serial_number)

                # 使用无警告的新属性（包含 UTC 时区）
                info["not_before"] = cert.not_valid_before_utc.isoformat()
                info["not_after"] = cert.not_valid_after_utc.isoformat()

            except Exception:
                pass  # 非证书，例如 dbx SHA256 条目

            results.append(info)
            entry_offset += SignatureSize

        offset += SignatureListSize

    return results


# ----------- 读取 PK / KEK / DB / DBX 文件 -------------
default_prefixes = {
    "PK": "PK",
    "KEK": "KEK",
    "db": "db",
    "dbx": "dbx"
}

# 让用户输入包含这些文件的目录（留空表示当前目录）
input_dir = input("请输入包含 PK/KEK/db/dbx 文件的目录路径（留空为当前目录）：").strip()
if input_dir == "":
    input_dir = "."

def find_file_by_prefix(directory, prefix):
    try:
        for name in os.listdir(directory):
            name_lower = name.lower()
            p = prefix.lower()
            if name_lower.startswith(p):
                # 确保 'db' 不会错误匹配 'dbx'：下一字符若存在且为字母数字则拒绝
                if len(name_lower) == len(p) or not name_lower[len(p)].isalnum():
                    return os.path.join(directory, name)
        return None
    except FileNotFoundError:
        return None

all_entries = []

for store_name, prefix in default_prefixes.items():
    filepath = find_file_by_prefix(input_dir, prefix)
    if not filepath:
        print(f"在目录 {input_dir} 中未找到以 '{prefix}' 开头的文件，跳过 {store_name}。")
        continue
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        entries = parse_signature_list(data)
        for e in entries:
            e["Store"] = store_name
        all_entries.extend(entries)
    except Exception as ex:
        print(f"读取文件 {filepath} 时出错：{ex}")


# ----------- 生成 CSV -------------
output_file = "UEFI_SecureBoot_entries.csv"
headers = [
    "Store", "SignatureType", "OwnerGUID", "is_x509",
    "subject", "issuer", "serial_number",
    "not_before", "not_after", "data_length"
]

with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(headers)
    for e in all_entries:
        writer.writerow([
            e.get("Store", ""),
            e.get("SignatureType", ""),
            e.get("OwnerGUID", ""),
            e.get("is_x509", ""),
            e.get("subject", ""),
            e.get("issuer", ""),
            e.get("serial_number", ""),
            e.get("not_before", ""),
            e.get("not_after", ""),
            e.get("data_length", "")
        ])

print(f"CSV 文件已生成：{output_file}")
