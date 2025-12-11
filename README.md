# UEFI 安全启动数据库解析器

用于生成和解析 UEFI 安全启动数据库（PK、KEK、DB、DBX）的 Python 工具集。

## 功能

- **生成器** (`create.py`)：使用自签名 X.509 证书和 SHA256 黑名单条目创建模拟 UEFI 安全启动数据库。
- **解析器** (`resolver.py`)：解析二进制签名列表并将证书详情导出到 Excel。

## 使用方法

### 生成测试数据库
```bash
python create.py
```
生成：`PK.bin`、`KEK.bin`、`db.bin`、`dbx.bin`

### 解析并导出到 Excel
```bash
python resolver.py
```
生成：`UEFI_SecureBoot_entries.xlsx`

## 依赖

```
cryptography
openpyxl
```

安装方式：
```bash
pip install cryptography openpyxl
```

## 文件说明

| 文件 | 说明 |
|------|------|
| `create.py` | 生成模拟 UEFI 安全启动数据库二进制文件 |
| `resolver.py` | 解析二进制数据库并导出到 Excel |
| `PK.bin`、`KEK.bin`、`db.bin`、`dbx.bin` | 生成的安全启动数据库文件 |
| `UEFI_SecureBoot_entries.xlsx` | 解析后的证书和签名数据 |

## 许可证

见 LICENSE 文件。
