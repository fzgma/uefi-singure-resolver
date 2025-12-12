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
运行时脚本会提示输入保存路径（留空使用当前运行目录）。脚本会创建目录（如不存在），并在所选目录生成：`PK.bin`、`KEK.bin`、`db.bin`、`dbx.bin`。示例：

```bash
python create.py
# 输入: D:/tmp/uefi_files
# 输出: D:/tmp/uefi_files/PK.bin 等
```

### 解析并导出到 CSV
```bash
python resolver.py
```
运行时脚本会提示输入包含 PK/KEK/db/dbx 文件的目录路径（留空使用当前目录）。解析器不再严格检查文件后缀，它会在指定目录中按前缀匹配文件名（以 `PK`、`KEK`、`db`、`dbx` 开头的文件均可），找到后进行解析并导出为 `UEFI_SecureBoot_entries.csv`。

## 依赖

```
cryptography
```

安装方式：
```bash
pip install -r requirements.txt
```

## 文件说明

| 文件 | 说明 |
|------|------|
| `create.py` | 生成模拟 UEFI 安全启动数据库二进制文件 |
| `resolver.py` | 解析二进制数据库并导出到 CSV |
| `PK.bin`、`KEK.bin`、`db.bin`、`dbx.bin` | 生成的安全启动数据库文件 |
| `UEFI_SecureBoot_entries.csv` | 解析后的证书和签名数据 |

## 许可证

见 LICENSE 文件。
