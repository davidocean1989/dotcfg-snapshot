# dotcfg-snapshot

跨机器同步个人环境引导信息的快照仓库。

## 文件

| 文件 | 说明 |
|---|---|
| `keyvault.vault` | 主文件。ASCII armor 文本，自描述 KDF 参数与盐值 |
| `keyvault.enc` | 同一份密文的裸 Fernet token（备用格式） |
| `bootstrap.py` | 恢复脚本 |

## 恢复

```bash
git clone https://github.com/davidocean1989/dotcfg-snapshot.git
cd dotcfg-snapshot
pip install cryptography
python bootstrap.py
```

脚本会提示输入口令，解密后重建本机配置：`~/.workbuddy/mcp.json`、`~/.ssh/` 下的密钥、助手脚本。
`python bootstrap.py --dry-run` 可以先只看清单不落盘。

## 说明

- 密文由 `scrypt(N=2^17, r=8, p=1)` 派生密钥后经 `AES-128-CBC + HMAC-SHA256`（Fernet）加密，明文先经 gzip 压缩。
- 前 5 行头部为明文，因为解密时需要 KDF 参数与盐值；安全性不依赖算法保密。
- **口令不在本仓库、不在任何文件中。遗忘即无法恢复。**
- 盐值每次重新生成都会更换，因此无法通过比对两次密文推断哪些内容没变。
