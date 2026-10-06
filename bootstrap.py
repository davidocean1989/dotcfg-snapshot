# -*- coding: utf-8 -*-
"""bootstrap.py —— 在一台全新电脑上恢复全部工作能力

用法：
    python bootstrap.py                 # 交互输口令，恢复本机配置
    python bootstrap.py --dry-run       # 只解密并列清单，不写任何文件
    python bootstrap.py --check         # 只校验口令对不对
    python bootstrap.py --get 关键词     # 打印匹配的条目（用来单独取某条密钥）
    python bootstrap.py --dump-json .   # 解密并写出完整 JSON（明文！谨慎）

依赖：pip install cryptography
前置条件只有两条：能上网 + 记得口令。手机、邮箱、密码管理器都不参与。
"""
from __future__ import annotations

import argparse
import base64
import getpass
import gzip
import json
import os
import shutil
import sys
import time

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    sys.exit("缺少依赖，请先执行：pip install cryptography")

HERE = os.path.dirname(os.path.abspath(__file__))
VAULT = os.path.join(HERE, "keyvault.vault")


def load_armor(path):
    head, body, inside = {}, [], False
    with open(path, "r", encoding="ascii") as fh:
        for line in fh:
            line = line.rstrip("\r\n")
            if line.startswith("-----BEGIN"):
                inside = True
                continue
            if line.startswith("-----END"):
                break
            if not inside or not line:
                continue
            if ":" in line and not line.startswith(" "):
                k, v = line.split(":", 1)
                head[k.strip().lower()] = v.strip()
            else:
                body.append(line)
    if not body:
        sys.exit("金库文件无法解析（找不到密文体）。")
    # Fernet token 本身就是 urlsafe-base64 文本，拼接后直接就是 token，不可再解一次
    return head, "".join(body).encode("ascii")


def parse_kdf(spec):
    n = int(spec.split("N=")[1].split()[0])
    r = int(spec.split("r=")[1].split()[0])
    p = int(spec.split("p=")[1].split()[0])
    return n, r, p


def derive(pw, salt, head):
    n, r, p = parse_kdf(head.get("kdf", "scrypt N=131072 r=8 p=1"))
    return base64.urlsafe_b64encode(
        Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(pw.encode("utf-8"))
    )


def ask():
    if sys.stdin.isatty():
        return getpass.getpass("口令: ")
    print("口令: ", end="", flush=True)
    return sys.stdin.readline().rstrip("\r\n")


def decrypt(path, pw=None):
    head, token = load_armor(path)
    salt = base64.b64decode(head["salt"])
    if pw is None:
        print("金库文件 : %s" % os.path.basename(path))
        print("KDF      : %s" % head.get("kdf"))
        print("算法     : %s" % head.get("cipher"))
        print("编码     : %s" % head.get("encoding", "json"))
        print()
        pw = ask()
    t0 = time.time()
    key = derive(pw, salt, head)
    try:
        raw = Fernet(key).decrypt(token)
    except InvalidToken:
        sys.exit("\n口令错误（或金库被篡改）—— HMAC 校验未通过。")
    if head.get("encoding", "json").startswith("gzip"):
        raw = gzip.decompress(raw)
    return json.loads(raw.decode("utf-8")), time.time() - t0


def show_tree(data, label):
    print("\n【%s】" % label)

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, path + (k if not path else " · " + str(k)))
        elif isinstance(node, list):
            for v in node:
                walk(v, path)
        else:
            shown = ("%d 字符" % len(node)) if isinstance(node, str) else node
            print("  - %-62s %s" % (path, shown))

    walk(data)


def restore(data, out_dir=None, root=None):
    files = data.get("files", {})
    rmap = data.get("restore_map", {})
    root = os.path.expanduser(root) if root else os.path.expanduser("~")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    written = []
    for logical, content in sorted(files.items()):
        if out_dir:
            target = os.path.join(out_dir, logical.replace("/", os.sep))
            mode = "0644"
        else:
            spec = rmap.get(logical)
            if not spec:
                target = os.path.join(root, logical.replace("/", os.sep))
                mode = "0600"
            else:
                target, mode = spec.split("|")
                target = os.path.expanduser(target)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.exists(target):
            shutil.copy2(target, target + ".bak-" + stamp)
        with open(target, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content if content.endswith("\n") else content + "\n")
        try:
            os.chmod(target, int(mode, 8))
        except Exception:
            pass
        written.append((logical, target, len(content), mode))
    return written


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vault", default=VAULT)
    ap.add_argument("--check", action="store_true", help="只校验口令")
    ap.add_argument("--dry-run", action="store_true", help="解密并列清单，不落盘")
    ap.add_argument("--get", metavar="关键词", help="打印匹配的条目")
    ap.add_argument("--only", metavar="文件名片段", help="只恢复匹配的文件")
    ap.add_argument("--out-dir", metavar="目录", help="全部解到指定目录，不动 ~")
    ap.add_argument("--dump-json", metavar="目录", help="写出完整明文 JSON（谨慎）")
    a = ap.parse_args()

    if not os.path.isfile(a.vault):
        sys.exit("找不到金库文件：%s" % a.vault)

    data, _ = decrypt(a.vault)
    print("\n✅ 口令正确")
    print("   创建时间 : %s" % data.get("created"))
    print("   版本     : %s" % data.get("version"))

    if a.get:
        needle = a.get
        hit = 0
        def walk(node, path=""):
            nonlocal hit
            if isinstance(node, dict):
                for k, v in node.items():
                    walk(v, path + "/" + str(k))
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    walk(v, path + "[%d]" % i)
            elif isinstance(node, str):
                if needle.lower() in path.lower() or needle.lower() in node.lower():
                    if len(node) > 400:
                        return
                    print("  %s\n      %s" % (path.strip("/"), node))
                    hit += 1
        walk(data)
        print("\n命中 %d 条" % hit)
        return

    show_tree(data.get("facts", {}), "连接事实")
    print("\n【可恢复文件】")
    for logical in sorted(data.get("files", {})):
        print("  - %-52s %d 字符" % (logical, len(data["files"][logical])))
    print("\n【随库文档】%d 篇" % len(data.get("docs", {})))

    if a.check:
        print("\n(--check：未写入任何文件)")
        return

    if a.dump_json:
        os.makedirs(a.dump_json, exist_ok=True)
        p = os.path.join(a.dump_json, "vault.plaintext.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        print("\n[!] 明文已写出：%s（用完请立即删除！）" % p)

    if a.dry_run:
        print("\n(--dry-run：未写入任何文件)")
        return

    files = data.get("files", {})
    if a.only:
        files = {k: v for k, v in files.items() if a.only in k}
        data = dict(data, files=files)
    written = restore(data, out_dir=a.out_dir)

    print("\n已恢复：")
    for logical, target, size, mode in written:
        print("  ✓ %-46s -> %s (%s)" % (logical, target, mode))
    if not written:
        print("  （无）")

    if not a.out_dir:
        print("""
接下来做什么：
  1. 重启 WorkBuddy —— 知识库（rag-kb）会自动生效，可以直接检索。
  2. 本机若没装 cryptography：pip install cryptography
  3. 要连服务器：ssh -i ~/.ssh/wb_ed25519 root@<facts 里的 host>
  4. 换机完成后，建议把旧机上的凭据轮换一遍（GitHub token / Cloudflare token / VPS 密码）。
  5. 想单独取某条密钥：python bootstrap.py --get 关键词
""")


if __name__ == "__main__":
    main()
