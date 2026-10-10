#!/usr/bin/env python3
# cryptBox v1
# 目录 -> payload.tar.gz（内含 MANIFEST.json）-> AES-256-GCM -> .enc = "LLMBOX01"(8) + nonce(12) + 密文||tag(16)
# 密钥只从环境变量 LLM_DATA_KEY（64 位十六进制）读取；AAD = jobId 的 UTF-8 字节
# 只打印计数、字节数和 SHA256，不打印文件名、数据、密钥
import argparse, base64, datetime, gzip, hashlib, io, json, os, re, sys, tarfile
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
magic = b"LLMBOX01"
jobRe = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
def die(msg, code):
    print("cryptBox: " + msg, file=sys.stderr)
    sys.exit(code)
def utcNow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
def sha256Bytes(b):
    return hashlib.sha256(b).hexdigest()
def sha256File(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
def loadKey():
    k = os.environ.get("LLM_DATA_KEY", "")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", k):
        die("LLM_DATA_KEY must be 64 hex chars in the environment", 2)
    return bytes.fromhex(k)
def checkJob(job):
    if not jobRe.match(job):
        die("bad jobId (allowed: letters digits . _ - , max 100)", 1)
    return job.encode("utf-8")
def listFiles(d):
    out = []
    for root, dirs, files in os.walk(d):
        dirs.sort()
        for n in sorted(files):
            p = os.path.join(root, n)
            rel = os.path.relpath(p, d).replace(os.sep, "/")
            if os.path.islink(p) or not os.path.isfile(p):
                die("a non-regular file (symlink/special) is present, refusing", 1)
            if rel == "MANIFEST.json":
                die("MANIFEST.json at the top level is a reserved name", 1)
            out.append(rel)
    return sorted(out)
def tarInfo(name, size):
    ti = tarfile.TarInfo(name)
    ti.size = size
    ti.mtime = 0
    ti.mode = 0o644
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = ""
    return ti
def packDir(d, job):
    files = []
    for rel in listFiles(d):
        p = os.path.join(d, rel)
        files.append({"path": rel, "bytes": os.path.getsize(p), "sha256": sha256File(p)})
    manifest = {"cryptBox": "v1", "jobId": job, "files": files}
    mBytes = json.dumps(manifest, ensure_ascii=False, indent=1, sort_keys=True).encode("utf-8")
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, compresslevel=6) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT) as tar:
            tar.addfile(tarInfo("MANIFEST.json", len(mBytes)), io.BytesIO(mBytes))
            for f in files:
                with open(os.path.join(d, f["path"]), "rb") as fh:
                    tar.addfile(tarInfo(f["path"], f["bytes"]), fh)
    return buf.getvalue(), manifest
def encryptBytes(plain, key, aad):
    nonce = os.urandom(12)
    return magic + nonce + AESGCM(key).encrypt(nonce, plain, aad)
def decryptBytes(blob, key, aad):
    if len(blob) < 8 + 12 + 16 or blob[:8] != magic:
        die("not an LLMBOX01 file", 3)
    try:
        return AESGCM(key).decrypt(blob[8:20], blob[20:], aad)
    except InvalidTag:
        die("GCM tag check failed (wrong key, wrong jobId, or corrupted file)", 3)
def splitFile(path, kb, job):
    data = open(path, "rb").read()
    size = kb * 1024
    if len(data) <= size:
        print("split skipped: file fits in one part (%d <= %d bytes)" % (len(data), size))
        return None
    d = os.path.dirname(path) or "."
    parts = []
    for i, off in enumerate(range(0, len(data), size)):
        chunk = data[off:off + size]
        name = os.path.basename(path) + ".part%03d" % i
        with open(os.path.join(d, name), "wb") as f:
            f.write(chunk)
        parts.append({"name": name, "bytes": len(chunk), "sha256": sha256Bytes(chunk)})
    info = {"cryptBox": "v1", "jobId": job, "file": os.path.basename(path), "partBytes": size, "parts": parts, "totalBytes": len(data), "totalSha256": sha256Bytes(data)}
    with open(os.path.join(d, "parts.json"), "w") as f:
        json.dump(info, f, indent=1)
    return info
def joinParts(inPath):
    d = os.path.dirname(inPath) or "."
    pj = os.path.join(d, "parts.json")
    if not os.path.exists(pj):
        return None
    info = json.load(open(pj))
    base = os.path.basename(inPath)
    if info.get("file") not in (base, base + ".b64"):
        return None
    out = bytearray()
    for p in info["parts"]:
        chunk = open(os.path.join(d, p["name"]), "rb").read()
        if len(chunk) != p["bytes"] or sha256Bytes(chunk) != p["sha256"]:
            die("part sha256 mismatch", 5)
        out += chunk
    out = bytes(out)
    if len(out) != info["totalBytes"] or sha256Bytes(out) != info["totalSha256"]:
        die("joined file sha256 mismatch", 5)
    print("joined parts=%d totalBytes=%d totalSha256=%s" % (len(info["parts"]), len(out), info["totalSha256"]))
    return out
def readEnc(inPath):
    if os.path.exists(inPath):
        blob = open(inPath, "rb").read()
    elif os.path.exists(inPath + ".b64"):
        blob = open(inPath + ".b64", "rb").read()
    else:
        blob = joinParts(inPath)
        if blob is None:
            die("input not found (no file, no .b64, no matching parts.json)", 1)
    if blob[:8] != magic:
        try:
            blob = base64.b64decode(blob)
        except Exception:
            die("input is neither LLMBOX01 binary nor base64 text", 3)
    return blob
def unpackTo(plain, outDir, job):
    os.makedirs(outDir, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        members = tar.getmembers()
        if not members or members[0].name != "MANIFEST.json":
            die("MANIFEST.json must be the first tar member", 4)
        manifest = json.load(tar.extractfile(members[0]))
        if manifest.get("cryptBox") != "v1" or manifest.get("jobId") != job:
            die("MANIFEST cryptBox/jobId mismatch", 4)
        want = {f["path"]: f for f in manifest["files"]}
        seen = set()
        for m in members[1:]:
            n = m.name
            if not m.isreg() or n.startswith("/") or ".." in n.split("/") or n not in want or n in seen:
                die("tar member not allowed by MANIFEST", 4)
            seen.add(n)
            data = tar.extractfile(m).read()
            if len(data) != want[n]["bytes"] or sha256Bytes(data) != want[n]["sha256"]:
                die("file sha256 mismatch against MANIFEST", 4)
            dst = os.path.join(outDir, n)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "wb") as f:
                f.write(data)
        if seen != set(want):
            die("MANIFEST lists files missing from tar", 4)
    return manifest
def cmdEncrypt(a):
    aad = checkJob(a.job)
    key = loadKey()
    plain, manifest = packDir(a.dir, a.job)
    blob = encryptBytes(plain, key, aad)
    outDir = os.path.dirname(os.path.abspath(a.out))
    os.makedirs(outDir, exist_ok=True)
    with open(a.out, "wb") as f:
        f.write(blob)
    meta = {"jobId": a.job, "cryptBox": "v1", "createdUtc": utcNow(), "plainBytes": len(plain), "plainSha256": sha256Bytes(plain), "encBytes": len(blob), "encSha256": sha256Bytes(blob)}
    with open(a.meta or os.path.join(outDir, "meta.json"), "w") as f:
        json.dump(meta, f, indent=1)
    print("encrypt ok files=%d plainBytes=%d plainSha256=%s encBytes=%d encSha256=%s" % (len(manifest["files"]), meta["plainBytes"], meta["plainSha256"], meta["encBytes"], meta["encSha256"]))
    target = a.out
    if a.b64:
        target = a.out + ".b64"
        with open(target, "wb") as f:
            f.write(base64.encodebytes(blob))
        print("b64 ok bytes=%d sha256=%s" % (os.path.getsize(target), sha256File(target)))
    if a.split:
        info = splitFile(target, a.split, a.job)
        if info:
            print("split ok parts=%d partBytes=%d totalSha256=%s" % (len(info["parts"]), info["partBytes"], info["totalSha256"]))
def cmdDecrypt(a):
    aad = checkJob(a.job)
    key = loadKey()
    blob = readEnc(a.inPath)
    plain = decryptBytes(blob, key, aad)
    manifest = unpackTo(plain, a.dir, a.job)
    encSha = sha256Bytes(blob)
    plainSha = sha256Bytes(plain)
    print("decrypt ok files=%d plainBytes=%d plainSha256=%s encBytes=%d encSha256=%s" % (len(manifest["files"]), len(plain), plainSha, len(blob), encSha))
    if a.meta:
        meta = json.load(open(a.meta))
        if meta.get("plainSha256") != plainSha or meta.get("encSha256") != encSha or meta.get("plainBytes") != len(plain) or meta.get("jobId") != a.job:
            die("meta.json does not match decrypted content", 4)
        print("meta check ok")
def cmdSplit(a):
    checkJob(a.job)
    info = splitFile(a.inPath, a.kb, a.job)
    if info:
        print("split ok parts=%d partBytes=%d totalSha256=%s" % (len(info["parts"]), info["partBytes"], info["totalSha256"]))
def cmdAddmeta(a):
    meta = json.load(open(a.meta))
    for p in a.json or []:
        meta.update(json.load(open(p)))
    for kv in a.set or []:
        k, v = kv.split("=", 1)
        meta[k] = int(v) if re.fullmatch(r"-?\d+", v) else v
    with open(a.meta, "w") as f:
        json.dump(meta, f, indent=1)
    print("addmeta ok keys=%d" % len(meta))
def main():
    ap = argparse.ArgumentParser(prog="cryptBox", description="cryptBox v1: AES-256-GCM box for a directory; key from env LLM_DATA_KEY")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("encrypt")
    e.add_argument("--dir", required=True)
    e.add_argument("--out", required=True)
    e.add_argument("--job", required=True)
    e.add_argument("--meta")
    e.add_argument("--b64", action="store_true", help="also write <out>.b64 (base64 text, for text-only transports)")
    e.add_argument("--split", nargs="?", const=700, type=int, help="split the written file (the .b64 text when --b64) into parts of KB (default 700) + parts.json")
    e.set_defaults(fn=cmdEncrypt)
    d = sub.add_parser("decrypt")
    d.add_argument("--in", dest="inPath", required=True)
    d.add_argument("--dir", required=True)
    d.add_argument("--job", required=True)
    d.add_argument("--meta", help="meta.json to cross-check plainSha256/encSha256/plainBytes/jobId")
    d.set_defaults(fn=cmdDecrypt)
    s = sub.add_parser("split")
    s.add_argument("--in", dest="inPath", required=True)
    s.add_argument("--kb", type=int, default=700)
    s.add_argument("--job", required=True)
    s.set_defaults(fn=cmdSplit)
    m = sub.add_parser("addmeta")
    m.add_argument("--meta", required=True)
    m.add_argument("--json", action="append")
    m.add_argument("--set", action="append")
    m.set_defaults(fn=cmdAddmeta)
    a = ap.parse_args()
    a.fn(a)
if __name__ == "__main__":
    main()
