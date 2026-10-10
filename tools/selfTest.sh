#!/usr/bin/env bash
# cryptBox v1 local self-test: fake data and a throwaway key only; prints counts, exit codes and SHA256 only
set -euo pipefail
t=$(mktemp -d)
export LLM_DATA_KEY=$(python3 -c "import os;print(os.urandom(32).hex())")
job=selftest-$(date -u +%Y%m%dT%H%M%SZ)
mkdir -p "$t/in/sub" "$t/out1" "$t/out2" "$t/out3"
head -c 1048576 /dev/urandom > "$t/in/blob.bin"
head -c 4096 /dev/urandom > "$t/in/sub/small.bin"
printf 'print("hello")\n' > "$t/in/run.py"
echo "== encrypt (b64 + split, default part size)"
python3 tools/cryptBox.py encrypt --dir "$t/in" --out "$t/enc/input.enc" --job "$job" --b64 --split
ls "$t/enc" | wc -l | sed 's/^/files in enc dir: /'
echo "== decrypt from binary .enc with meta check"
python3 tools/cryptBox.py decrypt --in "$t/enc/input.enc" --dir "$t/out1" --job "$job" --meta "$t/enc/meta.json"
echo "== decrypt from .b64 only"
mkdir -p "$t/b" && cp "$t/enc/input.enc.b64" "$t/b/" && python3 tools/cryptBox.py decrypt --in "$t/b/input.enc" --dir "$t/out2" --job "$job"
echo "== decrypt from parts only"
mkdir -p "$t/p" && cp "$t/enc/parts.json" "$t/enc/"*.part* "$t/p/" && python3 tools/cryptBox.py decrypt --in "$t/p/input.enc" --dir "$t/out3" --job "$job"
echo "== roundtrip compare (diff -r, expect no output)"
diff -r "$t/in" "$t/out1" && diff -r "$t/in" "$t/out2" && diff -r "$t/in" "$t/out3" && echo "roundtrip identical x3"
echo "== determinism: encrypt twice, plainSha256 must match"
a=$(python3 tools/cryptBox.py encrypt --dir "$t/in" --out "$t/d1/x.enc" --job "$job" | grep -o 'plainSha256=[0-9a-f]*')
b=$(python3 tools/cryptBox.py encrypt --dir "$t/in" --out "$t/d2/x.enc" --job "$job" | grep -o 'plainSha256=[0-9a-f]*')
[ "$a" = "$b" ] && echo "deterministic payload: $a"
echo "== negatives (expect nonzero exit codes)"
set +e
LLM_DATA_KEY=$(python3 -c "import os;print(os.urandom(32).hex())") python3 tools/cryptBox.py decrypt --in "$t/enc/input.enc" --dir "$t/neg1" --job "$job" 2>/dev/null; echo "wrong key exit=$?"
python3 tools/cryptBox.py decrypt --in "$t/enc/input.enc" --dir "$t/neg2" --job "${job}-other" 2>/dev/null; echo "wrong jobId exit=$?"
python3 -c "
p='$t/enc/input.enc';b=bytearray(open(p,'rb').read());b[40]^=1;open('$t/tamper.enc','wb').write(b)"
python3 tools/cryptBox.py decrypt --in "$t/tamper.enc" --dir "$t/neg3" --job "$job" 2>/dev/null; echo "tampered ciphertext exit=$?"
python3 -c "
p='$t/p/input.enc.b64.part001';b=bytearray(open(p,'rb').read());b[10]=ord('A') if b[10]!=ord('A') else ord('B');open(p,'wb').write(b)"
python3 tools/cryptBox.py decrypt --in "$t/p/input.enc" --dir "$t/neg4" --job "$job" 2>/dev/null; echo "tampered part exit=$?"
LLM_DATA_KEY=short python3 tools/cryptBox.py encrypt --dir "$t/in" --out "$t/neg5/x.enc" --job "$job" 2>/dev/null; echo "bad key format exit=$?"
python3 tools/cryptBox.py encrypt --dir "$t/in" --out "$t/neg6/x.enc" --job "../evil" 2>/dev/null; echo "bad jobId exit=$?"
set -e
echo "== meta.json shape (non-sensitive)"; cat "$t/enc/meta.json"
echo "== parts.json shape"; python3 -c "import json;d=json.load(open('$t/enc/parts.json'));print({k:(v if k!='parts' else [v[0],'...']) for k,v in d.items()})"
echo "== MANIFEST.json shape (from decrypted payload)"
python3 - <<PY
import os,json,tarfile,io,base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
b=open('$t/enc/input.enc','rb').read();k=bytes.fromhex(os.environ['LLM_DATA_KEY'])
p=AESGCM(k).decrypt(b[8:20],b[20:],'$job'.encode())
t=tarfile.open(fileobj=io.BytesIO(p),mode='r:gz');m=json.load(t.extractfile('MANIFEST.json'))
print(json.dumps(m,indent=1)[:600])
print('tar members:',[x.name for x in t.getmembers()])
PY
rm -rf "$t"
echo "SELFTEST DONE"
