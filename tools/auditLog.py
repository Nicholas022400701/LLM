#!/usr/bin/env python3
# auditLog v1: checks what a run-job workflow run may reveal. Prints counts only, never log content.
#   self  - inside the workflow: result listing + meta/parts field values + job id form
#   log   - on a saved Actions job log: key / canary hits, unknown 64-hex, residual free-text lines
import argparse, ast, json, os, re, sys
hex64 = re.compile(r'\b[0-9a-f]{64}\b'); hex40 = re.compile(r'\b[0-9a-f]{40}\b')
isoRe = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z'
tokRe = re.compile(r'^(?:[0-9a-f]{64}|[0-9a-f]{40}|' + isoRe + r'|[A-Za-z0-9_.:/+-]{1,80})$')
freeTextKeys = {"uname", "format", "workflow", "repository", "runnerOs", "python", "cryptography", "version", "image"}
reportKeys = {"jobId", "plainBytes", "plainSha256", "encBytes", "encSha256", "exitCode", "startUtc", "endUtc", "runId"}
listingRe = re.compile(r'^(meta\.json|parts\.json|output\.enc\.b64(\.part\d{3})?)$')
def walk(obj, key=""):
    if isinstance(obj, dict):
        for k, v in obj.items(): yield from walk(v, k)
    elif isinstance(obj, list):
        for v in obj: yield from walk(v, key)
    else: yield key, obj
def badValue(k, v):
    if v is None or isinstance(v, (bool, int, float)): return False
    if not isinstance(v, str): return True
    return k not in freeTextKeys and not tokRe.match(v)
def cmdSelf(a):
    bad = 0
    if not re.fullmatch(a.job_pattern, a.job): print("job id form FAIL"); bad += 1
    else: print("job id form ok")
    if not os.path.isdir(a.res): print("no result dir (nothing to audit)"); sys.exit(6 if bad else 0)
    names = sorted(os.listdir(a.res)); odd = [n for n in names if not listingRe.match(n)]
    print("result listing: %d files, unexpected names %d" % (len(names), len(odd))); bad += len(odd)
    for n in ("meta.json", "parts.json"):
        p = os.path.join(a.res, n)
        if not os.path.exists(p): continue
        vals = list(walk(json.load(open(p)))); b = [k for k, v in vals if badValue(k, v)]
        print("%s: %d values, unexpected %d" % (n, len(vals), len(b))); bad += len(b)
    print("audit self: %s" % ("ok" if bad == 0 else "FAIL %d" % bad)); sys.exit(6 if bad else 0)
def prefixes(paths):
    out = set()
    for p in paths:
        txt = open(p, encoding="utf-8", errors="replace").read()
        for m in re.finditer(r'(?:echo|print|exit|SystemExit|die)\s*\(?\s*f?(["\'])(.*?)\1', txt):
            s = re.split(r'[$%{\\]', m.group(2))[0].strip()
            if len(s) >= 6: out.add(s)
    return out
def cmdLog(a):
    tsRe = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z ?'); ansi = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
    wfLines = set(); srcPaths = [p for p in [a.workflow] + a.source if p]
    for p in srcPaths:
        for ln in open(p, encoding="utf-8", errors="replace"): wfLines.add(ln.strip())
    pre = sorted(prefixes(srcPaths), key=len, reverse=True)
    known = set()
    for p in a.known_hex: known |= set(hex64.findall(open(p, encoding="utf-8", errors="replace").read()))
    canaries = [c.strip() for c in open(a.canary_file)] if a.canary_file else []; canaries = [c for c in canaries if c]
    key = os.environ.get(a.key_env, "") if a.key_env else ""
    c = dict(lines=0, github=0, ours=0, wfText=0, marker=0, envLine=0, envBad=0, prefix=0, prefixFree=0, dict=0, dictBad=0, residual=0, keyHits=0, canaryHits=0, unknown64=0, hex40Distinct=0)
    ours = False; residual = []; all64 = set(); ok64 = set(); all40 = set()
    for raw in open(a.log, encoding="utf-8", errors="replace"):
        line = ansi.sub("", tsRe.sub("", raw.rstrip("\n"))); c["lines"] += 1
        low = line.lower()
        if key: c["keyHits"] += low.count(key.lower())
        for cn in canaries: c["canaryHits"] += line.count(cn)
        all40 |= set(hex40.findall(low)); h = set(hex64.findall(low)); all64 |= h
        s = line.strip()
        if s.startswith("##[group]Run "):
            ours = not s[13:].startswith("actions/")
        elif re.match(r'^(Post job cleanup\.|Cleaning up orphan processes|Complete job name:|Evaluate and set job outputs)', s): ours = False
        if not ours: c["github"] += 1; ok64 |= h; continue
        c["ours"] += 1
        if s.startswith("##["): c["marker"] += 1; ok64 |= h; continue
        if s in wfLines and s: c["wfText"] += 1; continue
        if s.startswith("{") and s.endswith("}"):
            c["dict"] += 1
            try:
                d = ast.literal_eval(s); bad = [k for k in d if k not in reportKeys] + [k for k, v in d.items() if badValue(k, v)]
            except Exception: bad = ["unparsable"]
            if bad: c["dictBad"] += 1; residual.append(line)
            else: ok64 |= h
            continue
        hit = next((p for p in pre if s.startswith(p)), None)
        if hit:
            c["prefix"] += 1
            if re.search(r'([A-Za-z]{3,}\s+){3,}[A-Za-z]{3,}', s[len(hit):]): c["prefixFree"] += 1; residual.append(line)
            else: ok64 |= h
            continue
        m = re.match(r'^(shell|env|[A-Z_][A-Z0-9_]*): ?(.*)$', s)
        if m and not s.startswith("{"):
            c["envLine"] += 1
            if not re.fullmatch(r'\*\*\*|true|false|-?\d+|/usr/bin/bash.*|[A-Za-z0-9_./:+-]{0,80}', m.group(2)): c["envBad"] += 1; residual.append(line)
            continue
        residual.append(line)
    c["residual"] = len(residual); c["unknown64"] = len(all64 - known - ok64); c["hex40Distinct"] = len(all40)
    if a.out:
        with open(a.out, "w") as f: f.write("\n".join(residual) + ("\n" if residual else ""))
    if a.shape:
        for r in residual[: a.shape]: print("  shape:", re.sub(r'\d', '9', re.sub(r'[A-Za-z]', 'a', r))[:70])
    fail = c["keyHits"] or c["canaryHits"] or c["unknown64"] or c["residual"]
    print("audit log:", json.dumps(c, separators=(",", ":"))); print("audit log: %s" % ("ok" if not fail else "FAIL")); sys.exit(6 if fail else 0)
ap = argparse.ArgumentParser(); sp = ap.add_subparsers(dest="cmd", required=True)
s1 = sp.add_parser("self"); s1.add_argument("--res", required=True); s1.add_argument("--job", required=True); s1.add_argument("--job-pattern", default=r'j-\d{8}-[0-9a-f]{6}')
s2 = sp.add_parser("log"); s2.add_argument("--log", required=True); s2.add_argument("--workflow", default=".github/workflows/run-job.yml"); s2.add_argument("--source", action="append", default=["tools/cryptBox.py"])
s2.add_argument("--known-hex", action="append", default=[]); s2.add_argument("--canary-file"); s2.add_argument("--key-env"); s2.add_argument("--out"); s2.add_argument("--shape", type=int, default=0)
a = ap.parse_args(); cmdSelf(a) if a.cmd == "self" else cmdLog(a)
