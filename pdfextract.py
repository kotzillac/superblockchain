"""PDF text extractor: handles xref streams + ObjStm, then reconstructs layout."""
import re, sys, zlib, struct

PATH = r"C:\Users\Kirill\Downloads\RISCV_CARD.pdf"
data = open(PATH, "rb").read()

# raw stream locator
stream_re = re.compile(rb"stream\r?\n(.*?)endstream", re.S)

def obj_body_from_offset(off):
    start = data.find(b"obj", off)
    end = data.find(b"endobj", off)
    if start == -1 or end == -1:
        return b""
    return data[start + 3:end]

def parse_dict_head(raw):
    raw = raw.strip()
    if not raw.startswith(b"<<"):
        return b"", raw
    depth = 0
    i = 0
    while i < len(raw) - 1:
        if raw[i:i+2] == b"<<":
            depth += 1; i += 2
        elif raw[i:i+2] == b">>":
            depth -= 1
            if depth == 0:
                return raw[2:i], raw[i+2:]
            i += 2
        else:
            i += 1
    return raw[2:], b""

def dict_kv(s):
    out = {}
    toks = re.findall(rb"/[A-Za-z][A-Za-z0-9]*|<<|>>|\[|\]|<[0-9A-Fa-f\s]*>|\((?:\\.|[^\\()])*\)|[A-Za-z]+|[-+]?[0-9]*\.?[0-9]+", s)
    i = 0
    n = len(toks)
    def take_value(i):
        """Consume one object starting at token i; return (value_text, next_i)."""
        if i >= n:
            return b"", i
        t = toks[i]
        if t == b"<<":
            depth = 1; j = i + 1
            while j < n and depth:
                if toks[j] == b"<<": depth += 1
                elif toks[j] == b">>": depth -= 1
                j += 1
            return b" ".join(toks[i:j]), j
        if t == b"[":
            depth = 1; j = i + 1
            while j < n and depth:
                if toks[j] == b"[": depth += 1
                elif toks[j] == b"]": depth -= 1
                j += 1
            return b" ".join(toks[i:j]), j
        if t.startswith(b"/"):
            return t, i + 1
        if t.startswith(b"(") or t.startswith(b"<"):
            return t, i + 1
        # number or keyword: check for indirect reference "N N R"
        if i + 2 < n and re.fullmatch(rb"-?[0-9]+", t) and re.fullmatch(rb"-?[0-9]+", toks[i+1]) and toks[i+2] == b"R":
            return b" ".join(toks[i:i+3]), i + 3
        return t, i + 1
    while i < n:
        t = toks[i]
        if t.startswith(b"/"):
            v, ni = take_value(i + 1)
            out[t[1:]] = v
            i = ni
        else:
            i += 1
    return out

def decompress_stream(raw):
    head, _ = parse_dict_head(raw)
    d = dict_kv(head)
    sm = stream_re.search(raw)
    if not sm:
        return b""
    s = sm.group(1)
    if d.get(b"Filter", b"").strip() == b"/FlateDecode":
        s = zlib.decompress(s)
    return s

# ---- xref stream ----
startxref = int(re.search(rb"startxref\s+(\d+)", data).group(1))
xraw = obj_body_from_offset(startxref)
xhead, _ = parse_dict_head(xraw)
xd = dict_kv(xhead)
w = [int(x) for x in re.findall(rb"(\d+)", xd[b"W"])]
xsz = int(xd[b"Size"])
idx = xd.get(b"Index", b"0 " + str(xsz).encode())
nums = re.findall(rb"\d+", idx)
first = int(nums[0]) if nums else 0
count = int(nums[1]) if len(nums) > 1 else xsz
xstream = decompress_stream(xraw)
W1, W2, W3 = w
row_len = W1 + W2 + W3

# obj id -> (type, field2, field3)
entries = {}
for r in range(count):
    row = xstream[r*row_len:(r+1)*row_len]
    if len(row) < row_len:
        break
    if W1:
        t = int.from_bytes(row[0:W1], "big")
    else:
        t = 1
    f2 = int.from_bytes(row[W1:W1+W2], "big") if W2 else 0
    f3 = int.from_bytes(row[W1+W2:], "big") if W3 else 0
    entries[first + r] = (t, f2, f3)

# ---- ObjStm ----
def get_body(oid):
    t, f2, f3 = entries[oid]
    if t == 1:
        return obj_body_from_offset(f2)
    elif t == 2:
        # object inside objstm f2 at index f3
        stm_data = decompress_stream(obj_body_from_offset(entries[f2][1]))
        m = re.match(rb"\s*(\d+)\s+(\d+)\s*\r?\n", stm_data)
        n_obj = int(m.group(1))
        hdr_len = int(m.group(2))  # length of header (count line + pairs)
        base = m.end()
        pairs = {}
        for a, b in re.findall(rb"(\d+)\s+(\d+)", stm_data[:hdr_len]):
            if len(pairs) >= n_obj:
                break
            pairs[int(a)] = int(b)
        off = pairs[oid]
        sorted_offs = sorted(pairs.values())
        pos = sorted_offs.index(off)
        obj_start = base + off
        obj_end = base + sorted_offs[pos + 1] if pos + 1 < len(sorted_offs) else len(stm_data)
        return stm_data[obj_start:obj_end]
    return b""

# ---- page tree ----
def find_root():
    root_ref = xd.get(b"Root", b"")
    m = re.search(rb"(\d+)\s+\d+\s+R", root_ref)
    return int(m.group(1)) if m else None

root_id = find_root()
print("root:", root_id, file=sys.stderr)

pages = []
seen = set()
def walk(oid):
    if oid in seen:
        return
    seen.add(oid)
    body = get_body(oid)
    head, _ = parse_dict_head(body)
    d = dict_kv(head)
    t = d.get(b"Type", b"").strip()
    if t == b"/Pages":
        kids = d.get(b"Kids", b"")
        for k in re.findall(rb"(\d+)\s+\d+\s+R", kids):
            walk(int(k))
    elif t == b"/Page":
        pages.append(oid)

try:
    walk(root_id)
except Exception as e:
    import traceback; traceback.print_exc()
    # fallback: scan all objects for /Type /Page
    for oid in entries:
        if entries[oid][0] != 1:
            continue
        body = obj_body_from_offset(entries[oid][1])
        if b"/Type /Page" in body and b"/Type /Pages" not in body:
            pages.append(oid)
print("pages:", pages, file=sys.stderr)

# ---- content stream ----
TOKEN = re.compile(rb"\[|]|\((?:\\.|[^\\()])*\)|<[0-9A-Fa-f\s]*>|/[A-Za-z][A-Za-z0-9]*|[-+]?[0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]+)?")

def unescape(s):
    out = b""
    i = 0
    while i < len(s):
        c = s[i:i+1]
        if c == b"\\" and i + 1 < len(s):
            n = s[i+1:i+2]
            if n == b"n": out += b"\n"
            elif n == b"r": out += b"\r"
            elif n == b"t": out += b"\t"
            elif n == b"b": out += b"\b"
            elif n == b"f": out += b"\f"
            elif n == b"(": out += b"("
            elif n == b")": out += b")"
            elif n == b"\\": out += b"\\"
            elif n.isdigit():
                j = i + 1
                num = b""
                while j < len(s) and s[j:j+1].isdigit() and len(num) < 3:
                    num += s[j:j+1]; j += 1
                out += bytes([int(num, 8) & 0xFF])
                i = j - 1
            else:
                out += n
            i += 2
        else:
            out += c
            i += 1
    return out

def extract(content):
    out = []
    operands = []
    tx = ty = 0.0
    tl = 0.0
    fs = 10.0
    n = len(content)
    i = 0
    while i < n:
        c = content[i:i+1]
        if c in (b" ", b"\n", b"\r", b"\t", b"\x0c", b"\x00"):
            i += 1; continue
        if c == b"%":
            j = content.find(b"\n", i)
            i = j if j != -1 else n
            continue
        m = TOKEN.match(content, i)
        if not m:
            i += 1; continue
        tok = m.group(0)
        i = m.end()
        if tok.startswith(b"("):
            operands.append(unescape(tok[1:-1]))
        elif tok.startswith(b"<"):
            hx = re.sub(rb"\s", b"", tok[1:-1])
            try:
                bts = bytes.fromhex(hx.decode())
            except Exception:
                bts = b""
            operands.append(bts)
        elif tok == b"[":
            depth = 1
            arr = bytearray()
            while i < n and depth:
                if content[i:i+1] == b"[":
                    depth += 1
                elif content[i:i+1] == b"]":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                arr += content[i:i+1]
                i += 1
            operands.append(("ARR", bytes(arr)))
        elif re.fullmatch(rb"[-+]?[0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]+)?", tok):
            operands.append(float(tok))
        else:
            op = tok
            if op == b"BT":
                tx = ty = 0.0; operands = []
            elif op == b"ET":
                operands = []
            elif op == b"Tf":
                fs = operands[-1] if operands and isinstance(operands[-1], float) else fs
                operands = []
            elif op == b"TL":
                tl = operands[-1] if operands and isinstance(operands[-1], float) else tl
                operands = []
            elif op == b"Td":
                if len(operands) >= 2: tx += operands[-2]; ty += operands[-1]
                operands = []
            elif op == b"TD":
                if len(operands) >= 2:
                    tx += operands[-2]; ty += operands[-1]; tl = -operands[-1]
                operands = []
            elif op == b"T*":
                ty += tl; operands = []
            elif op == b"Tm":
                if len(operands) >= 6: tx, ty = operands[-6+4], operands[-6+5]
                operands = []
            elif op == b"cm":
                operands = []
            elif op == b"Tj":
                if operands and isinstance(operands[-1], bytes):
                    out.append((tx, ty, operands[-1]))
                operands = []
            elif op == b"'":
                ty += tl
                if operands and isinstance(operands[-1], bytes):
                    out.append((tx, ty, operands[-1]))
                operands = []
            elif op == b'"':
                ty += tl
                if operands and isinstance(operands[-1], bytes):
                    out.append((tx, ty, operands[-1]))
                operands = []
            elif op == b"TJ":
                for o in operands:
                    if isinstance(o, tuple) and o[0] == "ARR":
                        arr = o[1]
                        xoff = 0.0
                        for mm in re.finditer(rb"\((?:\\.|[^\\()])*\)|[-+]?[0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]+)?", arr):
                            p = mm.group(0)
                            if p.startswith(b"("):
                                out.append((tx + xoff, ty, unescape(p[1:-1])))
                            else:
                                xoff -= float(p) * 0.001 * fs
                operands = []
            else:
                operands = []
    return out

def page_content(pg):
    body = get_body(pg)
    head, _ = parse_dict_head(body)
    d = dict_kv(head)
    contents = d.get(b"Contents", b"").strip()
    out = b""
    if re.fullmatch(rb"\d+\s+\d+\s+R", contents):
        out += decompress_stream(obj_body_from_offset(entries[int(contents.split()[0])][1])) if entries.get(int(contents.split()[0]), (0,))[0] == 1 else get_stream_of(contents)
    else:
        for ident in re.findall(rb"(\d+)\s+\d+\s+R", contents):
            cid = int(ident)
            t, f2, f3 = entries[cid]
            if t == 1:
                out += decompress_stream(obj_body_from_offset(f2))
            elif t == 2:
                stm = get_body(cid)
                out += stm
    return out

def get_stream_of(contents):
    m = re.search(rb"(\d+)\s+\d+\s+R", contents)
    return decompress_stream(obj_body_from_offset(entries[int(m.group(1))][1])) if m and entries[int(m.group(1))][0] == 1 else b""

for pno, pg in enumerate(pages, 1):
    content = page_content(pg)
    items = extract(content)
    if not items:
        print(f"===== PAGE {pno}: no text =====")
        continue
    # group into lines by y
    lines = {}
    for x, y, s in items:
        key = round(y, 2)
        lines.setdefault(key, []).append((x, s))
    # choose y ordering: try both, prefer one where vertical gaps are regular
    def score(keys):
        return sum(1 for a, b in zip(keys, keys[1:]) if 0 < abs(b - a) < 6)
    ks_down = sorted(lines)
    ks_up = sorted(lines, reverse=True)
    use = ks_down if score(ks_down) >= score(ks_up) else ks_up
    print(f"===== PAGE {pno} =====")
    for key in use:
        row = " ".join(s.decode("latin-1") for x, s in sorted(lines[key], key=lambda p: p[0]))
        print(row)
