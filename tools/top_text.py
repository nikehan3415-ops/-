#!/usr/bin/env python3
"""Tales of Phantasia (GBA, JP AN8J) dialogue extractor / validator.

usage:
  top_text.py extract ROM OUT.csv      # dump dialogue to CSV
  top_text.py verify  ROM IN.csv       # round-trip check of the `japanese` column
  top_text.py check   IN.csv           # lint the `korean` column against the original

Script data layout (found by analysis):
  ROM 0x27474C : 54 x u32 pointers to scenario blocks (0x6C7EC4-0x7BC2A4)
  ROM 0x7BC2A8 : one extra block referenced directly from code (0x5F10)
  block        : one or more chained sub-blocks
  sub-block    : u32 script_off, u32 text_off, u32 event_count, event_count x 8 bytes,
                 script bytecode, text area, then one 0xFF byte (next sub-block may be unaligned)
  text area    : 0x0000-terminated strings of u16 LE tokens.
                 The script references a string by its byte offset in the text area
                 (e.g. opcode `11 <u16 off>`), so strings may start at odd offsets.
"""
import csv, os, re, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
TBL_PATH = os.path.join(HERE, '..', 'tables', 'top_jp.tbl')
BLOCK_TABLE = 0x27474C
BLOCK_COUNT = 54
EXTRA_BLOCKS = [0x7BC2A8]
BLOCK_END = 0x7C0000

NAMES = {1: 'クレス', 2: 'ミント', 3: 'アーチェ', 4: 'クラース', 5: 'チェスター', 6: 'すず'}
# control code -> tag name for 1-arg codes
ARG1 = {5: 'SPD', 6: 'COL', 7: 'N', 8: 'ITEM', 9: 'TITLE'}
EXPR = {0xB: 'EXB', 0xC: 'EXC', 0xD: 'EXD', 0xE: 'VAR'}   # followed by a script expression ending in 0x80
COLS = ['id', 'block', 'sub', 'sub_addr', 'str_off', 'page', 'speaker', 'japanese', 'korean', 'note']


def load_tbl(path=TBL_PATH):
    dec, enc = {}, {}
    for line in open(path, encoding='utf-8'):
        line = line.rstrip('\n')
        if not line or line.startswith('#'):
            continue
        k, v = line.split('=', 1)
        k = int(k, 16)
        dec[k] = v
        enc.setdefault(v, k)
    return dec, enc


def expr_len(b, i):
    """length of a script expression starting at b[i] (terminated by 0x80)."""
    s = i
    while True:
        op = b[i]; i += 1
        if op == 0x80:
            return i - s
        if op == 0xC8:
            i += 2
        elif op == 0xC0 or 0xE0 <= op <= 0xEF or 0x40 <= op <= 0x7F:
            i += 1


def blocks(rom):
    """yield (block_no, sub_no, sub_addr, text_start) for every sub-block."""
    ptrs = struct.unpack_from('<%dI' % BLOCK_COUNT, rom, BLOCK_TABLE)
    starts = sorted(set(p - 0x08000000 for p in ptrs) | set(EXTRA_BLOCKS))
    for n, b in enumerate(starts):
        e = starts[n + 1] if n + 1 < len(starts) else BLOCK_END
        x, sub = b, 0
        while x + 12 <= e:
            so, to, cnt = struct.unpack_from('<3I', rom, x)
            if not (12 <= so <= to < e - x and cnt < 0x400):
                break
            yield n, sub, x, x + to
            _, end = split_strings(rom, x + to)
            x, sub = end + 1, sub + 1


def split_strings(rom, t0):
    """return list of (byte_off, raw_bytes incl. terminator) and the end offset."""
    out, i = [], t0
    while not (rom[i] == 0xFF and rom[i + 1] != 0):   # 0x00FF is the glyph ヴ
        s = i
        while True:
            v = rom[i] | rom[i + 1] << 8; i += 2
            if v == 0:
                break
            if v in ARG1:
                i += 2
            elif v == 0xA:
                i += 4
            elif v in EXPR:
                i += expr_len(rom, i)
        out.append((s - t0, rom[s:i]))
    return out, i


def decode(raw, dec, enc):
    """raw string bytes (with terminator) -> tagged text."""
    o, i = [], 0
    while True:
        v = raw[i] | raw[i + 1] << 8; i += 2
        if v == 0:
            break
        if v == 3:
            o.append('\n')
        elif v == 4:
            o.append('{W}')
        elif v in ARG1:
            a = raw[i] | raw[i + 1] << 8; i += 2
            o.append('{%s%d}' % (ARG1[v], a) if v == 7 else '{%s:%X}' % (ARG1[v], a))
        elif v == 0xA:
            o.append('{NUM:%X}' % struct.unpack_from('<I', raw, i)); i += 4
        elif v in EXPR:
            n = expr_len(raw, i)
            o.append('{%s:%s}' % (EXPR[v], raw[i:i + n].hex().upper())); i += n
        elif v < 0x10:
            o.append('{C:%X}' % v)
        elif v in dec and enc[dec[v]] == v:
            o.append(dec[v])
        else:
            o.append('{G:%X}' % v)         # unknown / duplicate glyph
    return ''.join(o)


TAG = re.compile(r'\{([A-Z]+)(\d+|:[0-9A-F]+)?\}|\n|.', re.S)
NAMEWORDS = {'SPD': 5, 'COL': 6, 'ITEM': 8, 'TITLE': 9}


def encode(text, enc):
    """tagged text -> raw bytes (with terminator). raises ValueError."""
    out = bytearray()
    w = lambda v: out.extend(struct.pack('<H', v))
    for m in TAG.finditer(text):
        s = m.group(0)
        if s == '\n':
            w(3)
        elif m.group(1):
            name, arg = m.group(1), m.group(2) or ''
            if name == 'W' and not arg:
                w(4)
            elif name == 'N' and arg.isdigit():
                w(7); w(int(arg))
            elif name in NAMEWORDS and arg.startswith(':'):
                w(NAMEWORDS[name]); w(int(arg[1:], 16))
            elif name == 'NUM':
                w(0xA); out.extend(struct.pack('<I', int(arg[1:], 16)))
            elif name in EXPR.values() and arg.startswith(':'):
                w({v: k for k, v in EXPR.items()}[name]); out.extend(bytes.fromhex(arg[1:]))
            elif name == 'C' and arg.startswith(':'):
                w(int(arg[1:], 16))
            elif name == 'G' and arg.startswith(':'):
                w(int(arg[1:], 16))
            else:
                raise ValueError('bad tag %s' % s)
        elif s in enc:
            w(enc[s])
        else:
            raise ValueError('unencodable char %r' % s)
    w(0)
    return bytes(out)


def pages(text):
    """split a string at {W} (kept at the end of each page)."""
    parts = re.split(r'(?<=\{W\})', text)
    return [p for p in parts if p] or ['']


SPK = re.compile(r'^((?:\{N\d\}|[^\n{「『（]){1,12})\n[「『（]')


def speaker(page):
    m = SPK.match(page)
    if not m:
        return ''
    return re.sub(r'\{N(\d)\}', lambda x: NAMES.get(int(x.group(1)), x.group(0)), m.group(1))


def extract(rom, out):
    dec, enc = load_tbl()
    rows, sid = [], 0
    for n, sub, b, t0 in blocks(rom):
        strs, _ = split_strings(rom, t0)
        for off, raw in strs:
            for p, pg in enumerate(pages(decode(raw, dec, enc))):
                rows.append({'id': '%02d-%02d-%04X-%02d' % (n, sub, off, p), 'block': n, 'sub': sub,
                             'sub_addr': '%06X' % b,
                             'str_off': '%04X' % off, 'page': p, 'speaker': speaker(pg),
                             'japanese': pg, 'korean': '', 'note': ''})
    with open(out, 'w', encoding='utf-8-sig', newline='') as f:
        wr = csv.DictWriter(f, COLS); wr.writeheader(); wr.writerows(rows)
    print('blocks=%d rows=%d -> %s' % (n + 1, len(rows), out))


def read_csv(path):
    with open(path, encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def group(rows, col):
    g = {}
    for r in rows:
        g.setdefault((int(r['block']), int(r['sub']), int(r['str_off'], 16)), []).append(r)
    return {k: ''.join(x[col] for x in sorted(v, key=lambda x: int(x['page']))) for k, v in g.items()}


def verify(rom, path):
    """re-encode the japanese column and compare with the ROM byte by byte."""
    dec, enc = load_tbl()
    strings = group(read_csv(path), 'japanese')
    err = unk = total = 0
    for n, sub, b, t0 in blocks(rom):
        strs, end = split_strings(rom, t0)
        rebuilt = bytearray()
        for off, raw in strs:
            total += 1
            txt = strings.get((n, sub, off))
            if txt is None:
                print('MISSING %d-%d off %04X' % (n, sub, off)); err += 1; continue
            unk += len(re.findall(r'\{G:[0-9A-F]+\}', txt))
            try:
                e = encode(txt, enc)
            except ValueError as ex:
                print('ENCODE %d-%d off %04X: %s' % (n, sub, off, ex)); err += 1; continue
            if e != raw:
                print('MISMATCH %d-%d off %04X' % (n, sub, off)); err += 1
            rebuilt += e
        if bytes(rebuilt) != rom[t0:end]:
            print('SUB-BLOCK %d-%d text area differs' % (n, sub)); err += 1
    extra = len(strings) - total
    print('strings=%d errors=%d unknown_glyph_tags=%d extra_rows=%d' % (total, err, unk, extra))
    print('RESULT:', 'PASS' if err == 0 and extra == 0 else 'FAIL')
    return err == 0 and extra == 0


# ---- translation lint -------------------------------------------------------
MAX_LINE = 17       # dialogue box width in full-width cells (99.8% of original lines)
MAX_LINES = 3       # lines per page box incl. speaker line


def ctrl_tags(s):
    return sorted(re.findall(r'\{(?!W\})[^}]*\}', s))


def width(line):
    line = re.sub(r'\{N(\d)\}', lambda m: NAMES.get(int(m.group(1)), 'XXXXX'), line)
    line = re.sub(r'\{(ITEM|TITLE):[0-9A-F]+\}', 'X' * 8, line)
    line = re.sub(r'\{[^}]*\}', '', line)
    return len(line)


def check(path):
    rows = read_csv(path)
    bad = done = 0
    for r in rows:
        ko, jp = r['korean'], r['japanese']
        if not ko:
            continue
        done += 1
        msgs = []
        if ctrl_tags(ko) != ctrl_tags(jp):
            msgs.append('control tags differ %s != %s' % (ctrl_tags(ko), ctrl_tags(jp)))
        if ko.count('{W}') != jp.count('{W}') or ko.endswith('{W}') != jp.endswith('{W}'):
            msgs.append('{W} count/position differs')
        if re.search(r'\{(?![A-Z]+(\d+|:[0-9A-F]+)?\})', ko) or ko.count('{') != ko.count('}'):
            msgs.append('broken brace tag')
        # special screens (credits, signs) may exceed the box; allow the original's own size
        jp_pages = [pg.split('\n') for pg in re.split(r'\{W\}', jp)]
        lim_w = max([MAX_LINE] + [width(ln) for pg in jp_pages for ln in pg])
        lim_l = max([MAX_LINES] + [len(pg) for pg in jp_pages])
        for pg in re.split(r'\{W\}', ko):
            ls = pg.split('\n')
            if len(ls) > lim_l:
                msgs.append('too many lines (%d)' % len(ls))
            for ln in ls:
                if width(ln) > lim_w:
                    msgs.append('line too long (%d): %s' % (width(ln), ln))
        if msgs:
            bad += 1
            print('[%s] %s' % (r['id'], '; '.join(msgs)))
    print('translated=%d/%d problems=%d' % (done, len(rows), bad))
    print('RESULT:', 'PASS' if bad == 0 else 'FAIL')
    return bad == 0


if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'extract':
        extract(open(sys.argv[2], 'rb').read(), sys.argv[3])
    elif cmd == 'verify':
        sys.exit(0 if verify(open(sys.argv[2], 'rb').read(), sys.argv[3]) else 1)
    elif cmd == 'check':
        sys.exit(0 if check(sys.argv[2]) else 1)
    else:
        print(__doc__)
