#!/usr/bin/env python3
"""Apply a block of Korean translations into script/dialogue.csv.

usage:
  apply_translations.py CSV JSON

JSON maps "block-sub-stroff" (e.g. "09-00-014C") -> full translated string
for that game string, using the same {tags} and \\n page-internal line
breaks as the `japanese` column, with {W} marking page boundaries. This
script splits it into pages (same rule as top_text.pages) and writes each
page into the matching row's `korean` column.
"""
import csv, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from top_text import pages, read_csv, COLS  # noqa: E402


def apply_translations(csv_path, json_path):
    translations = json.load(open(json_path, encoding='utf-8'))
    rows = read_csv(csv_path)
    by_key = {}
    for r in rows:
        key = '%02d-%02d-%s' % (int(r['block']), int(r['sub']), r['str_off'])
        by_key.setdefault(key, []).append(r)

    missing, mismatched = [], []
    for key, text in translations.items():
        group = by_key.get(key)
        if not group:
            missing.append(key)
            continue
        group.sort(key=lambda r: int(r['page']))
        pg_texts = pages(text)
        if len(pg_texts) != len(group):
            mismatched.append((key, len(pg_texts), len(group)))
            continue
        for row, pg in zip(group, pg_texts):
            row['korean'] = pg

    if missing:
        print('WARNING: %d keys not found in CSV: %s' % (len(missing), missing[:10]))
    if mismatched:
        print('WARNING: %d keys with page-count mismatch:' % len(mismatched))
        for key, got, want in mismatched:
            print('  %s: translated has %d page(s), CSV expects %d' % (key, got, want))

    with open(csv_path, 'w', encoding='utf-8-sig', newline='') as f:
        wr = csv.DictWriter(f, COLS)
        wr.writeheader()
        wr.writerows(rows)
    print('applied %d/%d keys' % (len(translations) - len(missing) - len(mismatched), len(translations)))
    return not missing and not mismatched


if __name__ == '__main__':
    ok = apply_translations(sys.argv[1], sys.argv[2])
    sys.exit(0 if ok else 1)
