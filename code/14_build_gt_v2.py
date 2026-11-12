# -*- coding: utf-8 -*-
"""14_build_gt_v2.py: ground truth v2, separating "code written by the malware author" from "library/runtime code".

Ground truth v1 (01_extract_symtab_gt.py) marks payload/helper functions by NAME rules only, so the malware's `main`
(the C2 loop of Mirai), exploit modules (`nuuo_init`, `httpd_serve`, `update_bins`, ...) and self-written packet
senders (`SendUDP`, `audp`, ...) end up as "other" together with libc. Ground truth v2 assigns a role to EVERY
symbolized function of the malware:

  library : name in the list of functions of libc/libm/libpthread/libresolv/librt/libcrypt/libgcc (glibc, `nm` of the
            static libraries), OR name starting with '_' (internal to libc/uClibc/crt/libgcc), OR name present in
            >= 10% of the ground-truth files (shared library code, as in 05/08), OR function hash in the library
            hash database (08_hash_functions.py, all ground-truth files)
  payload : as in v1 (name rules + EXTRA_MALWARE_NAMES)  ┐
  helper  : as in v1                                     ├─ "author code"
  author  : everything else (including `main`)           ┘

Output (folder --out, used instead of workdir/gt via `--gt-dir workdir/gt_v2` of 02_localize_functions.py):
  gt_functions.csv : file_hash, addr, size, name, role, role_detail
                     role = 'payload' for payload AND author (positive class = author code that is not a utility),
                            'helper', 'other' (= library)   -> usable by 02 without changes
  gt_files.csv     : as in v1, n_payload recomputed
  SUMMARY_GT_v2.md, author_names_top100.csv (the 100 most frequent author names, for manual review)

Usage: python3 14_build_gt_v2.py --gt-dir workdir/gt --hashes workdir/function_hashes \
           --libc-names workdir/gt_v2/libc_glibc_names.txt --out workdir/gt_v2
"""
import argparse, csv, gzip, os, re
from collections import Counter, defaultdict

EXTRA_MALWARE_NAMES = re.compile(r'flood|attack|scanner|killer|watchdog|vse|deobf|random_string|^astd$|^add_strings$|'
                                 r'^add_entry$|^rand_alpha_str$|^rand_int$|^rand_next_range$|^getRandom|^makeRandom|huawei|'
                                 r'exploit|botkill|^csum$|^trim$|^itoa$|cnc|^do_clone$', re.I)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--gt-dir', required=True)
    ap.add_argument('--hashes', required=True, help='folder with function_hashes.csv.gz (08_hash_functions.py)')
    ap.add_argument('--libc-names', required=True); ap.add_argument('--out', required=True)
    a = ap.parse_args()
    libc = {l.strip() for l in open(a.libc_names, encoding='utf-8') if l.strip() and not l.startswith('#')}
    rows = list(csv.DictReader(open(os.path.join(a.gt_dir, 'gt_functions.csv'), encoding='utf-8')))
    files = list(csv.DictReader(open(os.path.join(a.gt_dir, 'gt_files.csv'), encoding='utf-8')))
    n_files = len({r['file_hash'] for r in rows})
    # v1 roles (with EXTRA_MALWARE_NAMES) + shared library names (>= 10% of the files, as in 05/08)
    for r in rows:
        if r['role'] == 'other' and EXTRA_MALWARE_NAMES.search(r['name']):
            r['role'] = 'payload'
    name_files = defaultdict(set)
    for r in rows:
        if r['role'] == 'other':
            name_files[r['name']].add(r['file_hash'])
    shared = {n for n, s in name_files.items() if len(s) / n_files >= 0.10 and n != 'main'}
    # function hashes of all ground-truth files + library hash database (shared library code, no malware hash)
    h_of = {}
    with gzip.open(os.path.join(a.hashes, 'function_hashes.csv.gz'), 'rt', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            h_of[(r['file_hash'], r['addr'])] = r['h_op']
    lib_h, mal_h = set(), set()
    for r in rows:
        hh = h_of.get((r['file_hash'], r['addr']))
        if hh is None:
            continue
        if r['role'] in ('payload', 'helper'):
            mal_h.add(hh)
        elif r['name'] in shared:
            lib_h.add(hh)
    lib_h -= mal_h
    reasons = Counter()
    for r in rows:
        v = r['role']
        if v in ('payload', 'helper'):
            r['role_detail'] = v
            continue
        n = r['name']
        if n in libc:
            r['role_detail'], why = 'library', 'libc_name'
        elif n.startswith('_'):
            r['role_detail'], why = 'library', 'leading_underscore'
        elif n in shared:
            r['role_detail'], why = 'library', 'shared_name_10pct'
        elif h_of.get((r['file_hash'], r['addr'])) in lib_h:
            r['role_detail'], why = 'library', 'library_hash'
        else:
            r['role_detail'], why = 'author', 'remaining'
        reasons[why] += 1
    for r in rows:
        r['role'] = {'payload': 'payload', 'author': 'payload', 'helper': 'helper', 'library': 'other'}[r['role_detail']]
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, 'gt_functions.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['file_hash', 'addr', 'size', 'name', 'role', 'role_detail'])
        w.writeheader(); w.writerows({k: r[k] for k in w.fieldnames} for r in rows)
    npay = Counter(r['file_hash'] for r in rows if r['role'] == 'payload')
    for t in files:
        t['n_payload'] = npay.get(t['file_hash'], 0)
    with open(os.path.join(a.out, 'gt_files.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(files[0].keys())); w.writeheader(); w.writerows(files)
    ct = Counter(r['role_detail'] for r in rows)
    au = Counter(r['name'] for r in rows if r['role_detail'] == 'author')
    with open(os.path.join(a.out, 'author_names_top100.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['name', 'n_files'])
        for n, c in au.most_common(100):
            w.writerow([n, c])
    L = ['# Ground truth v2 (%d files, %d functions)' % (n_files, len(rows)), '',
         '| Detailed role | Functions |', '|---|---|'] + ['| %s | %d |' % (k, v) for k, v in ct.most_common()] + \
        ['', 'Reasons for the library / author assignment (only functions that are not v1 payload/helper):', ''] + \
        ['- %s: %d' % (k, v) for k, v in reasons.most_common()] + \
        ['', 'Most frequent `author` names (for manual review; libc names found here should be added to the libc list):', '',
         ', '.join('%s (%d)' % (n, c) for n, c in au.most_common(60))]
    open(os.path.join(a.out, 'SUMMARY_GT_v2.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    print('\n'.join(L))


if __name__ == '__main__':
    main()
