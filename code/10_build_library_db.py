# -*- coding: utf-8 -*-
"""10_build_library_db.py: whole-function hash database of library functions (FLIRT-like) for the library-aware HIN.

Reads the cache of 08_hash_functions.py (function_hashes.csv.gz, hashed_files.csv) and the ground truth. Only the
ground-truth files of the periods given by --periods (default 2020) are used:
  hashes of 'library' functions (role 'other', name present in >= 10% of the ground-truth files, except main) that
  are NEVER the hash of a malware function (payload/helper) -> one line per hash. By default the database is built
  from 2020 only and can therefore be used for every experiment on 2024 without leakage (the 2024 data set excludes
  files whose hash also occurs in 2020).
Output: <out>/library_functions_<periods>.txt (one '#' header line, then one line 'h_op<TAB>n_files<TAB>example_name'
        per hash)

Usage: python 10_build_library_db.py --gt-dir workdir/gt --cache workdir/function_hashes --out workdir/libaware [--periods 2020]
"""
import argparse, csv, gzip, os, re
from collections import Counter, defaultdict

EXTRA_MALWARE_NAMES = re.compile(r'flood|attack|scanner|killer|watchdog|vse|deobf|random_string|^astd$|^add_strings$|'
                                 r'^add_entry$|^rand_alpha_str$|^rand_int$|^rand_next_range$|^getRandom|^makeRandom|huawei|'
                                 r'exploit|botkill|^csum$|^trim$|^itoa$|cnc|^do_clone$', re.I)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--gt-dir', required=True); ap.add_argument('--cache', required=True); ap.add_argument('--out', required=True)
    ap.add_argument('--periods', nargs='+', default=['2020']); ap.add_argument('--min-files', type=int, default=1)
    a = ap.parse_args()
    gt_files = {r['file_hash']: r['period'] for r in csv.DictReader(open(os.path.join(a.gt_dir, 'gt_files.csv'), encoding='utf-8'))}
    gt, name_files = defaultdict(dict), defaultdict(set)
    for r in csv.DictReader(open(os.path.join(a.gt_dir, 'gt_functions.csv'), encoding='utf-8')):
        role = r['role']
        if role == 'other' and EXTRA_MALWARE_NAMES.search(r['name']):
            role = 'payload'
        gt[r['file_hash']][int(r['addr'])] = (r['name'], role)
        if role == 'other':
            name_files[r['name']].add(r['file_hash'])
    lib_names = {n for n, s in name_files.items() if len(s) / max(1, len(gt)) >= 0.10 and n != 'main'}
    lib, mal, example = Counter(), set(), {}
    with gzip.open(os.path.join(a.cache, 'function_hashes.csv.gz'), 'rt', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            h = r['file_hash']
            if r['period'] not in a.periods or gt_files.get(h) not in a.periods:
                continue
            g = gt.get(h, {}).get(int(r['addr']))
            if not g:
                continue
            n, role = g
            if role in ('payload', 'helper'):
                mal.add(r['h_op'])
            elif n in lib_names:
                lib[r['h_op']] += 1
                example.setdefault(r['h_op'], n)
    keep = {hh: c for hh, c in lib.items() if hh not in mal and c >= a.min_files}
    os.makedirs(a.out, exist_ok=True)
    out = os.path.join(a.out, 'library_functions_%s.txt' % '_'.join(a.periods))
    with open(out, 'w', encoding='utf-8') as f:
        f.write('# Library function hash database from the %s ground truth: %d hashes (%d hashes shared with malware functions '
                'removed). Hash = md5(arch#ops)[:16] as in 08_hash_functions.py\n'
                % ('+'.join(a.periods), len(keep), len([h for h in lib if h in mal])))
        for hh, c in sorted(keep.items(), key=lambda t: -t[1]):
            f.write('%s\t%d\t%s\n' % (hh, c, example[hh]))
    print('written', out, '|', len(keep), 'hashes')


if __name__ == '__main__':
    main()
