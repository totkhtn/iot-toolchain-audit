# -*- coding: utf-8 -*-
"""05_build_signature_roles.py: FLIRT-like database of "library signatures" for the symbol-table mask (mask b).

For every unstripped malware file with ground truth (workdir/gt), read the JSON, compute the semantic signature of
every block (identical to sem_key of the training script hin_static_v15) and assign the role of the FUNCTION that
contains the block according to the .symtab:
  library : function with role 'other' whose name occurs in >= --min-name-frac of the ground-truth files
            (shared libc/uClibc/libgcc/crt code), except 'main'
  malware : 'payload' or 'helper' function (written by the malware author)
  other   : everything else (rare 'other' functions, possibly malware functions missed by the name rules; not used
            for masking)
Output: signature_roles.csv.gz (file_hash, period, sig, n_library, n_malware, n_other), i.e. number of BLOCKS per role.
The masking decision (on the TRAINING set) is taken in hin_static_v15_libsym.py, not here, so no test label leaks.

Usage:  python 05_build_signature_roles.py --json-dir <feature_json_root> --gt-dir workdir/gt --out workdir/libsym [--time-limit 160]
"""
import argparse, csv, glob, gzip, json, os, re, sys, time
from collections import Counter, defaultdict

SEM_DROP = {'nop'}
# Supplement to NAME_RULES of 01_extract_symtab_gt.py: malware function names missed by the rules, found while
# reviewing library_names.txt
EXTRA_MALWARE_NAMES = re.compile(r'flood|attack|scanner|killer|watchdog|vse|deobf|random_string|^astd$|^add_strings$|'
                                 r'^add_entry$|^rand_alpha_str$|^rand_int$|^rand_next_range$|^getRandom|^makeRandom|huawei|'
                                 r'exploit|botkill|^csum$|^trim$|^itoa$|cnc|^do_clone$', re.I)
MIN_INSNS = 3
MAIN_SUBDIR = 'tap_chinh'   # sub-folder of the main sample set in the extractor output (fixed by the extractor)


def sem_key(sem):
    s = [x for x in sem if x not in SEM_DROP]
    return 'S:' + '|'.join(s) if len(s) >= MIN_INSNS else None


def hash_from_name(p):
    b = os.path.basename(p)
    m = re.match(r'[0-9a-fA-F]{64}', b)
    return m.group(0).lower() if m else b.split('__')[0].split('_')[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json-dir', required=True)
    ap.add_argument('--gt-dir', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--min-name-frac', type=float, default=0.10)
    ap.add_argument('--time-limit', type=float, default=1e18)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    files = {r['file_hash']: r for r in csv.DictReader(open(os.path.join(a.gt_dir, 'gt_files.csv'), encoding='utf-8'))}
    funcs = defaultdict(dict)
    name_files = defaultdict(set)
    for r in csv.DictReader(open(os.path.join(a.gt_dir, 'gt_functions.csv'), encoding='utf-8')):
        role = 'payload' if (r['role'] == 'other' and EXTRA_MALWARE_NAMES.search(r['name'])) else r['role']
        funcs[r['file_hash']][int(r['addr'])] = (r['name'], role)
        if role == 'other':
            name_files[r['name']].add(r['file_hash'])
    n_files = max(1, len(files))
    library_names = {n for n, s in name_files.items() if len(s) / n_files >= a.min_name_frac and n != 'main'}

    def sig_role(name, role):
        if role in ('payload', 'helper'):
            return 'malware'
        return 'library' if name in library_names else 'other'

    with open(os.path.join(a.out, 'library_names.txt'), 'w', encoding='utf-8') as f:
        f.write('# names of functions with role "other" present in >= %.0f%% of the ground-truth files -> treated as library/runtime\n'
                % (100 * a.min_name_frac))
        for n in sorted(library_names):
            f.write('%s\t%d\n' % (n, len(name_files[n])))

    js = {}
    for p in glob.glob(os.path.join(a.json_dir, '*', MAIN_SUBDIR, '**', '*.json*'), recursive=True):
        js[hash_from_name(p)] = (os.path.relpath(p, a.json_dir).split(os.sep)[0], p)
    out = os.path.join(a.out, 'signature_roles.csv.gz')
    done = set()
    if os.path.exists(out):
        try:
            with gzip.open(out, 'rt', encoding='utf-8') as f:
                done = {r['file_hash'] for r in csv.DictReader(f)}
        except (EOFError, OSError):       # the previous run was interrupted -> start again from scratch to be safe
            done = set()
            os.replace(out, out + '.broken')
    todo = sorted(h for h in files if h in js and h not in done)
    print('library names: %d | files left: %d (%d done)' % (len(library_names), len(todo), len(done)), flush=True)
    t0, n = time.time(), 0
    with gzip.open(out, 'at', encoding='utf-8', newline='') as f:
        w = csv.writer(f)
        if not done:
            w.writerow(['file_hash', 'period', 'sig', 'n_library', 'n_malware', 'n_other'])
        for h in todo:
            per, p = js[h]
            with gzip.open(p, 'rt', encoding='utf-8', errors='ignore') if p.endswith('.gz') else open(p, encoding='utf-8') as fj:
                d = json.load(fj)
            gt = funcs.get(h, {})
            c = defaultdict(Counter)
            for nd in (d.get('cfg_graph') or {}).get('nodes') or []:
                tf = nd.get('opcodes_tf') or {}
                if sum(int(v) for v in tf.values()) < MIN_INSNS:
                    continue
                k = sem_key(nd.get('sem_seq') or [])
                if not k:
                    continue
                fa = int(nd['func'], 16)
                c[k][sig_role(*gt[fa]) if fa in gt else 'other'] += 1
            for k, cc in c.items():
                w.writerow([h, per, k, cc['library'], cc['malware'], cc['other']])
            n += 1
            if time.time() - t0 > a.time_limit:
                print('STOPPED_AT_TIME_LIMIT after %d files' % n, flush=True)
                return
    print('DONE %d files, %.0fs' % (n, time.time() - t0), flush=True)


if __name__ == '__main__':
    main()
