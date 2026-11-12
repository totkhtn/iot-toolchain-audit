# -*- coding: utf-8 -*-
"""08_hash_functions.py: step 3 (feasibility), identification of library functions in stripped binaries by
WHOLE-FUNCTION hashing (FLIRT-like).

Phase 'hash'   : read the JSON files and compute two hashes per function (within one ISA):
                   h_op  = hash of the opcode sequences (ops_seq) of all blocks in address order         -> strict match
                   h_sem = hash of the semantic class sequences (sem_seq) of all blocks in address order -> looser match
                 The per-file cache is resumable and limited to --time-limit seconds per call.
                 Files: every unstripped malware file with ground truth plus a random sample of --sample files per
                 (period, label) among the remaining files.
Phase 'analyze' (reads the cache only, no JSON):
  (1) Accuracy of library identification on UNSTRIPPED files (the CFG is computed on the stripped copy anyway, so the
      conditions are realistic): the ground-truth files are split 80/20 by hash (fixed seed); the database holds the
      hashes of 'library' / 'malware' functions of the 80% part; prediction on the 20% part: a function is library if
      its hash is in the library database and NOT in the malware database. Precision/recall per ground-truth role,
      broken down by function size (number of instructions).
  (2) Coverage on STRIPPED and benign files: % of functions / % of instructions matching the library database (built
      from ALL ground-truth files).
  (3) Expected effect on the evidence: % of the s_topk score (stage A cache) inside functions matching the database.

Usage:
  python 08_hash_functions.py hash --json-dir <feature_json_root> --gt-dir workdir/gt \
         --inventory workdir/inventory_2020.csv workdir/inventory_2024.csv --cache workdir/function_hashes --sample 1500 --time-limit 160
  python 08_hash_functions.py analyze --gt-dir workdir/gt --cache workdir/function_hashes --audit-cache workdir/A_cache --out workdir/b3
"""
import argparse, csv, glob, gzip, hashlib, json, os, random, re, sys, time
from collections import Counter, defaultdict

SEM_DROP = {'nop'}
EXTRA_MALWARE_NAMES = re.compile(r'flood|attack|scanner|killer|watchdog|vse|deobf|random_string|^astd$|^add_strings$|'
                                 r'^add_entry$|^rand_alpha_str$|^rand_int$|^rand_next_range$|^getRandom|^makeRandom|huawei|'
                                 r'exploit|botkill|^csum$|^trim$|^itoa$|cnc|^do_clone$', re.I)
BINS = [(1, 4, '<5 insns'), (5, 19, '5–19'), (20, 99, '20–99'), (100, 10 ** 9, '>=100')]
MAIN_SUBDIR = 'tap_chinh'   # sub-folder of the main sample set in the extractor output (fixed by the extractor)


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)


def hash_from_name(p):
    m = re.match(r'[0-9a-fA-F]{64}', os.path.basename(p))
    return m.group(0).lower() if m else os.path.basename(p).split('__')[0]


def read_json(p):
    with (gzip.open(p, 'rt', encoding='utf-8', errors='ignore') if p.endswith('.gz') else open(p, encoding='utf-8')) as f:
        return json.load(f)


def hash_phase(a):
    gt_files = {r['file_hash']: r for r in csv.DictReader(open(os.path.join(a.gt_dir, 'gt_files.csv'), encoding='utf-8'))}
    inv = []
    for p in a.inventory:
        inv += list(csv.DictReader(open(p, encoding='utf-8')))
    js = {}
    for p in glob.glob(os.path.join(a.json_dir, '*', MAIN_SUBDIR, '**', '*.json*'), recursive=True):
        js[(os.path.relpath(p, a.json_dir).split(os.sep)[0], hash_from_name(p))] = p
    rng = random.Random(2026)
    sel = [(r['period'], r['file_hash'], 'gt') for r in inv if r['file_hash'] in gt_files]
    for per in ('2020', '2024'):
        for lab, grp in (('1', 'malware_stripped'), ('0', 'benign')):
            ds = [r for r in inv if r['period'] == per and r['label'] == lab and r['file_hash'] not in gt_files
                  and (lab == '0' or r['is_stripped'] == '1')]
            rng.shuffle(ds)
            sel += [(per, r['file_hash'], grp) for r in ds[:a.sample]]
    meta = {(r['period'], r['file_hash']): r for r in inv}
    os.makedirs(a.cache, exist_ok=True)
    f_fn, f_file = os.path.join(a.cache, 'function_hashes.csv.gz'), os.path.join(a.cache, 'hashed_files.csv')
    done = set()
    if os.path.exists(f_file):
        done = {(r['period'], r['file_hash']) for r in csv.DictReader(open(f_file, encoding='utf-8'))}
    todo = [c for c in sel if (c[0], c[1]) not in done and (c[0], c[1]) in js]
    log('%d files to hash (%d done)' % (len(todo), len(done)))
    t0, n = time.time(), 0
    new_file = not done
    with gzip.open(f_fn, 'at', encoding='utf-8', newline='') as fh, open(f_file, 'a', newline='', encoding='utf-8') as ft:
        wh, wt = csv.writer(fh), csv.writer(ft)
        if new_file:
            wh.writerow(['period', 'file_hash', 'addr', 'ninsn', 'nblocks', 'h_op', 'h_sem'])
            wt.writerow(['period', 'file_hash', 'group', 'label', 'arch', 'is_static', 'n_functions'])
        for per, h, grp in todo:
            d = read_json(js[(per, h)])
            arch = d.get('arch') or ''
            F = defaultdict(list)
            for nd in (d.get('cfg_graph') or {}).get('nodes') or []:
                F[int(nd['func'], 16)].append(nd)
            for fa, nds in F.items():
                nds.sort(key=lambda x: x.get('addr', 0))
                ops = '/'.join(','.join(nd.get('ops_seq') or []) for nd in nds)
                sem = '/'.join(','.join(x for x in (nd.get('sem_seq') or []) if x not in SEM_DROP) for nd in nds)
                ni = sum(int(nd.get('ninsn', 0) or 0) for nd in nds)
                wh.writerow([per, h, fa, ni, len(nds), hashlib.md5((arch + '#' + ops).encode()).hexdigest()[:16],
                             hashlib.md5((arch + '#' + sem).encode()).hexdigest()[:16]])
            m = meta.get((per, h), {})
            wt.writerow([per, h, grp, m.get('label'), arch, m.get('is_static'), len(F)])   # written AFTER the functions
            n += 1
            if n % 200 == 0:
                fh.flush(); ft.flush(); log('%d files, %.0fs' % (n, time.time() - t0))
            if time.time() - t0 > a.time_limit:
                log('STOPPED_AT_TIME_LIMIT after %d files' % n); return
    log('DONE hashing (%d new files)' % n)


def analyze(a):
    files = {(r['period'], r['file_hash']): r for r in csv.DictReader(open(os.path.join(a.cache, 'hashed_files.csv'), encoding='utf-8'))}
    # ---- ground-truth roles (as in 05: 'library' = 'other' name present in >= 10% of ground-truth files, except main) ----
    name_files, gt = defaultdict(set), defaultdict(dict)
    for r in csv.DictReader(open(os.path.join(a.gt_dir, 'gt_functions.csv'), encoding='utf-8')):
        role = r['role']
        if role == 'other' and EXTRA_MALWARE_NAMES.search(r['name']):
            role = 'payload'
        gt[r['file_hash']][int(r['addr'])] = (r['name'], role)
        if role == 'other':
            name_files[r['name']].add(r['file_hash'])
    n_gt = len(gt)
    lib_names = {n for n, s in name_files.items() if len(s) / n_gt >= 0.10 and n != 'main'}

    def role_of(h, fa):
        if fa not in gt.get(h, {}):
            return 'no_symbol'
        n, role = gt[h][fa]
        return 'malware' if role in ('payload', 'helper') else ('library' if n in lib_names else 'other')

    rows = defaultdict(list)          # (period, hash) -> [(addr, ninsn, nblocks, h_op, h_sem)]
    with gzip.open(os.path.join(a.cache, 'function_hashes.csv.gz'), 'rt', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            k = (r['period'], r['file_hash'])
            if k in files:
                rows[k].append((int(r['addr']), int(r['ninsn']), int(r['nblocks']), r['h_op'], r['h_sem']))
    gt_keys = sorted(k for k in rows if files[k]['group'] == 'gt')
    rng = random.Random(10)
    rng.shuffle(gt_keys)
    cut = int(0.8 * len(gt_keys))
    db_keys, ev_keys = gt_keys[:cut], gt_keys[cut:]

    def build_db(keys, col):
        lib, mal = Counter(), Counter()
        for k in keys:
            for fa, ni, nb, hop, hsem in rows[k]:
                v = role_of(k[1], fa)
                hh = hop if col == 'op' else hsem
                if v == 'library':
                    lib[hh] += 1
                elif v == 'malware':
                    mal[hh] += 1
        return lib, mal

    def bin_of(ni):
        for lo, hi, t in BINS:
            if lo <= ni <= hi:
                return t
        return BINS[0][2]

    L = ['# Step 3: library function identification by whole-function hashing (FLIRT-like)', '',
         'Ground-truth files: %d (database %d / evaluation %d, split by file). "Library" names: %d.'
         % (len(gt_keys), len(db_keys), len(ev_keys), len(lib_names)), '']
    out_rows = []
    splits = [('random_80_20', db_keys, ev_keys),
              ('temporal_2020_to_2024', [k for k in gt_keys if k[0] == '2020'], [k for k in gt_keys if k[0] == '2024'])]
    for (split_name, db_k, ev_k), col in [(c, b) for c in splits for b in ('op', 'sem')]:
        lib, mal = build_db(db_k, col)
        L += ['## (1) Accuracy: split `%s` (database %d files, evaluation %d files), hash `h_%s`' % (split_name, len(db_k), len(ev_k), col), '',
              '| Function size | n library (GT) | Library recall | n malware (GT) | Malware identified as library | Precision (library vs malware) |',
              '|---|---|---|---|---|---|']
        stat = defaultdict(Counter)
        for k in ev_k:
            for fa, ni, nb, hop, hsem in rows[k]:
                v = role_of(k[1], fa)
                if v not in ('library', 'malware'):
                    continue
                hh = hop if col == 'op' else hsem
                pred = hh in lib and hh not in mal
                b = bin_of(ni)
                for bb in (b, 'All'):
                    stat[bb][(v, pred)] += 1
        for b in [t for _, _, t in BINS] + ['All']:
            s = stat[b]
            nl, nm = s[('library', True)] + s[('library', False)], s[('malware', True)] + s[('malware', False)]
            tp, fp = s[('library', True)], s[('malware', True)]
            r = dict(split=split_name, hash=col, size=b, n_library=nl, recall_library=tp / nl if nl else float('nan'), n_malware=nm,
                     malware_as_library=fp / nm if nm else float('nan'), precision=tp / (tp + fp) if tp + fp else float('nan'))
            out_rows.append(r)
            L.append('| %s | %d | %.3f | %d | %.3f | %.4f |' % (b, nl, r['recall_library'], nm, r['malware_as_library'], r['precision']))
        L.append('')
    # ---- (2) Coverage: database built from ALL ground-truth files ----
    L += ['## (2) Coverage on files without ground truth (database built from all ground-truth files)', '',
          '| Hash | Period | Group | n files | % functions matching the library DB (median) | % instructions in matching functions (median) |',
          '|---|---|---|---|---|---|']
    cov_rows = []
    lib_match = {}
    for col in ('op', 'sem'):
        lib, mal = build_db(gt_keys, col)
        lib_match[col] = {hh for hh in lib if hh not in mal}
        for per in ('2020', '2024'):
            for grp in ('gt', 'malware_stripped', 'benign'):
                ks = [k for k in rows if k[0] == per and files[k]['group'] == grp]
                if not ks:
                    continue
                fr_f, fr_i = [], []
                for k in ks:
                    R = rows[k]
                    m = [(hop if col == 'op' else hsem) in lib_match[col] for _, _, _, hop, hsem in R]
                    tot_i = sum(ni for _, ni, *_ in R) or 1
                    fr_f.append(sum(m) / max(1, len(R)))
                    fr_i.append(sum(ni for (fa, ni, *_), mm in zip(R, m) if mm) / tot_i)
                    cov_rows.append(dict(hash=col, period=per, group=grp, file_hash=k[1], arch=files[k]['arch'],
                                         is_static=files[k]['is_static'], frac_functions=fr_f[-1], frac_instructions=fr_i[-1]))
                med = lambda v: sorted(v)[len(v) // 2]
                L.append('| %s | %s | %s | %d | %.3f | %.3f |' % (col, per, grp, len(ks), med(fr_f), med(fr_i)))
    L.append('')
    # ---- (3) Effect on the evidence (stage A cache) ----
    if a.audit_cache and os.path.isdir(a.audit_cache):
        L += ['## (3) Evidence `s_topk` inside functions matching the library DB (ground-truth files, hashes from the full database; optimistic)', '',
              '| Model | Hash | Period | % evidence in matching functions |', '|---|---|---|---|']
        idx = {}
        for k, R in rows.items():
            for fa, ni, nb, hop, hsem in R:
                idx[(k[0], k[1], fa)] = (hop, hsem)
        for p in sorted(glob.glob(os.path.join(a.audit_cache, 'cache_functions_*.csv'))):
            acc = defaultdict(lambda: [0.0, 0.0])
            with open(p, encoding='utf-8') as f:
                rd = csv.DictReader(f)
                models = [c[len('s_topk_'):] for c in rd.fieldnames if c.startswith('s_topk_')]
                for r in rd:
                    hh = idx.get((r['period'], r['file_hash'], int(r['addr'])))
                    if hh is None:
                        continue
                    for m in models:
                        v = float(r['s_topk_' + m])
                        for ci, col in enumerate(('op', 'sem')):
                            acc[(m, col, r['period'])][0] += v
                            if hh[ci] in lib_match[col]:
                                acc[(m, col, r['period'])][1] += v
            for (m, col, per), (t, k_) in sorted(acc.items()):
                L.append('| %s | %s | %s | %.3f |' % (m, col, per, k_ / t if t else float('nan')))
        L.append('')
    os.makedirs(a.out, exist_ok=True)
    for name, rr in (('B3_accuracy.csv', out_rows), ('B3_coverage_per_file.csv', cov_rows)):
        with open(os.path.join(a.out, name), 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(rr[0].keys())); w.writeheader(); w.writerows(rr)
    open(os.path.join(a.out, 'SUMMARY_B3.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    print('\n'.join(L))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('phase', choices=['hash', 'analyze'])
    ap.add_argument('--json-dir'); ap.add_argument('--gt-dir', required=True)
    ap.add_argument('--inventory', nargs='*', default=[]); ap.add_argument('--cache', required=True)
    ap.add_argument('--audit-cache', help='function-level cache of stage A (02_localize_functions.py --compute-cache)')
    ap.add_argument('--out')
    ap.add_argument('--sample', type=int, default=1500); ap.add_argument('--time-limit', type=float, default=1e18)
    a = ap.parse_args()
    hash_phase(a) if a.phase == 'hash' else analyze(a)


if __name__ == '__main__':
    main()
