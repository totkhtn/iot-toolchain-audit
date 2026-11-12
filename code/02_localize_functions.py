# -*- coding: utf-8 -*-
"""02_localize_functions.py: audit stage A, localization of malicious functions from the evidence scores of MHEN-S
(no GPU and no retraining needed).

Idea (adapted from XAIDroid, JISA 2026): the model learns file-level labels only; node scores are aggregated to the
function level and compared with function-level ground truth. Two differences from XAIDroid:
  1. MHEN-S has an ADDITIVE evidence term: evidence(f) = sum_t softplus(w_t) * TopK_{e in N_t(f)} s_e. The
     contribution of every semblock signature to the evidence is therefore EXACT (not a post hoc explanation such as
     attention). The 'topk' score below distributes exactly this contribution over the blocks and sums it per function.
  2. The ground truth is derived automatically from the .symtab of the original files (01_extract_symtab_gt.py)
     instead of 135 manually labelled samples.

Questions answered at this stage:
  Q1  Localization:   do function scores rank 'payload' functions at the top? (AUC, AP, Hit@k, analyst effort)
                      compared with baselines.
  Q1b Shortcut:       which share of the evidence falls on library functions ('other') instead of 'payload'?
  Q1c Vocabulary:     which share of payload functions has no signature in the vocabulary (score = 0, like
                      'unseen APIs' in XAIDroid)?
  Q3  Cross-ISA:      do payload functions with the same name receive similar ranks on different ISAs? (compared
                      with the function size baseline)
  Q4a Drift (part that needs no predictions): vocabulary coverage and evidence mass of 2020 versus 2024 files.
Q2 (top-k deletion fidelity) and Q4b (drift score as error predictor) need the model or its predictions and belong to
stage B (03_*, run on Kaggle; not part of this repository).

Modes:
  --build-file-list : select unstripped malware from inventory_*.csv and read file_path from the JSON
                      -> original_files.csv (input of 01_extract_symtab_gt.py on the Linux machine).
  --compute-cache   : compute function-level scores for the files with ground truth and write them to --cache.
  --q4a-only        : Q4a on all files of one period (no ground truth needed).
  (default)         : run Q1/Q1b/Q1c/Q3/Q4a.

Examples (Windows/VM or Kaggle CPU):
  python 02_localize_functions.py --build-file-list --inventory workdir/inventory_2020.csv workdir/inventory_2024.csv \
         --json-dir <feature_json_root> --out workdir
  python 02_localize_functions.py --json-dir <feature_json_root> --gt-dir workdir/gt \
         --scores <reports>/mhenS_entity_scores_semblock_grouped-2024_seed10.csv \
         --inventory workdir/inventory_2020.csv workdir/inventory_2024.csv \
         --model-name mhenS_seed10 --out workdir/A_seed10
"""
import argparse, csv, glob, gzip, json, math, os, random, re, sys, time
from collections import defaultdict

SEM_DROP = {'nop'}
MIN_INSNS = 3            # = CFG['BLOCK_MIN_INSNS'] of the training script (hin_static_v15)
TOPK = 8                 # = CFG['MHEN_TOPK']
ISAS = ['ARM', 'MIPS', 'PowerPC', 'x86', 'x64']
_ARCH = {'EM_ARM': 'ARM', 'EM_MIPS': 'MIPS', 'EM_PPC': 'PowerPC', 'EM_386': 'x86', 'EM_X86_64': 'x64'}
MAIN_SUBDIR = 'tap_chinh'   # sub-folder of the main sample set in the extractor output (fixed by the extractor)


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)


def read_json(p):
    op = gzip.open if p.endswith('.gz') else open
    with op(p, 'rt', encoding='utf-8', errors='ignore') as f:
        return json.load(f)


def sem_key(sem):
    s = [x for x in sem if x not in SEM_DROP]
    return 'S:' + '|'.join(s) if len(s) >= MIN_INSNS else None


def hash_from_name(p):
    """File name <sha256>[.elf]__<8 characters>_static.json.gz -> leading 64 hex digits (as in 00_inventory.py)."""
    b = os.path.basename(p)
    m = re.match(r'[0-9a-fA-F]{64}', b)
    return m.group(0).lower() if m else b.split('__')[0].split('_')[0]


def find_json(json_dir):
    m = {}
    for p in glob.glob(os.path.join(json_dir, '*', MAIN_SUBDIR, '**', '*.json*'), recursive=True):
        per = os.path.relpath(p, json_dir).split(os.sep)[0]
        m[(per, hash_from_name(p))] = p
    return m


def read_inventory(paths):
    rows = []
    for p in paths:
        with open(p, newline='', encoding='utf-8') as f:
            rows += list(csv.DictReader(f))
    return rows


# ------------------------------------------------------------------ mode: build the list of original files
def build_file_list(a):
    inv = read_inventory(a.inventory)
    js = find_json(a.json_dir)
    sel = [r for r in inv if r.get('label') == '1' and r.get('is_stripped') == '0' and r.get('status') == 'ok']
    log('unstripped malware files:', len(sel))
    os.makedirs(a.out, exist_ok=True)
    out = os.path.join(a.out, 'original_files.csv')
    with open(out, 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['file_hash', 'file_path', 'period', 'arch'])
        for r in sel:
            p = js.get((r['period'], r['file_hash']))
            if p:
                w.writerow([r['file_hash'], read_json(p).get('file_path'), r['period'], r['arch']])
    log('written', out)


# ------------------------------------------------------------------ entity scores and ground truth
def read_scores(path):
    s = {}
    with open(path, newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            if r.get('entity_type', 'semblock') == 'semblock':
                s[r['entity']] = float(r['malice_score'])
    log('semblock scores:', len(s), 'entities from', os.path.basename(path))
    return s


# Supplement to NAME_RULES of 01_extract_symtab_gt.py: malware function names missed by the rules
# (identical to EXTRA_MALWARE_NAMES in 05_build_signature_roles.py)
EXTRA_MALWARE_NAMES = re.compile(r'flood|attack|scanner|killer|watchdog|vse|deobf|random_string|^astd$|^add_strings$|'
                                 r'^add_entry$|^rand_alpha_str$|^rand_int$|^rand_next_range$|^getRandom|^makeRandom|huawei|'
                                 r'exploit|botkill|^csum$|^trim$|^itoa$|cnc|^do_clone$', re.I)


def read_gt(gt_dir):
    funcs = defaultdict(dict)
    with open(os.path.join(gt_dir, 'gt_functions.csv'), newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            role = r['role']
            if role == 'other' and EXTRA_MALWARE_NAMES.search(r['name']):
                role = 'payload'
            funcs[r['file_hash']][int(r['addr'])] = (r['name'], role)
    files = {}
    with open(os.path.join(gt_dir, 'gt_files.csv'), newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            files[r['file_hash']] = r
    return funcs, files


# ------------------------------------------------------------------ function-level scores of one file
LIBFN = None      # set of library function hashes (--libfn): matching functions are REMOVED from the evaluation
                  # (as in the library-aware HIN)


def library_functions_of_file(d):
    """Addresses (hex strings) of the functions whose hash md5(arch#ops)[:16] is in LIBFN; identical to the
    training script hin_static_v15_libaware.py."""
    if not LIBFN:
        return set()
    import hashlib
    arch = str(d.get('arch') or '')
    G = defaultdict(list)
    for nd in (d.get('cfg_graph') or {}).get('nodes') or []:
        G[nd.get('func')].append(nd)
    out = set()
    for fa, nds in G.items():
        ops = '/'.join(','.join(nd.get('ops_seq') or []) for nd in sorted(nds, key=lambda x: x.get('addr', 0)))
        if hashlib.md5((arch + '#' + ops).encode()).hexdigest()[:16] in LIBFN:
            out.add(fa)
    return out


def functions_of_file(d, scores):
    """Return {function_addr: dict(n_blocks, ninsn, n_sys, s_sum, s_max, keys)} and file-level information."""
    F = defaultdict(lambda: dict(n_blocks=0, ninsn=0, n_sys=0, s_sum=0.0, s_max=0.0, keys=defaultdict(int)))
    file_sigs = set()
    n_sem = n_vocab = 0
    drop = library_functions_of_file(d)
    for nd in (d.get('cfg_graph') or {}).get('nodes') or []:
        if nd.get('func') in drop:
            continue
        fa = int(nd['func'], 16)
        g = F[fa]
        tf = nd.get('opcodes_tf') or {}
        ni = sum(int(v) for v in tf.values())
        g['n_blocks'] += 1; g['ninsn'] += ni
        g['n_sys'] += int((nd.get('sem_tf') or {}).get('syscall', 0) > 0)
        if ni < MIN_INSNS:
            continue
        k = sem_key(nd.get('sem_seq') or [])
        if not k:
            continue
        n_sem += 1
        file_sigs.add(k)
        if k in scores:
            n_vocab += 1
            v = scores[k]
            g['s_sum'] += v; g['s_max'] = max(g['s_max'], v); g['keys'][k] += 1
    # --- EXACT contribution to the MHEN evidence: the top-K distinct signatures of the file ---
    top = sorted((k for k in file_sigs if k in scores), key=lambda k: -scores[k])[:TOPK]
    ev = sum(scores[k] for k in top)
    count = defaultdict(int)
    for g in F.values():
        for k, c in g['keys'].items():
            count[k] += c
    for g in F.values():
        g['s_topk'] = sum(scores[k] * c / count[k] for k, c in g['keys'].items() if k in top)
    info = dict(n_sem=n_sem, n_sig=len(file_sigs), n_sig_vocab=sum(k in scores for k in file_sigs),
                frac_block_vocab=n_vocab / n_sem if n_sem else 0.0, evidence_topk=ev)
    return F, info


# ------------------------------------------------------------------ ranking metrics
def auc(pos, neg):
    if not pos or not neg:
        return float('nan')
    allv = sorted([(v, 1) for v in pos] + [(v, 0) for v in neg])
    r, i, sp = 0.0, 0, 0.0
    while i < len(allv):                      # average rank for ties
        j = i
        while j < len(allv) and allv[j][0] == allv[i][0]:
            j += 1
        rk = (i + j + 1) / 2.0
        sp += rk * sum(1 for t in allv[i:j] if t[1] == 1)
        i = j
    n1, n0 = len(pos), len(neg)
    return (sp - n1 * (n1 + 1) / 2.0) / (n1 * n0)


def ap(scores, labels):
    o = sorted(zip(scores, labels), key=lambda t: -t[0])
    tp, s, P = 0, 0.0, sum(labels)
    if not P:
        return float('nan')
    for i, (_, l) in enumerate(o, 1):
        if l:
            tp += 1; s += tp / i
    return s / P


def rank_scores(scores, rng):
    """Rank 1 = highest score; ties are broken at random (no method is favoured)."""
    idx = list(range(len(scores)))
    rng.shuffle(idx)
    idx.sort(key=lambda i: -scores[i])
    rank = [0] * len(scores)
    for r, i in enumerate(idx, 1):
        rank[i] = r
    return rank


def bootstrap(vals, B=2000, seed=0):
    """Mean and 95% bootstrap CI over FILES (numpy, vectorized)."""
    import numpy as np
    v = np.array([x for x in vals if x == x], dtype=float)
    if not len(v):
        return float('nan'), float('nan'), float('nan')
    rng = np.random.default_rng(seed)
    ms = v[rng.integers(0, len(v), size=(B, len(v)))].mean(1)
    return float(v.mean()), float(np.quantile(ms, 0.025)), float(np.quantile(ms, 0.975))


def spearman(x, y):
    n = len(x)
    if n < 3:
        return float('nan')
    def rk(a):
        o = sorted(range(n), key=lambda i: a[i]); r = [0.0] * n
        i = 0
        while i < n:
            j = i
            while j < n and a[o[j]] == a[o[i]]:
                j += 1
            for t in range(i, j):
                r[o[t]] = (i + j - 1) / 2.0
            i = j
        return r
    rx, ry = rk(x), rk(y)
    mx, my = sum(rx) / n, sum(ry) / n
    num = sum((a - mx) * (b - my) for a, b in zip(rx, ry))
    den = math.sqrt(sum((a - mx) ** 2 for a in rx) * sum((b - my) ** 2 for b in ry))
    return num / den if den else float('nan')


MODEL_SCORES = ['s_topk', 's_sum', 's_max']                   # scores derived from the model
BASELINES = ['b_ninsn', 'b_nblocks', 'b_nsys', 'b_random']    # baselines that do not use the model


# ------------------------------------------------------------------ mode: analysis
def analyze(a):
    rng = random.Random(a.seed)
    scores = read_scores(a.scores) if not a.cache else None
    if a.cache:
        a.q4_sample = 0                    # the full Q4a is run separately (--q4a-only)
    gt_funcs, gt_files = read_gt(a.gt_dir)
    inv = {(r['period'], r['file_hash']): r for r in read_inventory(a.inventory)} if a.inventory else {}
    js = find_json(a.json_dir) if a.json_dir else {}
    if not js and a.cache:   # (release) analysis from the function-level cache only, no JSON needed
        js = dict.fromkeys(read_cache(a.cache, a.cache_model))
    test_set = None
    if a.test_hashes:
        with open(a.test_hashes, encoding='utf-8') as f:
            test_set = {l.strip() for l in f if l.strip()}
    os.makedirs(a.out, exist_ok=True)

    file_rows, func_rows = [], []
    todo = [(per, h) for (per, h) in js if h in gt_files and int(gt_files[h].get('n_payload') or 0) > 0]
    if a.max_files:
        todo = todo[:a.max_files]
    log('files with payload ground truth:', len(todo))
    cache = read_cache(a.cache, a.cache_model) if a.cache else None
    n_skipped_unmatched = [0]
    for i, (per, h) in enumerate(sorted(todo)):
        if cache is not None:
            if (per, h) not in cache:
                continue
            F, info, arch0 = cache[(per, h)]
            d = {'arch': arch0}
        else:
            d = read_json(js[(per, h)])
            F, info = functions_of_file(d, scores)
        gt = gt_funcs.get(h, {})
        addrs = [fa for fa in F if fa in gt]                       # only functions matched to a symbol
        if not addrs:
            continue
        lab = [1 if gt[fa][1] == 'payload' else 0 for fa in addrs]
        roles = [gt[fa][1] for fa in addrs]
        cols = {k: [F[fa][k] for fa in addrs] for k in MODEL_SCORES}
        cols['b_ninsn'] = [F[fa]['ninsn'] for fa in addrs]
        cols['b_nblocks'] = [F[fa]['n_blocks'] for fa in addrs]
        cols['b_nsys'] = [F[fa]['n_sys'] for fa in addrs]
        cols['b_random'] = [rng.random() for _ in addrs]
        arch = _ARCH.get(d.get('arch'), d.get('arch'))
        row = dict(period=per, file_hash=h, arch=arch, family=gt_files[h].get('family'),
                   is_test=(h in test_set) if test_set is not None else '', n_functions=len(addrs), n_payload=sum(lab),
                   n_functions_r2=len(F), n_functions_symtab=len(gt), **info)
        tot = sum(cols['s_topk']) or 1.0
        for r_ in ('payload', 'helper', 'other'):
            row['ev_share_' + r_] = sum(c for c, v in zip(cols['s_topk'], roles) if v == r_) / tot if sum(cols['s_topk']) else float('nan')
        pay_idx = [j for j, l in enumerate(lab) if l]
        if not pay_idx:                # payload exists in .symtab but r2 found none of these functions
            n_skipped_unmatched[0] += 1
            continue
        row['payload_out_of_vocab'] = sum(1 for j in pay_idx if not F[addrs[j]]['keys']) / len(pay_idx)
        neg_idx = [j for j, v in enumerate(roles) if v == 'other']   # strict: payload vs library/other (helpers excluded)
        for k in MODEL_SCORES + BASELINES:
            sc = cols[k]
            row['auc_' + k] = auc([sc[j] for j in pay_idx], [sc[j] for j in neg_idx])
            row['ap_' + k] = ap(sc, lab)
            rk = rank_scores(sc, rng)
            best = min(rk[j] for j in pay_idx)
            row['hit1_' + k] = int(best <= 1); row['hit5_' + k] = int(best <= 5); row['hit10_' + k] = int(best <= 10)
            row['p10_' + k] = sum(1 for j in pay_idx if rk[j] <= 10) / min(10, len(addrs))
            row['effort_first_' + k] = best / len(addrs)                       # share of functions inspected up to the first payload
            half = sorted(rk[j] for j in pay_idx)[max(0, math.ceil(len(pay_idx) / 2) - 1)]
            row['effort_half_' + k] = half / len(addrs)                        # ... up to half of the payload functions
            if k in ('s_topk', 's_sum', 'b_ninsn'):
                for j, fa in enumerate(addrs):
                    if roles[j] == 'payload':
                        func_rows.append(dict(period=per, file_hash=h, arch=arch, name=gt[fa][0], score=k,
                                              pct_rank=(rk[j] - 1) / max(1, len(addrs) - 1), value=sc[j]))
        file_rows.append(row)
        if (i + 1) % 200 == 0:
            log('%d/%d' % (i + 1, len(todo)))

    if not file_rows:
        sys.exit('No file matches the ground truth.')
    log('skipped %d files: no payload function matches a function address found by r2' % n_skipped_unmatched[0])
    write_csv(os.path.join(a.out, 'A_per_file.csv'), file_rows)
    write_csv(os.path.join(a.out, 'A_payload_rank.csv'), func_rows)

    # ---- Q1/Q1b/Q1c summary per period x ISA ----
    summary = []
    def group(rows, name):
        for k in MODEL_SCORES + BASELINES:
            r = dict(group=name, n_files=len(rows), score=k)
            for m in ('auc', 'ap', 'hit1', 'hit5', 'hit10', 'p10', 'effort_first', 'effort_half'):
                mu, lo, hi = bootstrap([x[m + '_' + k] for x in rows])
                r[m] = mu; r[m + '_lo'] = lo; r[m + '_hi'] = hi
            summary.append(r)
    pers = sorted({r['period'] for r in file_rows})
    for per in pers:
        rr = [r for r in file_rows if r['period'] == per]
        group(rr, per)
        for isa in ISAS:
            sub = [r for r in rr if r['arch'] == isa]
            if len(sub) >= a.min_files:
                group(sub, '%s|%s' % (per, isa))
        if test_set is not None:
            group([r for r in rr if r['is_test']], per + '|test_only')
    write_csv(os.path.join(a.out, 'A_Q1_summary.csv'), summary)

    # ---- Q3: rank consistency across ISAs (payload functions with the same name) ----
    q3 = []
    for per in pers:
        for k in ('s_topk', 's_sum', 'b_ninsn'):
            m = defaultdict(list)
            for r in func_rows:
                if r['period'] == per and r['score'] == k:
                    m[(r['name'], r['arch'])].append(r['pct_rank'])
            mean = {key: sum(v) / len(v) for key, v in m.items() if len(v) >= a.min_files_per_name}
            for i1, A in enumerate(ISAS):
                for B in ISAS[i1 + 1:]:
                    names = sorted({n for (n, s) in mean if s == A} & {n for (n, s) in mean if s == B})
                    x = [mean[(n, A)] for n in names]; y = [mean[(n, B)] for n in names]
                    q3.append(dict(period=per, score=k, isa_a=A, isa_b=B, n_names=len(names), spearman=spearman(x, y),
                                   mean_abs_diff=sum(abs(p - q) for p, q in zip(x, y)) / len(x) if x else float('nan')))
    write_csv(os.path.join(a.out, 'A_Q3_cross_isa.csv'), q3)

    # ---- Q4a: vocabulary / evidence drift on ALL inventoried files (no ground truth needed) ----
    if a.q4_sample and inv:
        q4 = []
        for per in pers:
            for lab in ('0', '1'):
                ds = [key for key, r in inv.items() if key[0] == per and r.get('label') == lab and r.get('status') == 'ok']
                rng.shuffle(ds)
                for key in ds[:a.q4_sample]:
                    if key not in js:
                        continue
                    _, info = functions_of_file(read_json(js[key]), scores)
                    q4.append(dict(period=per, label=lab, file_hash=key[1], arch=inv[key].get('arch'), **info))
        write_csv(os.path.join(a.out, 'A_Q4a_vocab_drift.csv'), q4)

    write_summary(a, file_rows, summary, q3)
    log('DONE ->', a.out)


INFO_K = ('n_sem', 'n_sig', 'n_sig_vocab', 'frac_block_vocab', 'evidence_topk')


def compute_cache(a):
    """Read every JSON file with payload ground truth ONCE, compute function-level scores for several models and write
    them to a cache (resumable, limited to --time-limit seconds per call). analyze(--cache) then reads only the cache,
    which is fast and avoids reading 2,000 JSON files again."""
    names = a.score_names or ['m%d' % i for i in range(len(a.scores))]
    score_sets = [read_scores(p) for p in a.scores]
    _, gt_files = read_gt_files(a.gt_dir)
    js = find_json(a.json_dir)
    os.makedirs(a.cache, exist_ok=True)
    f_fn, f_file = (os.path.join(a.cache, 'cache_functions_%s.csv' % a.period),
                    os.path.join(a.cache, 'cache_files_%s.csv' % a.period))
    done = set()
    if os.path.exists(f_file):
        with open(f_file, newline='', encoding='utf-8') as f:
            done = {r['file_hash'] for r in csv.DictReader(f)}
    cols_fn = ['period', 'file_hash', 'addr', 'n_blocks', 'ninsn', 'n_sys'] + \
        ['%s_%s' % (k, t) for t in names for k in ('s_sum', 's_max', 's_topk', 'nk')]
    cols_file = ['period', 'file_hash', 'arch'] + ['%s_%s' % (k, t) for t in names for k in INFO_K]
    todo = sorted(k for k in js if k[0] == a.period and k[1] in gt_files and int(gt_files[k[1]].get('n_payload') or 0) > 0
                  and k[1] not in done)
    if a.test_hashes:                     # compute the cache only for test files (e.g. the held-out ISA in cross-ISA runs)
        with open(a.test_hashes, encoding='utf-8') as f:
            keep = {l.strip() for l in f if l.strip()}
        todo = [k for k in todo if k[1] in keep]
    log('cache %s: %d files left (%d done)' % (a.period, len(todo), len(done)))
    t0, n = time.time(), 0
    new_file = not done
    with open(f_fn, 'a', newline='', encoding='utf-8') as fh, open(f_file, 'a', newline='', encoding='utf-8') as ft:
        wh, wt = csv.DictWriter(fh, fieldnames=cols_fn), csv.DictWriter(ft, fieldnames=cols_file)
        if new_file:
            wh.writeheader(); wt.writeheader()
        for key in todo:
            d = read_json(js[key])
            res = [functions_of_file(d, sc) for sc in score_sets]
            F0 = res[0][0]
            for fa in F0:
                r = dict(period=key[0], file_hash=key[1], addr=fa, n_blocks=F0[fa]['n_blocks'], ninsn=F0[fa]['ninsn'],
                         n_sys=F0[fa]['n_sys'])
                for t, (F, _) in zip(names, res):
                    g = F[fa]
                    r.update({'s_sum_' + t: round(g['s_sum'], 7), 's_max_' + t: round(g['s_max'], 7),
                              's_topk_' + t: round(g['s_topk'], 7), 'nk_' + t: len(g['keys'])})
                wh.writerow(r)
            rt = dict(period=key[0], file_hash=key[1], arch=d.get('arch'))
            for t, (_, info) in zip(names, res):
                rt.update({'%s_%s' % (k, t): info[k] for k in INFO_K})
            wt.writerow(rt)                       # the file row is written AFTER its functions: a file row means complete
            n += 1
            if n % 100 == 0:
                fh.flush(); ft.flush(); log('%d files, %.0fs' % (n, time.time() - t0))
            if time.time() - t0 > a.time_limit:
                log('STOPPED_AT_TIME_LIMIT after %d files' % n); return
    log('DONE cache %s (%d new files)' % (a.period, n))


def read_gt_files(gt_dir):
    files = {}
    with open(os.path.join(gt_dir, 'gt_files.csv'), newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            files[r['file_hash']] = r
    return None, files


def read_cache(cache_dir, t):
    """-> {(period, hash): (F, info, arch)} for model t, restricted to files that have a row in cache_files (complete)."""
    out = {}
    for p in sorted(glob.glob(os.path.join(cache_dir, 'cache_files_*.csv'))):
        with open(p, newline='', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                info = {k: float(r['%s_%s' % (k, t)]) for k in INFO_K}
                out[(r['period'], r['file_hash'])] = ({}, info, r['arch'])
    for p in sorted(glob.glob(os.path.join(cache_dir, 'cache_functions_*.csv'))):
        with open(p, newline='', encoding='utf-8') as f:
            for r in csv.DictReader(f):
                key = (r['period'], r['file_hash'])
                if key not in out:
                    continue
                out[key][0][int(r['addr'])] = dict(
                    n_blocks=int(r['n_blocks']), ninsn=int(r['ninsn']), n_sys=int(r['n_sys']),
                    s_sum=float(r['s_sum_' + t]), s_max=float(r['s_max_' + t]), s_topk=float(r['s_topk_' + t]),
                    keys=int(r['nk_' + t]))
    log('cache of model %s: %d files' % (t, len(out)))
    return out


def q4a_only(a):
    """Q4a on ALL files of one period, without ground truth. A single pass over the JSON files serves several score
    files (--scores may list several files, model names from --score-names). Resumable, time limited (--time-limit)."""
    names = a.score_names or ['m%d' % i for i in range(len(a.scores))]
    score_sets = [read_scores(p) for p in a.scores]
    inv = {(r['period'], r['file_hash']): r for r in read_inventory(a.inventory)}
    js = find_json(a.json_dir)
    os.makedirs(a.out, exist_ok=True)
    out = os.path.join(a.out, 'A_Q4a_full_%s.csv' % a.period)
    done = set()
    if os.path.exists(out):
        with open(out, newline='', encoding='utf-8') as f:
            done = {r['file_hash'] for r in csv.DictReader(f)}
    cols = ['period', 'file_hash', 'label', 'arch', 'is_static', 'is_stripped', 'n_sem', 'n_sig']
    for t in names:
        cols += ['%s_%s' % (k, t) for k in ('n_sig_vocab', 'frac_block_vocab', 'evidence_topk')]
    todo = sorted(k for k in js if k[0] == a.period and k[1] not in done and k in inv)
    log('Q4a %s: %d files left (%d done)' % (a.period, len(todo), len(done)))
    t0, n = time.time(), 0
    with open(out, 'a', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols)
        if not done:
            w.writeheader()
        for key in todo:
            d = read_json(js[key]); r = inv[key]
            row = dict(period=key[0], file_hash=key[1], label=r.get('label'), arch=r.get('arch'),
                       is_static=r.get('is_static'), is_stripped=r.get('is_stripped'))
            for t, sc in zip(names, score_sets):
                _, info = functions_of_file(d, sc)
                row['n_sem'], row['n_sig'] = info['n_sem'], info['n_sig']
                for k in ('n_sig_vocab', 'frac_block_vocab', 'evidence_topk'):
                    row['%s_%s' % (k, t)] = round(info[k], 6) if isinstance(info[k], float) else info[k]
            w.writerow(row); n += 1
            if n % 500 == 0:
                f.flush(); log('%d files, %.0fs' % (n, time.time() - t0))
            if time.time() - t0 > a.time_limit:
                log('STOPPED_AT_TIME_LIMIT after %d files' % n); return
    log('DONE Q4a %s (%d new files)' % (a.period, n))


def write_csv(path, rows):
    if not rows:
        return
    keys = list(rows[0].keys())
    for r in rows[1:]:
        for k in r:
            if k not in keys:
                keys.append(k)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=keys); w.writeheader(); w.writerows(rows)


def write_summary(a, file_rows, summary, q3):
    L = ['# Audit stage A: function localization (%s)' % a.model_name, '',
         'Entity scores: `%s`' % a.scores, '',
         '| Group | Score | n files | AUC (payload vs other) | AP | Hit@5 | Effort to first payload |', '|---|---|---|---|---|---|---|']
    for r in summary:
        if '|' in r['group'] and not r['group'].endswith('test_only'):
            continue
        L.append('| %s | %s | %d | %.3f [%.3f–%.3f] | %.3f | %.3f | %.3f |' % (
            r['group'], r['score'], r['n_files'], r['auc'], r['auc_lo'], r['auc_hi'], r['ap'], r['hit5'], r['effort_first']))
    L += ['', '## Q1b–Q1c', '']
    groups_q1b = [(p_, [r for r in file_rows if r['period'] == p_]) for p_ in sorted({r['period'] for r in file_rows})]
    groups_q1b += [(p_ + '|test_only', [r for r in rr_ if r['is_test'] is True]) for p_, rr_ in list(groups_q1b)
                   if any(r['is_test'] is True for r in rr_)]
    for per, rr in groups_q1b:
        f = lambda k: sum(r[k] for r in rr if r[k] == r[k]) / max(1, sum(1 for r in rr if r[k] == r[k]))
        L.append('- %s: share of top-K evidence on payload %.3f | helper %.3f | other (library) %.3f; '
                 'payload functions without any in-vocabulary signature %.3f; in-vocabulary blocks %.3f' % (
                     per, f('ev_share_payload'), f('ev_share_helper'), f('ev_share_other'), f('payload_out_of_vocab'),
                     f('frac_block_vocab')))
    L += ['', '## Q3 (Spearman correlation of payload function ranks across ISAs)', '',
          '| Period | Score | ISA | n names | Spearman |', '|---|---|---|---|---|']
    for r in q3:
        if r['n_names'] >= 3:
            L.append('| %s | %s | %s–%s | %d | %.3f |' % (r['period'], r['score'], r['isa_a'], r['isa_b'], r['n_names'], r['spearman']))
    L += ['', 'Note: `b_ninsn` (function size) is the control baseline for Q3. Functions compiled from the same source '
          'have correlated sizes across ISAs, so MHEN is informative only if it exceeds this baseline.']
    with open(os.path.join(a.out, 'SUMMARY_A.md'), 'w', encoding='utf-8') as f:
        f.write('\n'.join(L) + '\n')


def main():
    ap_ = argparse.ArgumentParser()
    ap_.add_argument('--build-file-list', action='store_true',
                     help='write original_files.csv (unstripped malware) for 01_extract_symtab_gt.py')
    ap_.add_argument('--json-dir', default='', help='feature JSON directory; optional when --cache is given')
    ap_.add_argument('--inventory', nargs='*', default=[], help='inventory_*.csv files written by 00_inventory.py')
    ap_.add_argument('--gt-dir')
    ap_.add_argument('--scores', nargs='+', help='mhenS_entity_scores_semblock_*.csv (several files allowed with --q4a-only and --compute-cache)')
    ap_.add_argument('--q4a-only', action='store_true', help='run only Q4a on all files of one period (no ground truth needed)')
    ap_.add_argument('--compute-cache', action='store_true', help='compute function-level scores of the files with ground truth, write them to --cache')
    ap_.add_argument('--cache', help='folder of the function-level score cache (created with --compute-cache)')
    ap_.add_argument('--cache-model', help='model name in the cache used for the analysis (e.g. S, S_libboth, unfiltered, filtered)')
    ap_.add_argument('--score-names', nargs='*', help='short name of every --scores file (--q4a-only and --compute-cache)')
    ap_.add_argument('--period', default='2024')
    ap_.add_argument('--time-limit', type=float, default=1e18, help='time limit in seconds per call (the run can be resumed)')
    ap_.add_argument('--test-hashes', help='(optional) hashes of the test set of the model that produced --scores')
    ap_.add_argument('--model-name', default='mhenS')
    ap_.add_argument('--out', required=True)
    ap_.add_argument('--seed', type=int, default=10)
    ap_.add_argument('--min-files', type=int, default=20, help='minimum number of files to report an ISA group')
    ap_.add_argument('--min-files-per-name', type=int, default=3, help='minimum number of files per (function name, ISA) in Q3')
    ap_.add_argument('--q4-sample', type=int, default=1500, help='files sampled per (period, label) for Q4a; 0 = skip')
    ap_.add_argument('--max-files', type=int, default=0)
    ap_.add_argument('--libfn', help='library_functions_2020.txt: remove library functions (hash match) from scores and evaluation')
    a = ap_.parse_args()
    if a.libfn:
        global LIBFN
        LIBFN = {l.split('\t')[0].strip() for l in open(a.libfn, encoding='utf-8') if l.strip() and not l.startswith('#')}
        log('removing library functions: %d hashes from %s' % (len(LIBFN), a.libfn))
    if a.build_file_list:
        build_file_list(a)
    elif a.compute_cache:
        if not (a.scores and a.gt_dir and a.cache):
            sys.exit('--scores, --gt-dir and --cache are required')
        compute_cache(a)
    elif a.q4a_only:
        if not a.scores:
            sys.exit('--scores is required')
        q4a_only(a)
    else:
        if not (a.gt_dir and (a.scores or a.cache)):
            sys.exit('--gt-dir and (--scores or --cache with --cache-model) are required')
        a.scores = a.scores[0] if a.scores else 'cache:%s/%s' % (a.cache, a.cache_model)
        analyze(a)


if __name__ == '__main__':
    main()
