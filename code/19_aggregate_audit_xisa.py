# -*- coding: utf-8 -*-
"""19_aggregate_audit_xisa.py: aggregation of cross-ISA function localization
(<a-dir>/<ISA>/<setting>_grouped-ISA-<ISA>_seed<s>/).

Per held-out ISA and pooled over 5 ISAs x 10 seeds: evidence shares (payload/helper/library), AUC/AP/Hit@5 of
`s_topk`, function size and random baselines; paired Wilcoxon test of filtered_non_library versus
unfiltered_non_library (paired by seed; the pooled test uses the normal approximation).

Usage: python3 19_aggregate_audit_xisa.py --a-dir workdir/A_xisa --out workdir/A_xisa
"""
import argparse, csv, glob, itertools, math, os, re, statistics as st
from collections import defaultdict

SETTINGS = [('unfiltered_all_functions', 'unfiltered, all functions'),
            ('unfiltered_non_library', 'unfiltered, library removed'),
            ('filtered_non_library', 'library-aware, library removed')]


def wilcoxon(d):
    d = [x for x in d if abs(x) > 1e-12]; n = len(d)
    if n == 0:
        return 1.0
    a = sorted(range(n), key=lambda i: abs(d[i])); rk = [0.0] * n; i = 0
    while i < n:
        j = i
        while j < n and abs(d[a[j]]) == abs(d[a[i]]):
            j += 1
        for t in range(i, j):
            rk[a[t]] = (i + j + 1) / 2.0
        i = j
    w = sum(r for r, x in zip(rk, d) if x > 0); mu = sum(rk) / 2
    if n <= 16:
        return sum(1 for s in itertools.product((0, 1), repeat=n)
                   if abs(sum(r for r, b in zip(rk, s) if b) - mu) >= abs(w - mu) - 1e-9) / 2 ** n
    sd = math.sqrt(sum(r * r for r in rk) / 4)
    return math.erfc(abs(w - mu) / sd / math.sqrt(2)) if sd else 1.0


def read_run(d):
    rows = {r['score']: r for r in csv.DictReader(open(os.path.join(d, 'A_Q1_summary.csv'), encoding='utf-8'))
            if r['group'].endswith('test_only')}
    tt = [r for r in csv.DictReader(open(os.path.join(d, 'A_per_file.csv'), encoding='utf-8')) if r['is_test'] == 'True']
    sh = {v: st.mean(float(r['ev_share_' + v]) for r in tt if r['ev_share_' + v] not in ('', 'nan'))
          for v in ('payload', 'helper', 'other')}
    g = lambda k, m: float(rows[k][m])
    return dict(n=int(rows['s_topk']['n_files']), auc=g('s_topk', 'auc'), ap=g('s_topk', 'ap'), hit5=g('s_topk', 'hit5'),
                ap_size=g('b_ninsn', 'ap'), auc_size=g('b_ninsn', 'auc'), hit5_size=g('b_ninsn', 'hit5'),
                ap_rand=g('b_random', 'ap'), **sh)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--a-dir', required=True); ap.add_argument('--out', required=True)
    a = ap.parse_args()
    R = defaultdict(dict)                      # (setting, isa) -> {seed: dict}
    for d in glob.glob(os.path.join(a.a_dir, '*', '*_grouped-ISA-*_seed*')):
        m = re.match(r'(.+)_grouped-ISA-([A-Za-z0-9]+)_seed(\d+)$', os.path.basename(d))
        if m and os.path.exists(os.path.join(d, 'A_Q1_summary.csv')):
            R[(m.group(1), m.group(2))][m.group(3)] = read_run(d)
    isas = sorted({k[1] for k in R})
    f = lambda v: '%.3f±%.3f' % (st.mean(v), st.stdev(v) if len(v) > 1 else 0.0)
    L = ['# Cross-ISA function localization (held-out ISA as test set; GT v2; mean ± std over 10 seeds)', '']
    for isa in isas + ['POOLED']:
        L += ['## %s' % isa, '', '| Setting | n GT files/seed | Share payload / helper / library | AUC | AP | Hit@5 | AP function size | AP random |',
              '|---|---|---|---|---|---|---|---|']
        for key, label in SETTINGS:
            V = [v for (k, i), X in R.items() if k == key and (isa == 'POOLED' or i == isa) for v in X.values()]
            if not V:
                continue
            L.append('| %s | %d | %s / %s / %s | %s | %s | %s | %s | %s |' % (
                label, round(st.mean(x['n'] for x in V)), f([x['payload'] for x in V]), f([x['helper'] for x in V]),
                f([x['other'] for x in V]), f([x['auc'] for x in V]), f([x['ap'] for x in V]), f([x['hit5'] for x in V]),
                f([x['ap_size'] for x in V]), f([x['ap_rand'] for x in V])))
        pairs = [(R[('unfiltered_non_library', i)][s], R[('filtered_non_library', i)][s]) for i in isas if isa in ('POOLED', i)
                 for s in R.get(('filtered_non_library', i), {}) if s in R.get(('unfiltered_non_library', i), {})]
        if pairs:
            L += ['', 'library-aware − unfiltered (same set of non-library functions), n = %d pairs:' % len(pairs)]
            for k in ('payload', 'other', 'ap', 'auc', 'hit5'):
                d = [l[k] - g[k] for g, l in pairs]
                L.append('- Δ %s = %+.3f (p = %.3g)' % (k, st.mean(d), wilcoxon(d)))
            d = [l['ap'] - l['ap_size'] for g, l in pairs]; L.append('- AP library-aware − AP function size = %+.3f (p = %.3g)' % (st.mean(d), wilcoxon(d)))
            d = [l['ap'] - l['ap_rand'] for g, l in pairs]; L.append('- AP library-aware − AP random = %+.3f (p = %.3g)' % (st.mean(d), wilcoxon(d)))
        L.append('')
    os.makedirs(a.out, exist_ok=True)
    open(os.path.join(a.out, 'SUMMARY_audit_xisa.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    print('\n'.join(L))


if __name__ == '__main__':
    main()
