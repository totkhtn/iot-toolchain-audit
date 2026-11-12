# -*- coding: utf-8 -*-
"""16_aggregate_libaware.py: aggregation over seeds, unfiltered model versus library-aware (filtered) model.

(1) Detection: for every (model, subset), mean ± std of the unfiltered and the filtered run; Δ = filtered − unfiltered,
    paired by seed; exact Wilcoxon signed-rank test.
(2) Localization (if <a-dir>/<setting>_grouped-2024_seed*/A_Q1_summary.csv exists, written by
    16_run_audit_libaware_multiseed.sh): mean ± std over seeds of AUC/AP/Hit@5 (s_topk) and of the evidence shares on
    payload/helper/other (test files), with baselines; Wilcoxon test of filtered_non_library versus
    unfiltered_non_library (same set of functions).

Usage: python3 16_aggregate_libaware.py --unfiltered <unfiltered>/libaware_results.csv --filtered <filtered>/libaware_results.csv \
           --a-dir workdir/A_la_ms --out workdir/libaware_summary
"""
import argparse, csv, glob, itertools, os, statistics as st
from collections import defaultdict

MET = ['F1', 'PR-AUC', 'F1@valthr', 'FPR@valthr', 'Recall@valfpr', 'FPR@valfpr']


def wilcoxon_exact(d):
    d = [x for x in d if x == x and abs(x) > 1e-12]
    n = len(d)
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
    return sum(1 for s in itertools.product((0, 1), repeat=n)
               if abs(sum(r for r, b in zip(rk, s) if b) - mu) >= abs(w - mu) - 1e-9) / 2 ** n


def ms(v):
    v = [x for x in v if x == x]
    return (st.mean(v), st.stdev(v) if len(v) > 1 else 0.0) if v else (float('nan'), float('nan'))


def read_results(p):
    d = defaultdict(dict)
    for r in csv.DictReader(open(p, encoding='utf-8')):
        d[(r['Model'], r['Subset'])][r['Seed']] = r
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--unfiltered', required=True); ap.add_argument('--filtered', required=True)
    ap.add_argument('--a-dir', default='workdir/A_la_ms'); ap.add_argument('--out', required=True)
    a = ap.parse_args()
    U, F = read_results(a.unfiltered), read_results(a.filtered)
    out = ['# Library-aware HIN: summary over seeds (unfiltered = no filtering, filtered = library functions filtered)', '',
           'Δ = filtered − unfiltered, paired by seed; p = exact two-sided Wilcoxon signed-rank test.', '']
    for sub in ('All', 'Static-only'):
        out += ['## Detection, subset %s' % sub, '',
                '| Model | n seeds | ' + ' | '.join('%s unfiltered / filtered' % m for m in MET) + ' | Δ F1 (p) | Δ FPR@valthr (p) | Δ PR-AUC (p) |',
                '|' + '---|' * (len(MET) + 5)]
        for m in sorted({k[0] for k in U if k[1] == sub}):
            u, f = U.get((m, sub), {}), F.get((m, sub), {})
            seeds = sorted(set(u) & set(f))
            if not seeds:
                continue
            cells = []
            for k in MET:
                mu_u, sd_u = ms([float(u[s][k]) for s in seeds]); mu_f, sd_f = ms([float(f[s][k]) for s in seeds])
                cells.append('%.4f±%.4f / %.4f±%.4f' % (mu_u, sd_u, mu_f, sd_f))
            dd = []
            for k in ('F1', 'FPR@valthr', 'PR-AUC'):
                diff = [float(f[s][k]) - float(u[s][k]) for s in seeds]
                dd.append('%+.4f (%.3f)' % (st.mean(diff), wilcoxon_exact(diff)))
            out.append('| %s | %d | %s | %s |' % (m, len(seeds), ' | '.join(cells), ' | '.join(dd)))
        out.append('')
    # ---- localization ----
    settings = [('unfiltered_all_functions', 'unfiltered, all functions'),
                ('unfiltered_non_library', 'unfiltered, library functions removed'),
                ('filtered_non_library', 'library-aware, library functions removed')]
    R = defaultdict(dict)
    for key, _ in settings:
        for d in glob.glob(os.path.join(a.a_dir, '%s_grouped-*_seed*' % key)):
            p = os.path.join(d, 'A_Q1_summary.csv')
            if not os.path.exists(p):
                continue
            sd = d.rsplit('seed', 1)[1]
            rows = {r['score']: r for r in csv.DictReader(open(p, encoding='utf-8')) if r['group'].endswith('test_only')}
            tt = [r for r in csv.DictReader(open(os.path.join(d, 'A_per_file.csv'), encoding='utf-8')) if r['is_test'] == 'True']
            sh = {v: st.mean(float(r['ev_share_' + v]) for r in tt if r['ev_share_' + v] not in ('', 'nan')) for v in ('payload', 'helper', 'other')}
            R[key][sd] = dict(auc=float(rows['s_topk']['auc']), ap=float(rows['s_topk']['ap']), hit5=float(rows['s_topk']['hit5']),
                              ap_size=float(rows['b_ninsn']['ap']), auc_size=float(rows['b_ninsn']['auc']),
                              ap_rand=float(rows['b_random']['ap']), n=int(rows['s_topk']['n_files']), **sh)
    if R:
        out += ['## Function localization on test files (mean ± std over seeds)', '',
                '| Setting | n seeds | n file-runs | Evidence share payload / helper / other | AUC s_topk | AP s_topk | Hit@5 | AP function size | AP random |',
                '|---|---|---|---|---|---|---|---|---|']
        f = lambda v: '%.3f±%.3f' % ms(v)
        for key, label in settings:
            X = R.get(key, {})
            if not X:
                continue
            V = list(X.values())
            out.append('| %s | %d | %d | %s / %s / %s | %s | %s | %s | %s | %s |' % (
                label, len(V), sum(x['n'] for x in V), f([x['payload'] for x in V]), f([x['helper'] for x in V]),
                f([x['other'] for x in V]), f([x['auc'] for x in V]), f([x['ap'] for x in V]), f([x['hit5'] for x in V]),
                f([x['ap_size'] for x in V]), f([x['ap_rand'] for x in V])))
        if R.get('unfiltered_non_library') and R.get('filtered_non_library'):
            s_ = sorted(set(R['unfiltered_non_library']) & set(R['filtered_non_library']))
            out += ['', 'Paired test, library-aware versus unfiltered (same set of non-library functions), n = %d seeds:' % len(s_), '']
            for k in ('payload', 'other', 'ap', 'auc', 'hit5'):
                diff = [R['filtered_non_library'][s][k] - R['unfiltered_non_library'][s][k] for s in s_]
                out.append('- Δ %s = %+.3f (p = %.4f)' % (k, st.mean(diff), wilcoxon_exact(diff)))
            diff = [R['filtered_non_library'][s]['ap'] - R['filtered_non_library'][s]['ap_size'] for s in s_]
            out.append('- AP library-aware − AP function size = %+.3f (p = %.4f)' % (st.mean(diff), wilcoxon_exact(diff)))
            diff = [R['filtered_non_library'][s]['ap'] - R['filtered_non_library'][s]['ap_rand'] for s in s_]
            out.append('- AP library-aware − AP random = %+.3f (p = %.4f)' % (st.mean(diff), wilcoxon_exact(diff)))
    os.makedirs(a.out, exist_ok=True)
    open(os.path.join(a.out, 'SUMMARY_libaware.md'), 'w', encoding='utf-8').write('\n'.join(out) + '\n')
    print('\n'.join(out))


if __name__ == '__main__':
    main()
