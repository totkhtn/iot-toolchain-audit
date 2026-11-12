# -*- coding: utf-8 -*-
"""13_compare_libaware.py: detection accuracy of the unfiltered model versus the library-aware (filtered) model,
same split and seed.

Usage: python3 13_compare_libaware.py --unfiltered <unfiltered>/reports/libaware_results.csv \
           --filtered <filtered>/reports/libaware_results.csv --out workdir/libaware
"""
import argparse, csv, os
from collections import defaultdict

MET = ['F1', 'PR-AUC', 'ROC-AUC', 'F1@valthr', 'FPR@valthr', 'Recall@valfpr', 'FPR@valfpr']


def read_results(p):
    d = {}
    for r in csv.DictReader(open(p, encoding='utf-8')):
        d[(r['Scenario'], r['SplitID'], r['Seed'], r['Model'], r['Subset'])] = r
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--unfiltered', required=True); ap.add_argument('--filtered', required=True); ap.add_argument('--out', required=True)
    a = ap.parse_args()
    U, F = read_results(a.unfiltered), read_results(a.filtered)
    keys = sorted(set(U) & set(F), key=lambda k: (k[0], k[1], k[2], k[4] != 'All', k[4], k[3]))
    out = ['# Detection: unfiltered → library-aware (library functions filtered), same split and seed', '',
           '| Scenario | Split | Seed | Subset | Model | ' + ' | '.join('%s unfiltered→filtered' % m for m in MET) + ' |',
           '|' + '---|' * (5 + len(MET))]
    for k in keys:
        if not (k[4] in ('All', 'Static-only') or k[0] == 'libaware_xisa'):
            continue
        u, f = U[k], F[k]
        cells = []
        for m in MET:
            try:
                cells.append('%.4f→%.4f' % (float(u[m]), float(f[m])))
            except (ValueError, KeyError):
                cells.append('—')
        out.append('| %s | %s | %s | %s | %s | %s |' % (k[0], k[1], k[2], k[4], k[3], ' | '.join(cells)))
    os.makedirs(a.out, exist_ok=True)
    open(os.path.join(a.out, 'DETECTION_COMPARISON.md'), 'w', encoding='utf-8').write('\n'.join(out) + '\n')
    print('\n'.join(out[:40]))
    if len(out) > 40:
        print('... (%d lines, see %s)' % (len(out), os.path.join(a.out, 'DETECTION_COMPARISON.md')))


if __name__ == '__main__':
    main()
