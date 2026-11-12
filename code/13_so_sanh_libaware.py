# -*- coding: utf-8 -*-
"""13_so_sanh_libaware.py — So sánh độ chính xác phát hiện: không lọc (goc) vs library-aware (loc), cùng split/seed.
Dùng: python3 13_so_sanh_libaware.py --goc .../goc/reports/libaware_results.csv --loc .../loc/reports/libaware_results.csv --out ket_qua/libaware
"""
import argparse, csv, os
from collections import defaultdict

MET = ['F1', 'PR-AUC', 'ROC-AUC', 'F1@valthr', 'FPR@valthr', 'Recall@valfpr', 'FPR@valfpr']


def doc(p):
    d = {}
    for r in csv.DictReader(open(p, encoding='utf-8')):
        d[(r['Scenario'], r['SplitID'], r['Seed'], r['Model'], r['Subset'])] = r
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--goc', required=True); ap.add_argument('--loc', required=True); ap.add_argument('--out', required=True)
    a = ap.parse_args()
    G, L_ = doc(a.goc), doc(a.loc)
    keys = sorted(set(G) & set(L_), key=lambda k: (k[0], k[1], k[2], k[4] != 'All', k[4], k[3]))
    out = ['# Phát hiện: không lọc (gốc) → library-aware (lọc hàm thư viện), cùng split/seed', '',
           '| Kịch bản | Split | Seed | Tập con | Mô hình | ' + ' | '.join('%s gốc→lọc' % m for m in MET) + ' |',
           '|' + '---|' * (5 + len(MET))]
    for k in keys:
        if not (k[4] in ('All', 'Static-only') or k[0] == 'libaware_xisa'):
            continue
        g, l = G[k], L_[k]
        cells = []
        for m in MET:
            try:
                cells.append('%.4f→%.4f' % (float(g[m]), float(l[m])))
            except (ValueError, KeyError):
                cells.append('—')
        out.append('| %s | %s | %s | %s | %s | %s |' % (k[0], k[1], k[2], k[4], k[3], ' | '.join(cells)))
    os.makedirs(a.out, exist_ok=True)
    open(os.path.join(a.out, 'SO_SANH_PHAT_HIEN.md'), 'w', encoding='utf-8').write('\n'.join(out) + '\n')
    print('\n'.join(out[:40]))
    if len(out) > 40:
        print('... (%d dòng, xem %s)' % (len(out), os.path.join(a.out, 'SO_SANH_PHAT_HIEN.md')))


if __name__ == '__main__':
    main()
