# -*- coding: utf-8 -*-
"""09_tong_hop_libsym.py — Tổng hợp nhiều seed của kịch bản 'libsym'.

(1) Phát hiện: mean ± std theo (biến thể, tập con) từ một hay nhiều libsym_results.csv (khử trùng theo Model, Subset, Seed);
    chênh lệch ghép cặp theo seed so với MHEN-S gốc + Wilcoxon signed-rank CHÍNH XÁC (hai phía).
    Lưu ý: với n seed, p nhỏ nhất có thể = 2/2^n (n=5 -> 0,0625; n=10 -> 0,002).
(2) Định vị (nếu có ket_qua/A_libsym_<biến thể>_<tag>/A_Q1_tong_hop.csv): mean ± std qua seed của AUC/AP/Hit@5 nhóm
    '2024|test_only' và tỉ trọng bằng chứng vào payload (A_theo_tep.csv, chỉ tệp test).

Dùng: python3 09_tong_hop_libsym.py --results <reports>/libsym_results.csv [thêm csv khác] --a-dir ket_qua --out ket_qua/libsym_tong_hop
"""
import argparse, csv, glob, itertools, math, os, re, statistics as st
from collections import defaultdict

BASE = 'MHEN-S (proposed)'
MET = ['F1', 'PR-AUC', 'ROC-AUC', 'F1@valthr', 'FPR@valthr', 'Recall@valfpr', 'FPR@valfpr']
SHORT = {'S': BASE, 'S_libben': BASE + ' + lib-suppress', 'S_libsym': BASE + ' + lib-suppress(symtab)',
         'S_libboth': BASE + ' + lib-suppress(symtab+benign)'}


def wilcoxon_exact(d):
    d = [x for x in d if x == x and abs(x) > 1e-12]
    n = len(d)
    if n == 0:
        return float('nan')
    a = sorted(range(n), key=lambda i: abs(d[i]))
    rk = [0.0] * n; i = 0
    while i < n:
        j = i
        while j < n and abs(d[a[j]]) == abs(d[a[i]]):
            j += 1
        for t in range(i, j):
            rk[a[t]] = (i + j + 1) / 2.0
        i = j
    w = sum(r for r, x in zip(rk, d) if x > 0)
    tot = sum(rk); mu = tot / 2
    cnt = sum(1 for s in itertools.product((0, 1), repeat=n)
              if abs(sum(r for r, b in zip(rk, s) if b) - mu) >= abs(w - mu) - 1e-9)
    return cnt / 2 ** n


def ms(v):
    v = [x for x in v if x == x]
    return (st.mean(v), st.stdev(v) if len(v) > 1 else 0.0, len(v)) if v else (float('nan'),) * 2 + (0,)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--results', nargs='+', required=True)
    ap.add_argument('--a-dir', default='ket_qua')
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    R = {}
    for p in a.results:
        for r in csv.DictReader(open(p, encoding='utf-8')):
            R[(r['Model'], r['Subset'], r['Seed'])] = r
    by = defaultdict(dict)
    for (m, s, sd), r in R.items():
        by[(m, s)][sd] = r
    L = ['# Tổng hợp kịch bản libsym (nhiều seed)', '', '## (1) Phát hiện — mean ± std qua seed; Δ = so với MHEN-S gốc, ghép cặp theo seed', '']
    for sub in ('All', 'Static-only'):
        L += ['### Tập con: %s' % sub, '', '| Biến thể | n seed | ' + ' | '.join(MET) + ' | Δ F1 (p) | Δ PR-AUC (p) |',
              '|' + '---|' * (len(MET) + 4)]
        base = by.get((BASE, sub), {})
        for m in SHORT.values():
            d = by.get((m, sub), {})
            if not d:
                continue
            cells = []
            for k in MET:
                mu, sd, n = ms([float(r[k]) for r in d.values() if r.get(k) not in (None, '')])
                cells.append('%.4f ± %.4f' % (mu, sd))
            dd = {}
            for k in ('F1', 'PR-AUC'):
                diff = [float(d[s_][k]) - float(base[s_][k]) for s_ in d if s_ in base]
                dd[k] = '—' if m == BASE else '%+.4f (%.3f)' % (st.mean(diff), wilcoxon_exact(diff)) if diff else '—'
            L.append('| %s | %d | %s | %s | %s |' % (m.replace(BASE, 'MHEN-S'), len(d), ' | '.join(cells), dd['F1'], dd['PR-AUC']))
        L.append('')
    # ---- (2) định vị ----
    L += ['## (2) Định vị hàm trên tệp test (mean ± std qua seed)', '',
          '| Biến thể | n seed | n tệp test GT (tổng) | AUC s_topk | AP s_topk | Hit@5 s_topk | AUC s_sum | % bằng chứng vào payload | AP kích thước hàm |',
          '|---|---|---|---|---|---|---|---|---|']
    for s, m in SHORT.items():
        auc, apv, hit, aucs, pay, apb, ntep = [], [], [], [], [], [], 0
        for d in sorted(glob.glob(os.path.join(a.a_dir, 'A_libsym_%s_grouped-*_seed*' % s))):
            p = os.path.join(d, 'A_Q1_tong_hop.csv')
            if not os.path.exists(p):
                continue
            rows = {r['diem']: r for r in csv.DictReader(open(p, encoding='utf-8')) if r['nhom'].endswith('test_only')}
            if 's_topk' not in rows:
                continue
            auc.append(float(rows['s_topk']['auc'])); apv.append(float(rows['s_topk']['ap']))
            hit.append(float(rows['s_topk']['hit5'])); aucs.append(float(rows['s_sum']['auc']))
            apb.append(float(rows['b_ninsn']['ap'])); ntep += int(rows['s_topk']['n_tep'])
            tt = [r for r in csv.DictReader(open(os.path.join(d, 'A_theo_tep.csv'), encoding='utf-8')) if r['is_test'] == 'True']
            v = [float(r['ev_share_payload']) for r in tt if r['ev_share_payload'] not in ('', 'nan')]
            pay.append(sum(v) / len(v) if v else float('nan'))
        if not auc:
            continue
        f = lambda v: '%.3f ± %.3f' % ms(v)[:2]
        L.append('| %s | %d | %d | %s | %s | %s | %s | %s | %s |' % (m.replace(BASE, 'MHEN-S'), len(auc), ntep, f(auc), f(apv),
                                                                   f(hit), f(aucs), f(pay), f(apb)))
    open(os.path.join(a.out, 'TONG_HOP_libsym.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    print('\n'.join(L))


if __name__ == '__main__':
    main()
