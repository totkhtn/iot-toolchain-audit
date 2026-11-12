# -*- coding: utf-8 -*-
"""17_tong_hop_xisa.py — Phát hiện cross-ISA (leave-one-ISA-out): không lọc (goc) vs library-aware (loc).

Tính lại chỉ số từ predictions/libaware_xisa__ISA-<isa>_seed<s>.npz (đủ 50 đơn vị/bên, kể cả các phiên Kaggle trước —
libaware_results.csv chỉ còn phiên cuối). Ngưỡng: thrval__ (tối ưu F1 trên val) và thrfpr__ (FPR mục tiêu trên val).
Chỉ số: F1@0.5, PR-AUC, F1@valthr, FPR@valthr, Recall@valfpr, FPR@valfpr. Kiểm định Wilcoxon chính xác ghép cặp theo seed
cho từng (mô hình, ISA) và gộp 50 cặp (ISA × seed) bằng xấp xỉ chuẩn.

Dùng: python3 17_tong_hop_xisa.py --goc <goc>/predictions --loc <loc>/predictions --out ket_qua/xisa_tong_hop
"""
import argparse, glob, itertools, math, os, re, statistics as st
from collections import defaultdict
import numpy as np

MET = ['F1', 'PR-AUC', 'F1@valthr', 'FPR@valthr', 'Recall@valfpr', 'FPR@valfpr']


def ap_score(y, p):
    o = np.argsort(-p, kind='mergesort'); y = y[o]
    tp = np.cumsum(y); prec = tp / np.arange(1, len(y) + 1)
    return float((prec * y).sum() / max(1, y.sum()))


def metrics(y, p, t):
    pred = (p >= t).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    f1 = 2 * tp / max(1, 2 * tp + fp + fn)
    return f1, fp / max(1, fp + tn), tp / max(1, tp + fn)


def tinh(z, m):
    y, p = z['y'].astype(int), z[m].astype(float)
    tv, tf = float(z['thrval__' + m]), float(z['thrfpr__' + m])
    f1, _, _ = metrics(y, p, 0.5); f1v, fprv, _ = metrics(y, p, tv); _, fprf, recf = metrics(y, p, tf)
    return {'F1': f1, 'PR-AUC': ap_score(y, p), 'F1@valthr': f1v, 'FPR@valthr': fprv, 'Recall@valfpr': recf, 'FPR@valfpr': fprf,
            'n': len(y), 'n_pos': int(y.sum())}


def wilcoxon_exact(d):
    d = [x for x in d if abs(x) > 1e-12]
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
    if n <= 16:
        return sum(1 for s in itertools.product((0, 1), repeat=n)
                   if abs(sum(r for r, b in zip(rk, s) if b) - mu) >= abs(w - mu) - 1e-9) / 2 ** n
    sd = math.sqrt(sum(r * r for r in rk) / 4)
    zz = abs(w - mu) / sd if sd else 0.0
    return math.erfc(zz / math.sqrt(2))


def doc(d):
    R = {}
    for p in glob.glob(os.path.join(d, 'libaware_xisa__ISA-*_seed*.npz')):
        m = re.search(r'ISA-([A-Za-z0-9]+)_seed(\d+)', p)
        z = np.load(p, allow_pickle=True)
        for k in z.files:
            if k in ('y', 'gidx') or k.startswith(('thrval__', 'thrfpr__', 'meta_')):
                continue
            R[(k, m.group(1), m.group(2))] = tinh(z, k)
    return R


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--goc', required=True); ap.add_argument('--loc', required=True); ap.add_argument('--out', required=True)
    a = ap.parse_args()
    G, L = doc(a.goc), doc(a.loc)
    keys = sorted(set(G) & set(L))
    models = sorted({k[0] for k in keys}); isas = sorted({k[1] for k in keys})
    out = ['# Cross-ISA (leave-one-ISA-out): không lọc (goc) → library-aware (loc)', '',
           '%d cặp đơn vị (mô hình × ISA × seed). Δ = loc − goc; p = Wilcoxon ghép cặp theo seed (n=10 mỗi ISA; '
           'gộp 50 cặp ISA×seed dùng xấp xỉ chuẩn).' % len(keys), '']
    csvrows = []
    for metric in ('F1@valthr', 'FPR@valthr', 'Recall@valfpr', 'PR-AUC'):
        out += ['## %s — mean qua seed (goc → loc, Δ, p)' % metric, '',
                '| Mô hình | ' + ' | '.join(isas) + ' | Gộp 5 ISA |', '|' + '---|' * (len(isas) + 2)]
        for m in models:
            cells, pool = [], []
            for isa in isas:
                ss = sorted(s for (mm, ii, s) in keys if mm == m and ii == isa)
                if not ss:
                    cells.append('—'); continue
                g = [G[(m, isa, s)][metric] for s in ss]; l = [L[(m, isa, s)][metric] for s in ss]
                d = [y - x for x, y in zip(g, l)]; pool += d
                p = wilcoxon_exact(d)
                star = '**' if p < 0.05 else ''
                cells.append('%s%.4f→%.4f (%+.4f, p=%.3f)%s' % (star, st.mean(g), st.mean(l), st.mean(d), p, star))
                csvrows.append(dict(metric=metric, model=m, isa=isa, n_seed=len(ss), goc=st.mean(g), loc=st.mean(l),
                                    delta=st.mean(d), p=p))
            pp = wilcoxon_exact(pool)
            cells.append('%+.4f (p=%.3g)' % (st.mean(pool), pp))
            out.append('| %s | %s |' % (m, ' | '.join(cells)))
        out.append('')
    os.makedirs(a.out, exist_ok=True)
    import csv as _csv
    with open(os.path.join(a.out, 'xisa_theo_isa.csv'), 'w', newline='', encoding='utf-8') as f:
        w = _csv.DictWriter(f, fieldnames=list(csvrows[0].keys())); w.writeheader(); w.writerows(csvrows)
    open(os.path.join(a.out, 'TONG_HOP_xisa.md'), 'w', encoding='utf-8').write('\n'.join(out) + '\n')
    print('\n'.join(out))


if __name__ == '__main__':
    main()
