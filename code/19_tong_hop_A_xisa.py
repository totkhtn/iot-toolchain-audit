# -*- coding: utf-8 -*-
"""19_tong_hop_A_xisa.py — Tổng hợp định vị hàm cross-ISA (ket_qua/A_xisa/<ISA>/<cách>_grouped-ISA-<ISA>_seed<s>/).
Theo từng ISA giữ lại và gộp 5 ISA × 10 seed: tỉ trọng bằng chứng (payload/helper/thư viện), AUC/AP/Hit@5 `s_topk`,
baseline kích thước/ngẫu nhiên; Wilcoxon ghép cặp loc_bo_thu_vien vs goc_bo_thu_vien (theo seed; gộp = xấp xỉ chuẩn).
Dùng: python3 19_tong_hop_A_xisa.py --a-dir ket_qua/A_xisa --out ket_qua/A_xisa
"""
import argparse, csv, glob, itertools, math, os, re, statistics as st
from collections import defaultdict

CACH = [('goc_moi_ham', 'gốc, mọi hàm'), ('goc_bo_thu_vien', 'gốc, bỏ thư viện'), ('loc_bo_thu_vien', 'library-aware, bỏ thư viện')]


def wil(d):
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


def doc(d):
    rows = {r['diem']: r for r in csv.DictReader(open(os.path.join(d, 'A_Q1_tong_hop.csv'), encoding='utf-8'))
            if r['nhom'].endswith('test_only')}
    tt = [r for r in csv.DictReader(open(os.path.join(d, 'A_theo_tep.csv'), encoding='utf-8')) if r['is_test'] == 'True']
    sh = {v: st.mean(float(r['ev_share_' + v]) for r in tt if r['ev_share_' + v] not in ('', 'nan'))
          for v in ('payload', 'helper', 'khac')}
    g = lambda k, m: float(rows[k][m])
    return dict(n=int(rows['s_topk']['n_tep']), auc=g('s_topk', 'auc'), ap=g('s_topk', 'ap'), hit5=g('s_topk', 'hit5'),
                ap_size=g('b_ninsn', 'ap'), auc_size=g('b_ninsn', 'auc'), hit5_size=g('b_ninsn', 'hit5'),
                ap_rand=g('b_random', 'ap'), **sh)


def main():
    ap = argparse.ArgumentParser(); ap.add_argument('--a-dir', required=True); ap.add_argument('--out', required=True)
    a = ap.parse_args()
    R = defaultdict(dict)                      # (cách, isa) -> {seed: dict}
    for d in glob.glob(os.path.join(a.a_dir, '*', '*_grouped-ISA-*_seed*')):
        m = re.match(r'(.+)_grouped-ISA-([A-Za-z0-9]+)_seed(\d+)$', os.path.basename(d))
        if m and os.path.exists(os.path.join(d, 'A_Q1_tong_hop.csv')):
            R[(m.group(1), m.group(2))][m.group(3)] = doc(d)
    isas = sorted({k[1] for k in R})
    f = lambda v: '%.3f±%.3f' % (st.mean(v), st.stdev(v) if len(v) > 1 else 0.0)
    L = ['# Định vị hàm cross-ISA (ISA giữ lại làm test; GT v2; mean ± std qua 10 seed)', '']
    for isa in isas + ['GỘP']:
        L += ['## %s' % isa, '', '| Cách | n tệp GT/seed | % payload / helper / thư viện | AUC | AP | Hit@5 | AP kích thước | AP ngẫu nhiên |',
              '|---|---|---|---|---|---|---|---|']
        for key, ten in CACH:
            V = [v for (k, i), X in R.items() if k == key and (isa == 'GỘP' or i == isa) for v in X.values()]
            if not V:
                continue
            L.append('| %s | %d | %s / %s / %s | %s | %s | %s | %s | %s |' % (
                ten, round(st.mean(x['n'] for x in V)), f([x['payload'] for x in V]), f([x['helper'] for x in V]),
                f([x['khac'] for x in V]), f([x['auc'] for x in V]), f([x['ap'] for x in V]), f([x['hit5'] for x in V]),
                f([x['ap_size'] for x in V]), f([x['ap_rand'] for x in V])))
        pairs = [(R[('goc_bo_thu_vien', i)][s], R[('loc_bo_thu_vien', i)][s]) for i in isas if isa in ('GỘP', i)
                 for s in R.get(('loc_bo_thu_vien', i), {}) if s in R.get(('goc_bo_thu_vien', i), {})]
        if pairs:
            L += ['', 'library-aware − gốc (cùng tập hàm không phải thư viện), n = %d cặp:' % len(pairs)]
            for k in ('payload', 'khac', 'ap', 'auc', 'hit5'):
                d = [l[k] - g[k] for g, l in pairs]
                L.append('- Δ %s = %+.3f (p = %.3g)' % (k, st.mean(d), wil(d)))
            d = [l['ap'] - l['ap_size'] for g, l in pairs]; L.append('- AP library-aware − AP kích thước = %+.3f (p = %.3g)' % (st.mean(d), wil(d)))
            d = [l['ap'] - l['ap_rand'] for g, l in pairs]; L.append('- AP library-aware − AP ngẫu nhiên = %+.3f (p = %.3g)' % (st.mean(d), wil(d)))
        L.append('')
    os.makedirs(a.out, exist_ok=True)
    open(os.path.join(a.out, 'TONG_HOP_A_xisa.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    print('\n'.join(L))


if __name__ == '__main__':
    main()
