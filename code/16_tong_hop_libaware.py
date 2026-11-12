# -*- coding: utf-8 -*-
"""16_tong_hop_libaware.py — Tổng hợp nhiều seed: không lọc (goc) vs library-aware (loc).

(1) Phát hiện: mỗi (mô hình, tập con): mean ± std của goc và loc; Δ = loc − goc ghép cặp theo seed; Wilcoxon chính xác.
(2) Định vị (nếu có ket_qua/A_la_ms/<cách>_grouped-2024_seed*/A_Q1_tong_hop.csv từ 16_chay_A_libaware_nhieu_seed.sh):
    mean ± std qua seed của AUC/AP/Hit@5 (s_topk) và tỉ trọng bằng chứng vào payload/helper/khác (test), kèm baseline,
    Wilcoxon cho loc_bo_thu_vien vs goc_bo_thu_vien (cùng tập hàm).
Dùng: python3 16_tong_hop_libaware.py --goc <goc>/libaware_results.csv --loc <loc>/libaware_results.csv \
        --a-dir ket_qua/A_la_ms --out ket_qua/libaware_tong_hop
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


def doc(p):
    d = defaultdict(dict)
    for r in csv.DictReader(open(p, encoding='utf-8')):
        d[(r['Model'], r['Subset'])][r['Seed']] = r
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--goc', required=True); ap.add_argument('--loc', required=True)
    ap.add_argument('--a-dir', default='ket_qua/A_la_ms'); ap.add_argument('--out', required=True)
    a = ap.parse_args()
    G, L_ = doc(a.goc), doc(a.loc)
    out = ['# Library-aware HIN — tổng hợp nhiều seed (goc = không lọc, loc = lọc hàm thư viện)', '',
           'Δ = loc − goc ghép cặp theo seed; p = Wilcoxon signed-rank chính xác, hai phía.', '']
    for sub in ('All', 'Static-only'):
        out += ['## Phát hiện — tập con %s' % sub, '',
                '| Mô hình | n seed | ' + ' | '.join('%s goc / loc' % m for m in MET) + ' | Δ F1 (p) | Δ FPR@valthr (p) | Δ PR-AUC (p) |',
                '|' + '---|' * (len(MET) + 5)]
        for m in sorted({k[0] for k in G if k[1] == sub}):
            g, l = G.get((m, sub), {}), L_.get((m, sub), {})
            seeds = sorted(set(g) & set(l))
            if not seeds:
                continue
            cells = []
            for k in MET:
                mg, sg = ms([float(g[s][k]) for s in seeds]); ml, sl = ms([float(l[s][k]) for s in seeds])
                cells.append('%.4f±%.4f / %.4f±%.4f' % (mg, sg, ml, sl))
            dd = []
            for k in ('F1', 'FPR@valthr', 'PR-AUC'):
                diff = [float(l[s][k]) - float(g[s][k]) for s in seeds]
                dd.append('%+.4f (%.3f)' % (st.mean(diff), wilcoxon_exact(diff)))
            out.append('| %s | %d | %s | %s |' % (m, len(seeds), ' | '.join(cells), ' | '.join(dd)))
        out.append('')
    # ---- định vị ----
    cach = [('goc_moi_ham', 'gốc, mọi hàm'), ('goc_bo_thu_vien', 'gốc, bỏ hàm thư viện'), ('loc_bo_thu_vien', 'library-aware, bỏ hàm thư viện')]
    R = defaultdict(dict)
    for key, _ in cach:
        for d in glob.glob(os.path.join(a.a_dir, '%s_grouped-*_seed*' % key)):
            p = os.path.join(d, 'A_Q1_tong_hop.csv')
            if not os.path.exists(p):
                continue
            sd = d.rsplit('seed', 1)[1]
            rows = {r['diem']: r for r in csv.DictReader(open(p, encoding='utf-8')) if r['nhom'].endswith('test_only')}
            tt = [r for r in csv.DictReader(open(os.path.join(d, 'A_theo_tep.csv'), encoding='utf-8')) if r['is_test'] == 'True']
            sh = {v: st.mean(float(r['ev_share_' + v]) for r in tt if r['ev_share_' + v] not in ('', 'nan')) for v in ('payload', 'helper', 'khac')}
            R[key][sd] = dict(auc=float(rows['s_topk']['auc']), ap=float(rows['s_topk']['ap']), hit5=float(rows['s_topk']['hit5']),
                              ap_size=float(rows['b_ninsn']['ap']), auc_size=float(rows['b_ninsn']['auc']),
                              ap_rand=float(rows['b_random']['ap']), n=int(rows['s_topk']['n_tep']), **sh)
    if R:
        out += ['## Định vị hàm trên tệp test (mean ± std qua seed)', '',
                '| Cách | n seed | n tệp-lượt | % bằng chứng payload / helper / khác | AUC s_topk | AP s_topk | Hit@5 | AP kích thước | AP ngẫu nhiên |',
                '|---|---|---|---|---|---|---|---|---|']
        f = lambda v: '%.3f±%.3f' % ms(v)
        for key, ten in cach:
            X = R.get(key, {})
            if not X:
                continue
            V = list(X.values())
            out.append('| %s | %d | %d | %s / %s / %s | %s | %s | %s | %s | %s |' % (
                ten, len(V), sum(x['n'] for x in V), f([x['payload'] for x in V]), f([x['helper'] for x in V]),
                f([x['khac'] for x in V]), f([x['auc'] for x in V]), f([x['ap'] for x in V]), f([x['hit5'] for x in V]),
                f([x['ap_size'] for x in V]), f([x['ap_rand'] for x in V])))
        if R.get('goc_bo_thu_vien') and R.get('loc_bo_thu_vien'):
            s_ = sorted(set(R['goc_bo_thu_vien']) & set(R['loc_bo_thu_vien']))
            out += ['', 'Kiểm định ghép cặp library-aware vs gốc (cùng tập hàm không phải thư viện), n = %d seed:' % len(s_), '']
            for k in ('payload', 'khac', 'ap', 'auc', 'hit5'):
                diff = [R['loc_bo_thu_vien'][s][k] - R['goc_bo_thu_vien'][s][k] for s in s_]
                out.append('- Δ %s = %+.3f (p = %.4f)' % (k, st.mean(diff), wilcoxon_exact(diff)))
            diff = [R['loc_bo_thu_vien'][s]['ap'] - R['loc_bo_thu_vien'][s]['ap_size'] for s in s_]
            out.append('- AP library-aware − AP kích thước hàm = %+.3f (p = %.4f)' % (st.mean(diff), wilcoxon_exact(diff)))
            diff = [R['loc_bo_thu_vien'][s]['ap'] - R['loc_bo_thu_vien'][s]['ap_rand'] for s in s_]
            out.append('- AP library-aware − AP ngẫu nhiên = %+.3f (p = %.4f)' % (st.mean(diff), wilcoxon_exact(diff)))
    os.makedirs(a.out, exist_ok=True)
    open(os.path.join(a.out, 'TONG_HOP_libaware.md'), 'w', encoding='utf-8').write('\n'.join(out) + '\n')
    print('\n'.join(out))


if __name__ == '__main__':
    main()
