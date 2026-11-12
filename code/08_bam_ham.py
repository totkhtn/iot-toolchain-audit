# -*- coding: utf-8 -*-
"""08_bam_ham.py — Bước 3 (khả thi): nhận diện hàm thư viện bằng BĂM CẢ HÀM (kiểu FLIRT) trên binary đã strip.

Pha 'bam' : đọc JSON, với mỗi hàm tính hai mã băm (cùng ISA):
              h_op  = băm chuỗi opcode (ops_seq) của mọi block theo thứ tự địa chỉ  -> khớp chặt
              h_sem = băm chuỗi lớp ngữ nghĩa (sem_seq) của mọi block theo thứ tự địa chỉ -> khớp lỏng hơn
            Ghi cache theo tệp (chạy tiếp được, có hạn --han giây).
            Tập tệp: mọi mã độc còn ký hiệu có GT + mẫu ngẫu nhiên --mau tệp mỗi (giai đoạn, nhãn) trong số còn lại.
Pha 'phan_tich' (đọc cache, không đọc JSON):
  (1) Độ chính xác nhận diện thư viện trên tệp CÒN KÝ HIỆU (CFG vốn đã tính trên bản strip -> giống điều kiện thật):
      chia tệp GT 80/20 theo hash (seed cố định); CSDL = băm của hàm 'thu_vien' / 'ma_doc' trong 80%; dự đoán trên 20%:
      hàm là thư viện nếu băm có trong CSDL thư viện và KHÔNG có trong CSDL mã độc. Báo precision/recall theo vai trò GT,
      tách theo kích thước hàm (số lệnh).
  (2) Độ phủ trên tệp ĐÃ STRIP và lành tính: % hàm / % block khớp CSDL thư viện (CSDL dựng từ TOÀN BỘ tệp GT).
  (3) Tác động dự kiến lên bằng chứng: % điểm s_topk (cache giai đoạn A) nằm trong hàm khớp thư viện.

Dùng:
  python 08_bam_ham.py bam --json-dir .../dataset-moi --gt-dir ket_qua/gt --kiem-ke ket_qua/kiem_ke_dataset_moi_2020.csv \
         ket_qua/kiem_ke_dataset_moi_2024.csv --cache ket_qua/bam_ham --mau 1500 --han 160
  python 08_bam_ham.py phan_tich --gt-dir ket_qua/gt --cache ket_qua/bam_ham --cache-A ket_qua/A_cache --out ket_qua/bam_ham
"""
import argparse, csv, glob, gzip, hashlib, json, os, random, re, sys, time
from collections import Counter, defaultdict

SEM_DROP = {'nop'}
MA_DOC_THEM = re.compile(r'flood|attack|scanner|killer|watchdog|vse|deobf|random_string|^astd$|^add_strings$|'
                         r'^add_entry$|^rand_alpha_str$|^rand_int$|^rand_next_range$|^getRandom|^makeRandom|huawei|'
                         r'exploit|botkill|^csum$|^trim$|^itoa$|cnc|^do_clone$', re.I)
BINS = [(1, 4, '<5 lệnh'), (5, 19, '5–19'), (20, 99, '20–99'), (100, 10 ** 9, '>=100')]


def log(*a):
    print(time.strftime('%H:%M:%S'), *a, flush=True)


def hash_tu_ten(p):
    m = re.match(r'[0-9a-fA-F]{64}', os.path.basename(p))
    return m.group(0).lower() if m else os.path.basename(p).split('__')[0]


def doc_json(p):
    with (gzip.open(p, 'rt', encoding='utf-8', errors='ignore') if p.endswith('.gz') else open(p, encoding='utf-8')) as f:
        return json.load(f)


def bam(a):
    tep_gt = {r['file_hash']: r for r in csv.DictReader(open(os.path.join(a.gt_dir, 'gt_tep.csv'), encoding='utf-8'))}
    kk = []
    for p in a.kiem_ke:
        kk += list(csv.DictReader(open(p, encoding='utf-8')))
    js = {}
    for p in glob.glob(os.path.join(a.json_dir, '*', 'tap_chinh', '**', '*.json*'), recursive=True):
        js[(os.path.relpath(p, a.json_dir).split(os.sep)[0], hash_tu_ten(p))] = p
    rng = random.Random(2026)
    chon = [(r['period'], r['file_hash'], 'gt') for r in kk if r['file_hash'] in tep_gt]
    for per in ('2020', '2024'):
        for lab, ten in (('1', 'md_strip'), ('0', 'lanh_tinh')):
            ds = [r for r in kk if r['period'] == per and r['label'] == lab and r['file_hash'] not in tep_gt
                  and (lab == '0' or r['is_stripped'] == '1')]
            rng.shuffle(ds)
            chon += [(per, r['file_hash'], ten) for r in ds[:a.mau]]
    meta = {(r['period'], r['file_hash']): r for r in kk}
    os.makedirs(a.cache, exist_ok=True)
    f_ham, f_tep = os.path.join(a.cache, 'bam_ham.csv.gz'), os.path.join(a.cache, 'bam_tep.csv')
    xong = set()
    if os.path.exists(f_tep):
        xong = {(r['period'], r['file_hash']) for r in csv.DictReader(open(f_tep, encoding='utf-8'))}
    viec = [c for c in chon if (c[0], c[1]) not in xong and (c[0], c[1]) in js]
    log('cần băm %d tệp (đã xong %d)' % (len(viec), len(xong)))
    t0, n = time.time(), 0
    moi = not xong
    with gzip.open(f_ham, 'at', encoding='utf-8', newline='') as fh, open(f_tep, 'a', newline='', encoding='utf-8') as ft:
        wh, wt = csv.writer(fh), csv.writer(ft)
        if moi:
            wh.writerow(['period', 'file_hash', 'addr', 'ninsn', 'nblocks', 'h_op', 'h_sem'])
            wt.writerow(['period', 'file_hash', 'nhom', 'label', 'arch', 'is_static', 'n_ham'])
        for per, h, nhom in viec:
            d = doc_json(js[(per, h)])
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
            wt.writerow([per, h, nhom, m.get('label'), arch, m.get('is_static'), len(F)])   # ghi SAU hàm
            n += 1
            if n % 200 == 0:
                fh.flush(); ft.flush(); log('%d tệp, %.0fs' % (n, time.time() - t0))
            if time.time() - t0 > a.han:
                log('DUNG_THEO_HAN sau %d tệp' % n); return
    log('XONG băm (%d tệp mới)' % n)


def phan_tich(a):
    tep = {(r['period'], r['file_hash']): r for r in csv.DictReader(open(os.path.join(a.cache, 'bam_tep.csv'), encoding='utf-8'))}
    # ---- vai trò GT (như 05: 'thu_vien' = tên 'khac' có trong >= 10% tệp GT, trừ main) ----
    ten_tep, gt = defaultdict(set), defaultdict(dict)
    for r in csv.DictReader(open(os.path.join(a.gt_dir, 'gt_ham.csv'), encoding='utf-8')):
        vt = r['vai_tro']
        if vt == 'khac' and MA_DOC_THEM.search(r['name']):
            vt = 'payload'
        gt[r['file_hash']][int(r['addr'])] = (r['name'], vt)
        if vt == 'khac':
            ten_tep[r['name']].add(r['file_hash'])
    n_gt = len(gt)
    tv = {n for n, s in ten_tep.items() if len(s) / n_gt >= 0.10 and n != 'main'}

    def vai(h, fa):
        if fa not in gt.get(h, {}):
            return 'khong_ky_hieu'
        n, vt = gt[h][fa]
        return 'ma_doc' if vt in ('payload', 'helper') else ('thu_vien' if n in tv else 'khac')

    rows = defaultdict(list)          # (period, hash) -> [(addr, ninsn, nblocks, h_op, h_sem)]
    with gzip.open(os.path.join(a.cache, 'bam_ham.csv.gz'), 'rt', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            k = (r['period'], r['file_hash'])
            if k in tep:
                rows[k].append((int(r['addr']), int(r['ninsn']), int(r['nblocks']), r['h_op'], r['h_sem']))
    gt_keys = sorted(k for k in rows if tep[k]['nhom'] == 'gt')
    rng = random.Random(10)
    rng.shuffle(gt_keys)
    cut = int(0.8 * len(gt_keys))
    db_keys, ev_keys = gt_keys[:cut], gt_keys[cut:]

    def dung_db(keys, col):
        lib, mal = Counter(), Counter()
        for k in keys:
            for fa, ni, nb, hop, hsem in rows[k]:
                v = vai(k[1], fa)
                hh = hop if col == 'op' else hsem
                if v == 'thu_vien':
                    lib[hh] += 1
                elif v == 'ma_doc':
                    mal[hh] += 1
        return lib, mal

    def bin_of(ni):
        for lo, hi, t in BINS:
            if lo <= ni <= hi:
                return t
        return BINS[0][2]

    L = ['# Bước 3 — nhận diện hàm thư viện bằng băm cả hàm (kiểu FLIRT)', '',
         'Tệp GT: %d (CSDL %d / đánh giá %d, chia theo tệp). Tên "thư viện": %d tên.' % (len(gt_keys), len(db_keys), len(ev_keys), len(tv)), '']
    out_rows = []
    cach_chia = [('ngau_nhien_80_20', db_keys, ev_keys),
                 ('thoi_gian_2020_den_2024', [k for k in gt_keys if k[0] == '2020'], [k for k in gt_keys if k[0] == '2024'])]
    for (ten_chia, db_k, ev_k), col in [(c, b) for c in cach_chia for b in ('op', 'sem')]:
        lib, mal = dung_db(db_k, col)
        L += ['## (1) Độ chính xác — chia `%s` (CSDL %d tệp, đánh giá %d tệp) — băm `h_%s`' % (ten_chia, len(db_k), len(ev_k), col), '',
              '| Kích thước hàm | n thư viện (GT) | Recall thư viện | n mã độc (GT) | Mã độc bị gán nhầm thư viện | Precision (thư viện vs mã độc) |',
              '|---|---|---|---|---|---|']
        stat = defaultdict(Counter)
        for k in ev_k:
            for fa, ni, nb, hop, hsem in rows[k]:
                v = vai(k[1], fa)
                if v not in ('thu_vien', 'ma_doc'):
                    continue
                hh = hop if col == 'op' else hsem
                pred = hh in lib and hh not in mal
                b = bin_of(ni)
                for bb in (b, 'Tất cả'):
                    stat[bb][(v, pred)] += 1
        for b in [t for _, _, t in BINS] + ['Tất cả']:
            s = stat[b]
            nl, nm = s[('thu_vien', True)] + s[('thu_vien', False)], s[('ma_doc', True)] + s[('ma_doc', False)]
            tp, fp = s[('thu_vien', True)], s[('ma_doc', True)]
            r = dict(chia=ten_chia, bam=col, kich_thuoc=b, n_thu_vien=nl, recall_thu_vien=tp / nl if nl else float('nan'), n_ma_doc=nm,
                     ma_doc_nham=fp / nm if nm else float('nan'), precision=tp / (tp + fp) if tp + fp else float('nan'))
            out_rows.append(r)
            L.append('| %s | %d | %.3f | %d | %.3f | %.4f |' % (b, nl, r['recall_thu_vien'], nm, r['ma_doc_nham'], r['precision']))
        L.append('')
    # ---- (2) Độ phủ: CSDL từ TOÀN BỘ tệp GT ----
    L += ['## (2) Độ phủ trên tệp không có GT (CSDL dựng từ toàn bộ tệp GT)', '',
          '| Băm | Giai đoạn | Nhóm | n tệp | % hàm khớp thư viện (trung vị) | % lệnh trong hàm khớp (trung vị) |', '|---|---|---|---|---|---|']
    cov_rows = []
    khop_lib = {}
    for col in ('op', 'sem'):
        lib, mal = dung_db(gt_keys, col)
        khop_lib[col] = {hh for hh in lib if hh not in mal}
        for per in ('2020', '2024'):
            for nhom in ('gt', 'md_strip', 'lanh_tinh'):
                ks = [k for k in rows if k[0] == per and tep[k]['nhom'] == nhom]
                if not ks:
                    continue
                fr_f, fr_i = [], []
                for k in ks:
                    R = rows[k]
                    m = [(hop if col == 'op' else hsem) in khop_lib[col] for _, _, _, hop, hsem in R]
                    tot_i = sum(ni for _, ni, *_ in R) or 1
                    fr_f.append(sum(m) / max(1, len(R)))
                    fr_i.append(sum(ni for (fa, ni, *_), mm in zip(R, m) if mm) / tot_i)
                    cov_rows.append(dict(bam=col, period=per, nhom=nhom, file_hash=k[1], arch=tep[k]['arch'],
                                         is_static=tep[k]['is_static'], frac_ham=fr_f[-1], frac_lenh=fr_i[-1]))
                med = lambda v: sorted(v)[len(v) // 2]
                L.append('| %s | %s | %s | %d | %.3f | %.3f |' % (col, per, nhom, len(ks), med(fr_f), med(fr_i)))
    L.append('')
    # ---- (3) Tác động lên bằng chứng (cache giai đoạn A) ----
    if a.cache_A and os.path.isdir(a.cache_A):
        L += ['## (3) Bằng chứng `s_topk` nằm trong hàm khớp thư viện (tệp GT, băm từ CSDL toàn bộ — lạc quan)', '',
              '| Mô hình | Băm | Giai đoạn | % bằng chứng trong hàm khớp thư viện |', '|---|---|---|---|']
        idx = {}
        for k, R in rows.items():
            for fa, ni, nb, hop, hsem in R:
                idx[(k[0], k[1], fa)] = (hop, hsem)
        for p in sorted(glob.glob(os.path.join(a.cache_A, 'cache_ham_*.csv'))):
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
                            if hh[ci] in khop_lib[col]:
                                acc[(m, col, r['period'])][1] += v
            for (m, col, per), (t, k_) in sorted(acc.items()):
                L.append('| %s | %s | %s | %.3f |' % (m, col, per, k_ / t if t else float('nan')))
        L.append('')
    os.makedirs(a.out, exist_ok=True)
    for name, rr in (('B3_do_chinh_xac.csv', out_rows), ('B3_do_phu_theo_tep.csv', cov_rows)):
        with open(os.path.join(a.out, name), 'w', newline='', encoding='utf-8') as f:
            w = csv.DictWriter(f, fieldnames=list(rr[0].keys())); w.writeheader(); w.writerows(rr)
    open(os.path.join(a.out, 'TOM_TAT_B3.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    print('\n'.join(L))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('pha', choices=['bam', 'phan_tich'])
    ap.add_argument('--json-dir'); ap.add_argument('--gt-dir', required=True)
    ap.add_argument('--kiem-ke', nargs='*', default=[]); ap.add_argument('--cache', required=True)
    ap.add_argument('--cache-A'); ap.add_argument('--out')
    ap.add_argument('--mau', type=int, default=1500); ap.add_argument('--han', type=float, default=1e18)
    a = ap.parse_args()
    bam(a) if a.pha == 'bam' else phan_tich(a)


if __name__ == '__main__':
    main()
