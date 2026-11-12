# -*- coding: utf-8 -*-
"""05_tao_chu_ky_thu_vien.py — Cơ sở dữ liệu "chữ ký thư viện" kiểu FLIRT cho lib-suppress (symtab).

Với mỗi mã độc còn ký hiệu có GT (ket_qua/gt), đọc JSON, tính chữ ký ngữ nghĩa của từng block (giống hệt sem_key của
hin_static_v15) và gán vai trò của HÀM chứa block theo .symtab:
  thu_vien : hàm vai trò 'khac' có tên xuất hiện trong >= --min-frac-ten tệp GT (libc/uClibc/libgcc/crt dùng chung),
             trừ 'main'
  ma_doc   : hàm 'payload' hoặc 'helper' (do tác giả mã độc viết)
  khac     : còn lại (hàm 'khac' hiếm — có thể là hàm mã độc chưa có trong quy tắc tên; không dùng để mặt nạ)
Đầu ra: chu_ky_thu_vien.csv.gz  (file_hash, period, sig, n_thu_vien, n_ma_doc, n_khac) — số BLOCK theo vai trò.
Quyết định mặt nạ (theo tập TRAIN) nằm trong hin_static_v15_libsym.py, không ở đây -> không rò rỉ nhãn test.

Dùng:  python 05_tao_chu_ky_thu_vien.py --json-dir .../HIN-Static/dataset-moi --gt-dir ket_qua/gt --out ket_qua/libsym [--han 160]
"""
import argparse, csv, glob, gzip, json, os, re, sys, time
from collections import Counter, defaultdict

SEM_DROP = {'nop'}
# Bổ sung cho QUY_TAC của 01_trich_symtab_gt.py: tên hàm mã độc bị bỏ sót, phát hiện khi rà ten_thu_vien.txt (24/10)
MA_DOC_THEM = re.compile(r'flood|attack|scanner|killer|watchdog|vse|deobf|random_string|^astd$|^add_strings$|'
                         r'^add_entry$|^rand_alpha_str$|^rand_int$|^rand_next_range$|^getRandom|^makeRandom|huawei|'
                         r'exploit|botkill|^csum$|^trim$|^itoa$|cnc|^do_clone$', re.I)
MIN_INSNS = 3


def sem_key(sem):
    s = [x for x in sem if x not in SEM_DROP]
    return 'S:' + '|'.join(s) if len(s) >= MIN_INSNS else None


def hash_tu_ten(p):
    b = os.path.basename(p)
    m = re.match(r'[0-9a-fA-F]{64}', b)
    return m.group(0).lower() if m else b.split('__')[0].split('_')[0]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--json-dir', required=True)
    ap.add_argument('--gt-dir', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--min-frac-ten', type=float, default=0.10)
    ap.add_argument('--han', type=float, default=1e18)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    tep = {r['file_hash']: r for r in csv.DictReader(open(os.path.join(a.gt_dir, 'gt_tep.csv'), encoding='utf-8'))}
    ham = defaultdict(dict)
    ten_tep = defaultdict(set)
    for r in csv.DictReader(open(os.path.join(a.gt_dir, 'gt_ham.csv'), encoding='utf-8')):
        vt = 'payload' if (r['vai_tro'] == 'khac' and MA_DOC_THEM.search(r['name'])) else r['vai_tro']
        ham[r['file_hash']][int(r['addr'])] = (r['name'], vt)
        if vt == 'khac':
            ten_tep[r['name']].add(r['file_hash'])
    n_tep = max(1, len(tep))
    thu_vien_ten = {n for n, s in ten_tep.items() if len(s) / n_tep >= a.min_frac_ten and n != 'main'}

    def vai(name, vt):
        if vt in ('payload', 'helper'):
            return 'ma_doc'
        return 'thu_vien' if name in thu_vien_ten else 'khac'

    with open(os.path.join(a.out, 'ten_thu_vien.txt'), 'w', encoding='utf-8') as f:
        f.write('# tên hàm vai trò "khác" có mặt trong >= %.0f%% tệp GT -> coi là thư viện/runtime\n' % (100 * a.min_frac_ten))
        for n in sorted(thu_vien_ten):
            f.write('%s\t%d\n' % (n, len(ten_tep[n])))

    js = {}
    for p in glob.glob(os.path.join(a.json_dir, '*', 'tap_chinh', '**', '*.json*'), recursive=True):
        js[hash_tu_ten(p)] = (os.path.relpath(p, a.json_dir).split(os.sep)[0], p)
    out = os.path.join(a.out, 'chu_ky_thu_vien.csv.gz')
    xong = set()
    if os.path.exists(out):
        try:
            with gzip.open(out, 'rt', encoding='utf-8') as f:
                xong = {r['file_hash'] for r in csv.DictReader(f)}
        except (EOFError, OSError):       # lần trước bị ngắt giữa chừng -> làm lại từ đầu cho chắc
            xong = set()
            os.replace(out, out + '.hong')
    viec = sorted(h for h in tep if h in js and h not in xong)
    print('tên thư viện: %d | tệp còn: %d (đã xong %d)' % (len(thu_vien_ten), len(viec), len(xong)), flush=True)
    t0, n = time.time(), 0
    with gzip.open(out, 'at', encoding='utf-8', newline='') as f:
        w = csv.writer(f)
        if not xong:
            w.writerow(['file_hash', 'period', 'sig', 'n_thu_vien', 'n_ma_doc', 'n_khac'])
        for h in viec:
            per, p = js[h]
            with gzip.open(p, 'rt', encoding='utf-8', errors='ignore') if p.endswith('.gz') else open(p, encoding='utf-8') as fj:
                d = json.load(fj)
            gt = ham.get(h, {})
            c = defaultdict(Counter)
            for nd in (d.get('cfg_graph') or {}).get('nodes') or []:
                tf = nd.get('opcodes_tf') or {}
                if sum(int(v) for v in tf.values()) < MIN_INSNS:
                    continue
                k = sem_key(nd.get('sem_seq') or [])
                if not k:
                    continue
                fa = int(nd['func'], 16)
                c[k][vai(*gt[fa]) if fa in gt else 'khac'] += 1
            for k, cc in c.items():
                w.writerow([h, per, k, cc['thu_vien'], cc['ma_doc'], cc['khac']])
            n += 1
            if time.time() - t0 > a.han:
                print('DUNG_THEO_HAN sau %d tệp' % n, flush=True)
                return
    print('XONG %d tệp, %.0fs' % (n, time.time() - t0), flush=True)


if __name__ == '__main__':
    main()
