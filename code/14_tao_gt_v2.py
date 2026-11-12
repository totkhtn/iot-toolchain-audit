# -*- coding: utf-8 -*-
"""14_tao_gt_v2.py — Ground truth v2: tách "mã do tác giả mã độc viết" khỏi "mã thư viện/runtime".

GT v1 (01_trich_symtab_gt.py) chỉ đánh dấu payload/helper theo quy tắc TÊN, nên `main` của mã độc (vòng lặp C2 của
Mirai), module khai thác (`nuuo_init`, `httpd_serve`, `update_bins`...), hàm gửi gói tự viết (`SendUDP`, `audp`...) bị
xếp "khác" cùng với libc. GT v2 gán vai trò cho MỌI hàm có ký hiệu trong mã độc:

  thu_vien : tên có trong danh sách hàm libc/libm/libpthread/libresolv/librt/libcrypt/libgcc (glibc, `nm` của các
             thư viện tĩnh), HOẶC tên bắt đầu bằng '_' (nội bộ libc/uClibc/crt/libgcc), HOẶC tên có trong >= 10% tệp GT
             (thư viện dùng chung như 05/08), HOẶC băm hàm khớp CSDL hàm thư viện (08_bam_ham.py, mọi tệp GT)
  payload  : như v1 (quy tắc tên + MA_DOC_THEM)  ┐
  helper   : như v1                               ├─ "mã tác giả"
  tac_gia  : còn lại (kể cả `main`)               ┘

Đầu ra (thư mục --out, dùng thay ket_qua/gt bằng `--gt-dir ket_qua/gt_v2` cho 02_dinh_vi_ham.py):
  gt_ham.csv : file_hash, addr, size, name, vai_tro, vai_tro_chi_tiet
               vai_tro = 'payload' cho payload VÀ tac_gia (dương tính = mã tác giả không phải tiện ích),
                         'helper', 'khac' (= thư viện)   -> 02 dùng được nguyên trạng
  gt_tep.csv : như v1, n_payload tính lại
  TOM_TAT_GT_v2.md, mau_tac_gia.csv (100 tên tac_gia phổ biến nhất để rà tay)

Dùng: python3 14_tao_gt_v2.py --gt-dir ket_qua/gt --bam ket_qua/bam_ham --libc-names ket_qua/gt_v2/ten_libc_glibc.txt --out ket_qua/gt_v2
"""
import argparse, csv, gzip, os, re
from collections import Counter, defaultdict

MA_DOC_THEM = re.compile(r'flood|attack|scanner|killer|watchdog|vse|deobf|random_string|^astd$|^add_strings$|'
                         r'^add_entry$|^rand_alpha_str$|^rand_int$|^rand_next_range$|^getRandom|^makeRandom|huawei|'
                         r'exploit|botkill|^csum$|^trim$|^itoa$|cnc|^do_clone$', re.I)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--gt-dir', required=True); ap.add_argument('--bam', required=True)
    ap.add_argument('--libc-names', required=True); ap.add_argument('--out', required=True)
    a = ap.parse_args()
    libc = {l.strip() for l in open(a.libc_names, encoding='utf-8') if l.strip() and not l.startswith('#')}
    rows = list(csv.DictReader(open(os.path.join(a.gt_dir, 'gt_ham.csv'), encoding='utf-8')))
    tep = list(csv.DictReader(open(os.path.join(a.gt_dir, 'gt_tep.csv'), encoding='utf-8')))
    n_tep = len({r['file_hash'] for r in rows})
    # vai trò v1 (có MA_DOC_THEM) + tên thư viện dùng chung (>= 10% tệp, như 05/08)
    for r in rows:
        if r['vai_tro'] == 'khac' and MA_DOC_THEM.search(r['name']):
            r['vai_tro'] = 'payload'
    ten_tep = defaultdict(set)
    for r in rows:
        if r['vai_tro'] == 'khac':
            ten_tep[r['name']].add(r['file_hash'])
    chung = {n for n, s in ten_tep.items() if len(s) / n_tep >= 0.10 and n != 'main'}
    # băm hàm của mọi tệp GT + CSDL băm thư viện (thư viện dùng chung, không trùng băm hàm mã độc)
    h_of = {}
    with gzip.open(os.path.join(a.bam, 'bam_ham.csv.gz'), 'rt', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            h_of[(r['file_hash'], r['addr'])] = r['h_op']
    lib_h, mal_h = set(), set()
    for r in rows:
        hh = h_of.get((r['file_hash'], r['addr']))
        if hh is None:
            continue
        if r['vai_tro'] in ('payload', 'helper'):
            mal_h.add(hh)
        elif r['name'] in chung:
            lib_h.add(hh)
    lib_h -= mal_h
    ly_do = Counter()
    for r in rows:
        v = r['vai_tro']
        if v in ('payload', 'helper'):
            r['vai_tro_chi_tiet'] = v
            continue
        n = r['name']
        if n in libc:
            r['vai_tro_chi_tiet'], why = 'thu_vien', 'ten_libc'
        elif n.startswith('_'):
            r['vai_tro_chi_tiet'], why = 'thu_vien', 'gach_duoi'
        elif n in chung:
            r['vai_tro_chi_tiet'], why = 'thu_vien', 'ten_chung_10pct'
        elif h_of.get((r['file_hash'], r['addr'])) in lib_h:
            r['vai_tro_chi_tiet'], why = 'thu_vien', 'bam_thu_vien'
        else:
            r['vai_tro_chi_tiet'], why = 'tac_gia', 'con_lai'
        ly_do[why] += 1
    for r in rows:
        r['vai_tro'] = {'payload': 'payload', 'tac_gia': 'payload', 'helper': 'helper', 'thu_vien': 'khac'}[r['vai_tro_chi_tiet']]
    os.makedirs(a.out, exist_ok=True)
    with open(os.path.join(a.out, 'gt_ham.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['file_hash', 'addr', 'size', 'name', 'vai_tro', 'vai_tro_chi_tiet'])
        w.writeheader(); w.writerows({k: r[k] for k in w.fieldnames} for r in rows)
    npay = Counter(r['file_hash'] for r in rows if r['vai_tro'] == 'payload')
    for t in tep:
        t['n_payload'] = npay.get(t['file_hash'], 0)
    with open(os.path.join(a.out, 'gt_tep.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(tep[0].keys())); w.writeheader(); w.writerows(tep)
    ct = Counter(r['vai_tro_chi_tiet'] for r in rows)
    tg = Counter(r['name'] for r in rows if r['vai_tro_chi_tiet'] == 'tac_gia')
    with open(os.path.join(a.out, 'mau_tac_gia.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['name', 'so_tep'])
        for n, c in tg.most_common(100):
            w.writerow([n, c])
    L = ['# Ground truth v2 (%d tệp, %d hàm)' % (n_tep, len(rows)), '',
         '| Vai trò chi tiết | Số hàm |', '|---|---|'] + ['| %s | %d |' % (k, v) for k, v in ct.most_common()] + \
        ['', 'Lý do xếp thư viện / tác giả (chỉ hàm không phải payload/helper v1):', ''] + \
        ['- %s: %d' % (k, v) for k, v in ly_do.most_common()] + \
        ['', 'Tên `tac_gia` phổ biến nhất (rà tay — nếu thấy tên libc thì bổ sung vào danh sách libc):', '',
         ', '.join('%s (%d)' % (n, c) for n, c in tg.most_common(60))]
    open(os.path.join(a.out, 'TOM_TAT_GT_v2.md'), 'w', encoding='utf-8').write('\n'.join(L) + '\n')
    print('\n'.join(L))


if __name__ == '__main__':
    main()
