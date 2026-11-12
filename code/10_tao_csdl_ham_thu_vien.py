# -*- coding: utf-8 -*-
"""10_tao_csdl_ham_thu_vien.py — CSDL băm hàm thư viện (kiểu FLIRT) cho "library-aware HIN".

Đọc cache của 08_bam_ham.py (bam_ham.csv.gz, bam_tep.csv) + GT. Chỉ dùng tệp GT của các giai đoạn --tu (mặc định 2020):
  băm của hàm 'thư viện' (tên 'khác' có trong >= 10% tệp GT, trừ main) MÀ KHÔNG BAO GIỜ là băm của hàm mã độc
  (payload/helper) -> một dòng/băm. Mặc định CSDL chỉ từ 2020 => dùng cho mọi thí nghiệm trên 2024 mà không rò rỉ
  (dataset-moi 2024 đã loại tệp trùng hash với 2020).
Đầu ra: <out>/ham_thu_vien_<tu>.txt  (dòng đầu '#', sau đó mỗi dòng 'h_op<TAB>so_tep<TAB>ten_vi_du')

Dùng: python 10_tao_csdl_ham_thu_vien.py --gt-dir ket_qua/gt --cache ket_qua/bam_ham --out ket_qua/libaware [--tu 2020]
"""
import argparse, csv, gzip, os, re
from collections import Counter, defaultdict

MA_DOC_THEM = re.compile(r'flood|attack|scanner|killer|watchdog|vse|deobf|random_string|^astd$|^add_strings$|'
                         r'^add_entry$|^rand_alpha_str$|^rand_int$|^rand_next_range$|^getRandom|^makeRandom|huawei|'
                         r'exploit|botkill|^csum$|^trim$|^itoa$|cnc|^do_clone$', re.I)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--gt-dir', required=True); ap.add_argument('--cache', required=True); ap.add_argument('--out', required=True)
    ap.add_argument('--tu', nargs='+', default=['2020']); ap.add_argument('--min-tep', type=int, default=1)
    a = ap.parse_args()
    tep_gt = {r['file_hash']: r['period'] for r in csv.DictReader(open(os.path.join(a.gt_dir, 'gt_tep.csv'), encoding='utf-8'))}
    gt, ten_tep = defaultdict(dict), defaultdict(set)
    for r in csv.DictReader(open(os.path.join(a.gt_dir, 'gt_ham.csv'), encoding='utf-8')):
        vt = r['vai_tro']
        if vt == 'khac' and MA_DOC_THEM.search(r['name']):
            vt = 'payload'
        gt[r['file_hash']][int(r['addr'])] = (r['name'], vt)
        if vt == 'khac':
            ten_tep[r['name']].add(r['file_hash'])
    tv = {n for n, s in ten_tep.items() if len(s) / max(1, len(gt)) >= 0.10 and n != 'main'}
    lib, mal, ten = Counter(), set(), {}
    with gzip.open(os.path.join(a.cache, 'bam_ham.csv.gz'), 'rt', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            h = r['file_hash']
            if r['period'] not in a.tu or tep_gt.get(h) not in a.tu:
                continue
            g = gt.get(h, {}).get(int(r['addr']))
            if not g:
                continue
            n, vt = g
            if vt in ('payload', 'helper'):
                mal.add(r['h_op'])
            elif n in tv:
                lib[r['h_op']] += 1
                ten.setdefault(r['h_op'], n)
    keep = {hh: c for hh, c in lib.items() if hh not in mal and c >= a.min_tep}
    os.makedirs(a.out, exist_ok=True)
    out = os.path.join(a.out, 'ham_thu_vien_%s.txt' % '_'.join(a.tu))
    with open(out, 'w', encoding='utf-8') as f:
        f.write('# CSDL băm hàm thư viện từ GT %s: %d băm (bỏ %d băm trùng hàm mã độc). Băm = md5(arch#ops)[:16] như 08_bam_ham.py\n'
                % ('+'.join(a.tu), len(keep), len([h for h in lib if h in mal])))
        for hh, c in sorted(keep.items(), key=lambda t: -t[1]):
            f.write('%s\t%d\t%s\n' % (hh, c, ten[hh]))
    print('đã ghi', out, '|', len(keep), 'băm')


if __name__ == '__main__':
    main()
