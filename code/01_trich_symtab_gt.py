# -*- coding: utf-8 -*-
"""01_trich_symtab_gt.py — Lấy ground truth cấp hàm từ .symtab của TỆP GỐC (chạy trên máy Linux có tệp ELF).

Vì sao dùng được: bộ trích v5.2 tính CFG trên bản sao đã strip ("cách 2"), byte PT_LOAD giữ nguyên, nên địa chỉ
hàm trong JSON (trường nút 'func') trùng với địa chỉ ký hiệu FUNC trong .symtab của tệp gốc. Mô hình không bao giờ
thấy tên hàm -> tên chỉ dùng để ĐÁNH GIÁ, không rò rỉ vào huấn luyện.

Đầu vào : danh_sach_tep_goc.csv (cột file_hash, file_path, period, arch) — do 02_dinh_vi_ham.py --lap-danh-sach tạo,
          hoặc tự lập. file_path là đường dẫn trên máy Linux (trường 'file_path' trong JSON).
Đầu ra  : gt_ham.csv  (file_hash, addr, size, name, vai_tro)
          gt_tep.csv  (file_hash, n_func_sym, n_payload, n_helper, ho_doan, loi)

Vai trò (quy tắc tên, xem QUY_TAC bên dưới; nên kiểm tay ~30 tệp và báo cáo độ khớp):
  payload : logic độc (tấn công DDoS, quét/brute-force, diệt tiến trình đối thủ, kết nối C2, bảng cấu hình mã hoá)
  helper  : hàm tiện ích do tác giả mã độc viết (util_*, rand_*, checksum_*) — không độc tự thân
  khac    : còn lại (chủ yếu libc/uClibc liên kết tĩnh, crt, main...)

Dùng:  pip install pyelftools
       python3 01_trich_symtab_gt.py danh_sach_tep_goc.csv <thu_muc_ra> [--tim-trong /data /mnt/...]
       (--tim-trong: nếu tệp đã bị chuyển chỗ, tìm lại theo tên sha256 trong các thư mục này)
"""
import csv, os, re, sys

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    sys.exit('Cần pyelftools: pip install pyelftools')

QUY_TAC = [
    # ---- Mirai (mã nguồn bị lộ 2016) và đa số biến thể ----
    ('payload', r'^attack_'),
    ('payload', r'^scanner_|^setup_connection$|^get_random_ip$|^consume_|^can_consume$|_auth_entry$|^report_working$|^deobf$'),
    ('payload', r'^killer_|^has_exe_access$|^memory_scan_match$'),
    ('payload', r'^table_|^toggle_obf$'),
    ('payload', r'^resolv_|^resolve_cnc_addr$'),
    ('payload', r'^anti_gdb_entry$|^establish_connection$|^teardown_connection$|^ensure_single_instance$|^unlock_tbl_if_nodebug$'),
    # ---- Gafgyt / Bashlite / Qbot ----
    ('payload', r'^processCmd$|^send(UDP|TCP|STD|HTTP|JUNK|HOLD|CNC|GREIP|GREETH|DNS|VSE)$|^StartTheLelz$|^initConnection$'),
    ('payload', r'^(getOurIP|getRandomPublicIP|getRandomIP|getHost|makeIPPacket|negotiate|matchPrompt|readUntil|connectTimeout|listFork)$'),
    ('payload', r'^(botkill|killer|scanner|telnet|ssh|huawei|realtek|gpon|netis|zyxel|dlink|thinkphp|exploit)', re.I),
    # ---- Tsunami / Kaiten (IRC) ----
    ('payload', r'^(irc_|ircsend|sendirc|_PRIVMSG|_PING|_NICK|_376|_352|_433|move|getspoof|udpflood|tcpflood|synflood|ackflood|pan|tsunami|unknown|spoof)', re.I),
    # ---- helper do tác giả viết ----
    ('helper', r'^util_|^rand_(init|next|str|alphastr)$|^checksum_|^(rand_cmwc|init_rand|csum|tcpcsum|makeRandomStr|sockprintf|fdgets|fdpopen|fdpclose|trim|uppercase)$'),
]
_QT = [(v, re.compile(p, *f)) for v, p, *f in QUY_TAC]


def vai_tro(name):
    for v, rx in _QT:
        if rx.search(name):
            return v
    return 'khac'


def doc_symtab(path):
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        la_arm = elf['e_machine'] == 'EM_ARM'
        out = {}
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection) or sec['sh_type'] != 'SHT_SYMTAB':
                continue
            for s in sec.iter_symbols():
                if s['st_info']['type'] != 'STT_FUNC' or s['st_shndx'] == 'SHN_UNDEF' or not s.name:
                    continue
                a = int(s['st_value'])
                if la_arm:
                    a &= ~1          # bit Thumb
                if a and (a not in out or len(s.name) < len(out[a][1])):
                    out[a] = (int(s['st_size']), s.name)
        return out


_HEX = re.compile(r'[0-9a-fA-F]{64}')


def lap_chi_muc(goc_list):
    """Quét các thư mục gốc, ánh xạ sha256 (64 hex đầu tên tệp) -> đường dẫn. Bỏ qua json/gz/zip/csv/txt/log."""
    m = {}
    for goc in goc_list:
        for dp, _, fs in os.walk(goc):
            for fn in fs:
                if fn.endswith(('.json', '.gz', '.zip', '.csv', '.txt', '.log', '.pkl')):
                    continue
                h = _HEX.match(fn)
                if h:
                    m.setdefault(h.group(0).lower(), os.path.join(dp, fn))
    print('chỉ mục: %d tệp có tên dạng sha256 trong %s' % (len(m), goc_list), flush=True)
    return m


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('danh_sach'); ap.add_argument('thu_muc_ra')
    ap.add_argument('--tim-trong', nargs='*', default=[],
                    help='thư mục để TÌM tệp gốc theo hash khi file_path trong danh sách không còn (vd /data)')
    args = ap.parse_args()
    ds, ra = args.danh_sach, args.thu_muc_ra
    os.makedirs(ra, exist_ok=True)
    with open(ds, newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    if args.tim_trong:
        cm = lap_chi_muc(args.tim_trong)
        thieu = 0
        for r in rows:
            if not os.path.isfile(r['file_path']):
                p = cm.get(r['file_hash'].lower())
                if p:
                    r['file_path'] = p
                else:
                    thieu += 1
        print('không tìm thấy %d/%d tệp' % (thieu, len(rows)), flush=True)
        if thieu == len(rows):
            sys.exit('Không tìm thấy tệp nào — kiểm tra lại thư mục --tim-trong')
    fh = open(os.path.join(ra, 'gt_ham.csv'), 'w', newline='', encoding='utf-8')
    ft = open(os.path.join(ra, 'gt_tep.csv'), 'w', newline='', encoding='utf-8')
    wh = csv.writer(fh); wt = csv.writer(ft)
    wh.writerow(['file_hash', 'addr', 'size', 'name', 'vai_tro'])
    wt.writerow(['file_hash', 'period', 'arch', 'n_func_sym', 'n_payload', 'n_helper', 'ho_doan', 'loi'])
    for i, r in enumerate(rows):
        h, p = r['file_hash'], r['file_path']
        try:
            sy = doc_symtab(p)
            vt = {ad: vai_tro(n) for ad, (_, n) in sy.items()}
            for ad, (sz, n) in sorted(sy.items()):
                wh.writerow([h, ad, sz, n, vt[ad]])
            names = {n for _, n in sy.values()}
            ho = ('mirai' if any(n.startswith('attack_') for n in names) else
                  'gafgyt' if 'processCmd' in names else 'khac')
            wt.writerow([h, r.get('period'), r.get('arch'), len(sy), sum(v == 'payload' for v in vt.values()),
                         sum(v == 'helper' for v in vt.values()), ho, ''])
        except Exception as e:
            wt.writerow([h, r.get('period'), r.get('arch'), 0, 0, 0, '', '%s: %s' % (type(e).__name__, e)])
        if (i + 1) % 200 == 0:
            print('%d/%d' % (i + 1, len(rows)), flush=True)
    fh.close(); ft.close()
    print('XONG', len(rows))


if __name__ == '__main__':
    main()
