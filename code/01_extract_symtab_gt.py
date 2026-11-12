# -*- coding: utf-8 -*-
"""01_extract_symtab_gt.py: function-level ground truth from the .symtab of the ORIGINAL (unstripped) files.
Runs on a Linux machine that holds the ELF binaries.

Why this works: the static extractor v5.2 computes the CFG on a stripped copy of each file and leaves the PT_LOAD
bytes unchanged, so the function addresses in the JSON (node field 'func') coincide with the addresses of the FUNC
symbols in the .symtab of the original file. The models never see function names; names are used for EVALUATION
only and cannot leak into training.

Input : original_files.csv (columns file_hash, file_path, period, arch), written by
        02_localize_functions.py --build-file-list or prepared by hand. file_path is the path on the Linux machine
        (field 'file_path' of the JSON).
Output: gt_functions.csv (file_hash, addr, size, name, role)
        gt_files.csv     (file_hash, period, arch, n_func_sym, n_payload, n_helper, family, error)

Roles (name rules, see NAME_RULES below; a manual check of about 30 files is recommended):
  payload : malicious logic (DDoS attacks, scanning/brute forcing, killing competing processes, C2 connection,
            encrypted configuration table)
  helper  : utility functions written by the malware author (util_*, rand_*, checksum_*), not malicious by themselves
  other   : everything else (mostly statically linked libc/uClibc, crt, main, ...)

Usage:  pip install pyelftools
        python3 01_extract_symtab_gt.py original_files.csv <output_dir> [--search-in /data /mnt/...]
        (--search-in: if files have been moved, look them up by their sha256 name in these folders)
"""
import csv, os, re, sys

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:
    sys.exit('pyelftools is required: pip install pyelftools')

NAME_RULES = [
    # ---- Mirai (source code leaked in 2016) and most of its variants ----
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
    # ---- helpers written by the author ----
    ('helper', r'^util_|^rand_(init|next|str|alphastr)$|^checksum_|^(rand_cmwc|init_rand|csum|tcpcsum|makeRandomStr|sockprintf|fdgets|fdpopen|fdpclose|trim|uppercase)$'),
]
_RULES = [(v, re.compile(p, *f)) for v, p, *f in NAME_RULES]


def role_of(name):
    for v, rx in _RULES:
        if rx.search(name):
            return v
    return 'other'


def read_symtab(path):
    with open(path, 'rb') as f:
        elf = ELFFile(f)
        is_arm = elf['e_machine'] == 'EM_ARM'
        out = {}
        for sec in elf.iter_sections():
            if not isinstance(sec, SymbolTableSection) or sec['sh_type'] != 'SHT_SYMTAB':
                continue
            for s in sec.iter_symbols():
                if s['st_info']['type'] != 'STT_FUNC' or s['st_shndx'] == 'SHN_UNDEF' or not s.name:
                    continue
                a = int(s['st_value'])
                if is_arm:
                    a &= ~1          # clear the Thumb bit
                if a and (a not in out or len(s.name) < len(out[a][1])):
                    out[a] = (int(s['st_size']), s.name)
        return out


_HEX = re.compile(r'[0-9a-fA-F]{64}')


def build_index(roots):
    """Walk the given folders and map sha256 (leading 64 hex digits of the file name) -> path.
    Files ending in json/gz/zip/csv/txt/log/pkl are ignored."""
    m = {}
    for root in roots:
        for dp, _, fs in os.walk(root):
            for fn in fs:
                if fn.endswith(('.json', '.gz', '.zip', '.csv', '.txt', '.log', '.pkl')):
                    continue
                h = _HEX.match(fn)
                if h:
                    m.setdefault(h.group(0).lower(), os.path.join(dp, fn))
    print('index: %d files with sha256 names in %s' % (len(m), roots), flush=True)
    return m


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('file_list'); ap.add_argument('output_dir')
    ap.add_argument('--search-in', nargs='*', default=[],
                    help='folders in which to LOOK UP original files by hash when the file_path of the list no longer exists (e.g. /data)')
    args = ap.parse_args()
    lst, out_dir = args.file_list, args.output_dir
    os.makedirs(out_dir, exist_ok=True)
    with open(lst, newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    if args.search_in:
        idx = build_index(args.search_in)
        missing = 0
        for r in rows:
            if not os.path.isfile(r['file_path']):
                p = idx.get(r['file_hash'].lower())
                if p:
                    r['file_path'] = p
                else:
                    missing += 1
        print('%d/%d files not found' % (missing, len(rows)), flush=True)
        if missing == len(rows):
            sys.exit('No file was found; check the --search-in folders')
    fh = open(os.path.join(out_dir, 'gt_functions.csv'), 'w', newline='', encoding='utf-8')
    ft = open(os.path.join(out_dir, 'gt_files.csv'), 'w', newline='', encoding='utf-8')
    wh = csv.writer(fh); wt = csv.writer(ft)
    wh.writerow(['file_hash', 'addr', 'size', 'name', 'role'])
    wt.writerow(['file_hash', 'period', 'arch', 'n_func_sym', 'n_payload', 'n_helper', 'family', 'error'])
    for i, r in enumerate(rows):
        h, p = r['file_hash'], r['file_path']
        try:
            sy = read_symtab(p)
            rl = {ad: role_of(n) for ad, (_, n) in sy.items()}
            for ad, (sz, n) in sorted(sy.items()):
                wh.writerow([h, ad, sz, n, rl[ad]])
            names = {n for _, n in sy.values()}
            fam = ('mirai' if any(n.startswith('attack_') for n in names) else
                   'gafgyt' if 'processCmd' in names else 'other')
            wt.writerow([h, r.get('period'), r.get('arch'), len(sy), sum(v == 'payload' for v in rl.values()),
                         sum(v == 'helper' for v in rl.values()), fam, ''])
        except Exception as e:
            wt.writerow([h, r.get('period'), r.get('arch'), 0, 0, 0, '', '%s: %s' % (type(e).__name__, e)])
        if (i + 1) % 200 == 0:
            print('%d/%d' % (i + 1, len(rows)), flush=True)
    fh.close(); ft.close()
    print('DONE', len(rows))


if __name__ == '__main__':
    main()
