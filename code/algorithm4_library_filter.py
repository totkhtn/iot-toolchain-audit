# -*- coding: utf-8 -*-
"""algorithm4_library_filter.py: reference implementation of the library-related parts of step 4 (library-aware training and post hoc filtering).

These functions are copied from the training scripts used for the paper (the detector code itself is not part of
this repository, see docs/TRAINING.md). They operate on the per-file CFG of the static extractor:
cfg = {'nodes': [{'id', 'addr', 'func', 'ops_seq', ...}], 'edges': [...], 'call_edges': [...]}.

  load_library_db(path)                     -> set of hashes (data/library_db/library_functions_2020.txt)
  function_hash(arch, nodes)                -> MD5(arch + '#' + opcode sequence of all blocks in address order)[:16]
  filter_library_functions(cfg, arch, D)    -> mode (d): CFG without the blocks of library functions, and counts
  symtab_mask(n_lib, n_mal, ...)            -> mode (b): signatures whose score is set to zero
  benign_static_mask(frac, thr=0.05)        -> mode (a): signatures present in >= 5% of static benign training files
Mode (c) is the union of (a) and (b); mode (e) applies filter_library_functions only when explaining.
"""
import hashlib
from collections import defaultdict


def load_library_db(path):
    with open(path, encoding='utf-8') as f:
        return {l.split('\t')[0].strip() for l in f if l.strip() and not l.startswith('#')}


def function_hash(arch, nodes):
    ops = '/'.join(','.join(nd.get('ops_seq') or []) for nd in sorted(nodes, key=lambda x: x.get('addr', 0)))
    return hashlib.md5((arch + '#' + ops).encode()).hexdigest()[:16]


def filter_library_functions(cfg, arch, D):
    """Remove the blocks of functions whose hash is in D, and the edges that touch them.
    Returns (filtered cfg, (blocks removed, blocks, functions removed, functions))."""
    nodes = cfg.get('nodes') or []
    F = defaultdict(list)
    for nd in nodes:
        if isinstance(nd, dict) and nd.get('func') is not None:
            F[nd['func']].append(nd)
    drop = {fa for fa, nds in F.items() if function_hash(arch, nds) in D}
    if not drop:
        return cfg, (0, len(nodes), 0, len(F))
    keep = [nd for nd in nodes if not (isinstance(nd, dict) and nd.get('func') in drop)]
    ids = {nd.get('id') for nd in keep if isinstance(nd, dict)}

    def _edges(E):
        out = []
        for e in E or []:
            a, b = (e.get('source'), e.get('target')) if isinstance(e, dict) else ((e[0], e[1]) if len(e) >= 2 else (None, None))
            if a in ids and b in ids:
                out.append(e)
        return out
    edges, calls = _edges(cfg.get('edges')), _edges(cfg.get('call_edges'))
    out = dict(cfg, nodes=keep, edges=edges, call_edges=calls, num_nodes=len(keep), num_edges=len(edges),
               num_call_edges=len(calls), num_functions=len(F) - len(drop))
    return out, (len(nodes) - len(keep), len(nodes), len(drop), len(F))


def symtab_mask(n_lib, n_mal, min_files=3, max_mal_frac=0.10):
    """n_lib[e] / n_mal[e]: number of unstripped TRAINING malware files in which signature e occurs in a library
    function / in a payload or helper function (counts from data/signature_roles/signature_roles.csv.gz restricted to
    the training files of the split). Returns the set of signatures to mask."""
    out = set()
    for e in set(n_lib) | set(n_mal):
        nl, nm = n_lib.get(e, 0), n_mal.get(e, 0)
        if nl >= min_files and nm <= max_mal_frac * (nl + nm):
            out.add(e)
    return out


def benign_static_mask(frac_in_static_benign, thr=0.05):
    """frac_in_static_benign[e]: fraction of statically linked benign training files that contain signature e."""
    return {e for e, fr in frac_in_static_benign.items() if fr >= thr}
