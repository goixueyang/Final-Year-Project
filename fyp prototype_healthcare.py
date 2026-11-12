# ==========================================
# 0. IMPORTS, CONSTANTS & RESOURCE HELPERS
# ==========================================
import gc
import hashlib
import math
import os
import random
import statistics
import time

import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import pandas as pd
import psutil
import pyswarms as ps
import tenseal as ts

CSV_PATH     = 'job_M8PVI8UsVGIq47DBk-AVGYIrMFw8.csv'
BASE_DEGREE  = 32768                               # baseline CKKS ring degree
BASE_CHAIN   = [60, 40, 40, 40, 40, 40, 60]        # baseline coefficient modulus chain
BASE_SLOTS   = BASE_DEGREE // 2                    # slots per baseline ciphertext
SLOTS_OF     = {8192: 4096, 16384: 8192, 32768: 16384}   # ring degree -> slots
OPT_CHAIN    = [60, 40, 40, 60]                    # 200 bits <= 218 (128-bit security at N=8192)
SCALE        = 2 ** 40
W_FHE, W_MHT, W_PROOF = 1.0, 0.3, 0.1              # PSO objective weights (relative to baseline)
AUDIT_TRIALS = 100                                 # integrity benchmark trials
TAMPER_RATE  = 0.3                                 # fraction of trials that are tampered
RUN_ABLATION = True                                # extra run: baseline N with the short chain
MB           = 1024 * 1024

process = psutil.Process(os.getpid())

def rss():
    return process.memory_info().rss

def cpu_seconds():
    t = process.cpu_times()
    return t.user + t.system

def reduction_pct(base, opt):
    return (base - opt) / base * 100 if base else 0.0

# ==========================================
# 1. LOAD & PREPROCESS DATASET
# ==========================================
df = pd.read_csv(CSV_PATH)

# Automatically detect initial numeric and text columns based on data types
original_numeric_cols = df.select_dtypes(include=['number']).columns.tolist()
text_cols = df.select_dtypes(include=['object', 'string', 'category']).columns.tolist()

print(f"Detected numeric columns: {original_numeric_cols}")
print(f"Detected text columns: {text_cols}")

# Clean numeric fields (handle missing values)
for col in original_numeric_cols:
    df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

# Label-encode text columns into integer codes (missing -> 0) for safe FHE handling
encoded_text_cols = []
for col in text_cols:
    df[col] = df[col].fillna("NA").astype(str).str.strip()
    df[col] = df[col].astype('category').cat.codes
    df[col] = df[col].apply(lambda x: 0 if x < 0 else x)
    encoded_text_cols.append(col)

# Unified pipeline column list
numeric_cols = original_numeric_cols + encoded_text_cols
n_rows = len(df)

print(f"\n[*] Total columns now processed under FHE pipeline: {len(numeric_cols)}")
print(f"    - Numeric: {original_numeric_cols}")
print(f"    - Encoded Text: {encoded_text_cols}")

print("\n--- Processed Dataset Preview (First 5 Rows) ---")
print(df.head(5))

if not numeric_cols:
    raise SystemExit("No numeric columns found to encrypt.")
if n_rows > BASE_SLOTS:
    raise SystemExit(f"Baseline packs one column per ciphertext: rows ({n_rows}) must be <= {BASE_SLOTS}.")

col_arrays = {c: df[c].to_numpy(dtype=float) for c in numeric_cols}

# ==========================================
# 2. MERKLE HASH TREE (MHT) HELPERS
# One k-ary implementation: k=2 is the classic binary tree (baseline),
# k>2 is the PSO-optimized shallower tree. Only the arity differs.
# ==========================================
def row_leaf_hashes(frame):
    return [hashlib.sha256("".join(str(v) for v in r).encode()).digest()
            for r in frame.itertuples(index=False)]

def build_kary_merkle(leaves, k):
    """Returns all levels, bottom (leaves) -> top (root)."""
    levels = [leaves]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        levels.append([hashlib.sha256(b"".join(cur[i:i + k])).digest()
                       for i in range(0, len(cur), k)])
    return levels

def verify_leaf(levels, idx, k):
    """Recompute the path from one leaf to the root using stored sibling hashes."""
    h = levels[0][idx]
    for lvl in levels[:-1]:
        start = (idx // k) * k
        group = list(lvl[start:start + k])
        group[idx - start] = h
        h = hashlib.sha256(b"".join(group)).digest()
        idx //= k
    return h == levels[-1][0]

def locate_tampered_leaf(base_levels, new_levels, k):
    """Walk from the root down, following the child whose hash changed."""
    idx = 0
    for lvl in range(len(base_levels) - 2, -1, -1):
        start = idx * k
        for c in range(start, min(start + k, len(base_levels[lvl]))):
            if base_levels[lvl][c] != new_levels[lvl][c]:
                idx = c
                break
    return idx

def arity_for_depth(d):
    """Target depth d over n leaves -> branching factor k (k^d >= n)."""
    return max(2, math.ceil(n_rows ** (1.0 / d)))

def ciphertext_root(serialized_by_col, k):
    """Merkle root over the serialized ciphertexts (one leaf per encrypted column)."""
    leaves = [hashlib.sha256(serialized_by_col[c]).digest() for c in numeric_cols]
    return build_kary_merkle(leaves, k)[-1][0]

print("\n--- [Merkle Hash Tree Initialization] ---")
leaf_hashes = row_leaf_hashes(df)
binary_levels = build_kary_merkle(leaf_hashes, 2)
print(f"[*] Baseline (binary) Merkle Root Computed: {binary_levels[-1][0].hex()}")

# ==========================================
# 3. PLAINTEXT BASELINE PERFORMANCE
# ==========================================
print("\n--- [Plaintext Baseline Performance] ---")
t0 = time.perf_counter()
plaintext_sums = {col: df[col].sum() for col in numeric_cols}
plain_duration = time.perf_counter() - t0
print(f"Plaintext Total Execution Time (All {len(numeric_cols)} Columns): {plain_duration:.4f} seconds")

# ==========================================
# 4. BASELINE CKKS CONTEXT + ENCRYPTED DATASET (used by previews & attack demos)
# ==========================================
def new_context(N, chain):
    ctx = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=N, coeff_mod_bit_sizes=chain)
    ctx.global_scale = SCALE
    ctx.generate_galois_keys()
    return ctx

def timed_context(N, chain):
    """Create a context and record one-time key-setup time, CPU time and memory."""
    rss0, cpu0, t0 = rss(), cpu_seconds(), time.perf_counter()
    ctx = new_context(N, chain)
    return ctx, {"time": time.perf_counter() - t0,
                 "cpu": cpu_seconds() - cpu0,
                 "mem_mb": (rss() - rss0) / MB}

context, base_setup = timed_context(BASE_DEGREE, BASE_CHAIN)

encrypted_dataset = {col: ts.ckks_vector(context, df[col].tolist()) for col in numeric_cols}
intercepted_transit_channel = {col: vec.serialize() for col, vec in encrypted_dataset.items()}  # for MITM demos

print("--- Encrypted Dataset Preview (First 5 Rows) ---")
for i in range(5):
    print(f"Row Group {i} (Column Ciphertexts): "
          f"{ {col: str(encrypted_dataset[col]) for col in numeric_cols} }")
print(f"Status: Successfully encrypted {len(encrypted_dataset)} columns across all {n_rows} rows.")

print("\n--- Decrypted Dataset Preview (First 5 Rows) ---")
decrypted_df_preview = pd.DataFrame({
    col: encrypted_dataset[col].decrypt()[:5] for col in numeric_cols
}).round(4)
print(decrypted_df_preview)

# ==========================================
# 5. FHE PIPELINE (identical code path for baseline and PSO)
# ==========================================
def run_fhe(ctx, slots, cols=None):
    """Single run: encrypt -> homomorphic sum -> decrypt.
    Returns times, CPU time, peak memory increase, ciphertext payload and accuracy."""
    cols = cols or numeric_cols
    n_blocks = math.ceil(n_rows / slots)
    start_rss = peak_rss = rss()

    cpu0 = cpu_seconds()
    t0 = time.perf_counter()
    blocks = []
    for b in range(n_blocks):
        lo, hi = b * slots, (b + 1) * slots
        blocks.append({c: ts.ckks_vector(ctx, col_arrays[c][lo:hi].tolist()) for c in cols})
    t1 = time.perf_counter()
    peak_rss = max(peak_rss, rss())
    sums = [{c: blk[c].sum() for c in cols} for blk in blocks]
    t2 = time.perf_counter()
    peak_rss = max(peak_rss, rss())
    for blk in blocks:
        for c in cols:
            blk[c].decrypt()
    t3 = time.perf_counter()
    cpu1 = cpu_seconds()
    peak_rss = max(peak_rss, rss())

    # Untimed checks: accuracy of the block sums and total ciphertext payload
    decrypted_sums = {c: sum(s[c].decrypt()[0] for s in sums) for c in cols}
    max_err = max(abs(decrypted_sums[c] - float(plaintext_sums[c])) / max(abs(float(plaintext_sums[c])), 1.0)
                  for c in cols)
    payload = sum(len(blk[c].serialize()) for blk in blocks for c in cols)

    return {"enc": t1 - t0, "comp": t2 - t1, "dec": t3 - t2, "total": t3 - t0,
            "cpu": cpu1 - cpu0, "mem_mb": (peak_rss - start_rss) / MB,
            "payload_mb": payload / MB, "n_ct": n_blocks * len(cols),
            "err": max_err, "sums": decrypted_sums}

# ==========================================
# 6. PARTICLE SWARM OPTIMIZATION (PSO)
# Decision variables : (1) block size   (2) Merkle tree depth
# Cost function      : REAL measured time (no hand-written formula)
#
# A block must fit inside the CKKS slots (N/2), so block size is tied to the
# ring degree N: smaller block -> smaller N -> much cheaper ciphertexts, but
# more of them. PSO finds the best trade-off.
# ==========================================
print("\n--- [Phase 1: Running PSO for Framework Optimization] ---")

def degree_for_block(block_size):
    for N in (8192, 16384, 32768):
        if SLOTS_OF[N] >= block_size:
            return N
    return 32768

_fhe_cache = {}
def fhe_cost_for_degree(N):
    if N not in _fhe_cache:
        ctx = new_context(N, OPT_CHAIN)
        r = run_fhe(ctx, SLOTS_OF[N], cols=[numeric_cols[0]])
        _fhe_cache[N] = r["total"] * len(numeric_cols)      # one column -> all columns
        del ctx
        gc.collect()
    return _fhe_cache[N]

_mht_cache = {}
def mht_metrics(k):
    if k not in _mht_cache:
        sample = random.sample(range(n_rows), min(200, n_rows))
        t0 = time.perf_counter()
        levels = build_kary_merkle(leaf_hashes, k)
        t1 = time.perf_counter()
        assert all(verify_leaf(levels, i, k) for i in sample)
        t2 = time.perf_counter()
        depth = len(levels) - 1
        _mht_cache[k] = {"time": t2 - t0, "depth": depth, "proof_bytes": depth * (k - 1) * 32}
    return _mht_cache[k]

# Baselines used to normalise the PSO objective
base_fhe = run_fhe(context, BASE_SLOTS, cols=[numeric_cols[0]])["total"] * len(numeric_cols)
base_mht = mht_metrics(2)

def pso_cost(x):
    costs = np.zeros(x.shape[0])
    for i in range(x.shape[0]):
        N = degree_for_block(int(round(x[i, 0])))
        m = mht_metrics(arity_for_depth(int(round(x[i, 1]))))
        costs[i] = (W_FHE * fhe_cost_for_degree(N) / base_fhe
                    + W_MHT * m["time"] / base_mht["time"]
                    + W_PROOF * m["proof_bytes"] / base_mht["proof_bytes"])
    return costs

bounds = (np.array([4096, 2]), np.array([16384, 14]))      # [block size, Merkle depth]
optimizer = ps.single.GlobalBestPSO(n_particles=20, dimensions=2,
                                    options={'c1': 1.5, 'c2': 1.5, 'w': 0.7}, bounds=bounds)
best_cost, best_position = optimizer.optimize(pso_cost, iters=20, verbose=False)

best_N             = degree_for_block(int(round(best_position[0])))
optimal_block_size = SLOTS_OF[best_N]                      # effective block size (fills all slots)
best_arity         = arity_for_depth(int(round(best_position[1])))
mht_opt            = mht_metrics(best_arity)
optimal_mht_depth  = mht_opt["depth"]

print("[+] PSO Optimization Complete:")
print(f"    - Optimal Block Size : {optimal_block_size} rows  (ring degree N = {best_N})")
print(f"    - Optimal MHT Depth  : {optimal_mht_depth} levels (arity = {best_arity})")
print(f"    - Best normalised cost (baseline = {W_FHE + W_MHT + W_PROOF:.1f}): {best_cost:.3f}")

# ==========================================
# 7. PHASE 2: REAL FHE EXECUTION ON ALL ROWS
# ==========================================
print(f"\n--- [Phase 2: Real FHE on ALL {n_rows} rows | block={optimal_block_size}, N={best_N}] ---")

ctx_opt, opt_setup = timed_context(best_N, OPT_CHAIN)
# The smaller pipeline runs first, so memory the allocator keeps from the larger baseline
# run can't flatter PSO: the comparison is conservative.
res_opt  = run_fhe(ctx_opt, optimal_block_size)
res_base = run_fhe(context, BASE_SLOTS)
del ctx_opt
gc.collect()

res_abl = None
if RUN_ABLATION:       # isolates the effect of the shorter modulus chain at the SAME ring degree
    ctx_abl = new_context(BASE_DEGREE, OPT_CHAIN)
    res_abl = run_fhe(ctx_abl, BASE_SLOTS)
    del ctx_abl
    gc.collect()

print("\n--- Encrypted Dataset Summary (All Encrypted Columns) ---\n")
for col in numeric_cols:
    print(f"Column: {col}")
    print(f"  Actual Plaintext Sum:        ${float(plaintext_sums[col]):,.2f}")
    print(f"  Baseline Encrypted Sum:      ${res_base['sums'][col]:,.2f}")
    print(f"  PSO-Optimized Encrypted Sum: ${res_opt['sums'][col]:,.2f}\n")

# ==========================================
# 8. MHT INTEGRITY DETECTION BENCHMARK
# Baseline binary tree  vs  PSO-optimized k-ary tree, on identical trials
# ==========================================
print("--- [MHT Integrity Benchmark: Binary Tree vs PSO-Optimized Tree] ---")
assert row_leaf_hashes(df) == leaf_hashes, "Leaf hashing is not reproducible"

audit_col = original_numeric_cols[0] if original_numeric_cols else numeric_cols[0]
trial_plan = []                                   # tampered row index, or None for a clean trial
for _ in range(AUDIT_TRIALS):
    tampered = random.random() < TAMPER_RATE
    trial_plan.append(random.randint(0, n_rows - 1) if tampered else None)
n_tampered = sum(r is not None for r in trial_plan)
n_clean = AUDIT_TRIALS - n_tampered

trees = {"Binary (baseline)": {"k": 2, "levels": binary_levels},
         "PSO-optimized":     {"k": best_arity, "levels": build_kary_merkle(leaf_hashes, best_arity)}}
for t in trees.values():
    t.update(root=t["levels"][-1][0], depth=len(t["levels"]) - 1, correct=0, detected=0,
             false_alarm=0, localized=0, build_times=[], latencies=[])

for malicious_row in trial_plan:
    audit_df = df.copy()
    if malicious_row is not None:
        # keep the column dtype so ONLY the targeted row's leaf changes
        delta = 9999 if pd.api.types.is_integer_dtype(audit_df[audit_col]) else 9999.99
        audit_df.loc[audit_df.index[malicious_row], audit_col] += delta

    t0 = time.perf_counter()
    audit_leaves = row_leaf_hashes(audit_df)               # shared cost for both trees
    leaf_time = time.perf_counter() - t0

    for t in trees.values():
        t1 = time.perf_counter()
        new_levels = build_kary_merkle(audit_leaves, t["k"])
        verified = (new_levels[-1][0] == t["root"])
        build_time = time.perf_counter() - t1
        t["build_times"].append(build_time)
        t["latencies"].append(leaf_time + build_time)

        if malicious_row is not None:
            if not verified:
                t["correct"] += 1
                t["detected"] += 1
                if locate_tampered_leaf(t["levels"], new_levels, t["k"]) == malicious_row:
                    t["localized"] += 1
        elif verified:
            t["correct"] += 1
        else:
            t["false_alarm"] += 1

for t in trees.values():
    t["accuracy"] = t["correct"] / AUDIT_TRIALS * 100
    t["avg_build"] = statistics.mean(t["build_times"])
    t["avg_latency"] = statistics.mean(t["latencies"])

# Without MHT nothing is verified: every tamper is accepted, only clean trials "pass"
accuracy_without_mht = n_clean / AUDIT_TRIALS * 100
bin_t, opt_t = trees["Binary (baseline)"], trees["PSO-optimized"]

# ==========================================
# 9. PERFORMANCE METRICS & THESIS OVERHEAD REPORT
# ==========================================
def row(label, base, opt, fmt=".4f", reduce=True):
    red = f"{reduction_pct(base, opt):.1f}%" if reduce else "-"
    print(f"{label:<38}{base:>14{fmt}}{opt:>16{fmt}}{red:>10}")

def overhead(t):
    return (t - plain_duration) / plain_duration * 100 if plain_duration > 0 else 0.0

print("\n" + "=" * 78)
print("             PERFORMANCE METRICS & THESIS OVERHEAD REPORT")
print("=" * 78)
print(f"Dataset: {n_rows} rows x {len(numeric_cols)} columns | single run | "
      f"plaintext time (T_plain): {plain_duration:.4f} s")
print(f"{'':<38}{'Baseline':>14}{'PSO-Optimized':>16}{'Reduction':>10}")
print("-" * 78)
print(f"{'CONFIGURATION':<38}")
print(f"{'  Ring degree N':<38}{BASE_DEGREE:>14}{best_N:>16}")
print(f"{'  Coefficient modulus chain (bits)':<38}{sum(BASE_CHAIN):>14}{sum(OPT_CHAIN):>16}")
print(f"{'  Block size (rows / ciphertext)':<38}{BASE_SLOTS:>14}{optimal_block_size:>16}")
print(f"{'  Number of ciphertexts':<38}{res_base['n_ct']:>14}{res_opt['n_ct']:>16}")
print("-" * 78)
print(f"{'HE TIME (s)':<38}")
row("  Key setup (one-time)",            base_setup["time"], opt_setup["time"])
row("  Encryption (T_enc)",              res_base["enc"],  res_opt["enc"])
row("  Homomorphic comp. (T_comp)",      res_base["comp"], res_opt["comp"])
row("  Decryption (T_dec)",              res_base["dec"],  res_opt["dec"])
row("  Total end-to-end HE (T_total)",   res_base["total"], res_opt["total"])
print("-" * 78)
print(f"{'OVERHEAD vs PLAINTEXT (%)':<38}")
row("  Encryption overhead",             overhead(res_base["enc"]),   overhead(res_opt["enc"]),   ".2f")
row("  End-to-end HE overhead",          overhead(res_base["total"]), overhead(res_opt["total"]), ".2f")
print("-" * 78)
print(f"{'RESOURCES':<38}")
row("  CPU time per run (s)",            res_base["cpu"],  res_opt["cpu"])
row("  Peak memory increase / run (MB)", res_base["mem_mb"], res_opt["mem_mb"], ".2f")
row("  Key-setup CPU time (s)",          base_setup["cpu"], opt_setup["cpu"])
row("  Key-setup memory (MB)",           base_setup["mem_mb"], opt_setup["mem_mb"], ".2f")
row("  Ciphertext payload (MB)",         res_base["payload_mb"], res_opt["payload_mb"], ".2f")
row("  Max relative error",              res_base["err"], res_opt["err"], ".2e", reduce=False)
if res_abl:
    print("-" * 78)
    print(f"ABLATION (N={BASE_DEGREE}, short chain {sum(OPT_CHAIN)} bits, 1 block/column):")
    print(f"  Enc {res_abl['enc']:.4f}s | Comp {res_abl['comp']:.4f}s | Dec {res_abl['dec']:.4f}s | "
          f"Total {res_abl['total']:.4f}s | CPU {res_abl['cpu']:.4f}s")
print("=" * 78)
print(f"{'MHT INTEGRITY':<38}{'Binary':>14}{'PSO tree':>16}{'Reduction':>10}")
print("-" * 78)
print(f"{'  Arity':<38}{bin_t['k']:>14}{opt_t['k']:>16}")
row("  Tree depth (levels)",             bin_t["depth"], opt_t["depth"], "d")
row("  Tree build time (ms)",            bin_t["avg_build"] * 1000, opt_t["avg_build"] * 1000, ".2f")
row("  Full verification latency (ms)",  bin_t["avg_latency"] * 1000, opt_t["avg_latency"] * 1000, ".2f")
print(f"{'  Proof size (B), depth x (k-1) x 32':<38}{base_mht['proof_bytes']:>14}{mht_opt['proof_bytes']:>16}"
      f"{reduction_pct(base_mht['proof_bytes'], mht_opt['proof_bytes']):>9.1f}%")
row("  Detection accuracy (with MHT, %)", bin_t["accuracy"], opt_t["accuracy"], ".2f", reduce=False)
print(f"{'  Tampers detected':<38}{str(bin_t['detected']) + '/' + str(n_tampered):>14}"
      f"{str(opt_t['detected']) + '/' + str(n_tampered):>16}")
print(f"{'  False alarms':<38}{str(bin_t['false_alarm']) + '/' + str(n_clean):>14}"
      f"{str(opt_t['false_alarm']) + '/' + str(n_clean):>16}")
print(f"{'  Exact tampered row localized':<38}{str(bin_t['localized']) + '/' + str(n_tampered):>14}"
      f"{str(opt_t['localized']) + '/' + str(n_tampered):>16}")
print("-" * 78)
print(f"Integrity Detection Accuracy (Without MHT): {accuracy_without_mht:.2f}%  (tamper detection rate 0%)")
print("=" * 78)

# ==========================================
# 10. FIGURES
# ==========================================
# --- PSO convergence ---
plt.figure(figsize=(8, 5))
plt.plot(optimizer.cost_history, marker='o', color='#2b5c8f')
plt.title('PSO Convergence (normalised measured cost)', fontsize=13, fontweight='bold')
plt.xlabel('Iteration'); plt.ylabel('Global best cost')
plt.grid(linestyle='--', alpha=0.7); plt.tight_layout(); plt.show()

# --- Merkle trees: top 3 levels (binary vs PSO n-ary) ---
def draw_top_levels(levels, k, title, top=3, max_children=4):
    G, pos, labels, colors = nx.DiGraph(), {}, {}, {}
    palette = ['#2b5c8f', '#4682b4', '#5dade2', '#2ecc71']
    cursor = [0]

    def place(level, i, depth):
        name = f"{level}-{i}"
        labels[name] = f"{'Merkle Root' if depth == 0 else f'Level {depth}'}\n({levels[level][i].hex()[:6]})"
        colors[name] = palette[min(depth, len(palette) - 1)]
        G.add_node(name)
        kids = list(range(i * k, min(i * k + k, len(levels[level - 1])))) if level > 0 else []
        if depth == top - 1 or not kids:
            x = cursor[0]; cursor[0] += 1
        else:
            shown = kids if len(kids) <= max_children else kids[:max_children - 1]
            xs = []
            for c in shown:
                xs.append(place(level - 1, c, depth + 1))
                G.add_edge(name, f"{level - 1}-{c}")
            if len(shown) < len(kids):                      # collapse the remaining children
                more = f"{name}-more"
                labels[more] = f"+{len(kids) - len(shown)}\nmore"
                colors[more] = '#95a5a6'
                G.add_edge(name, more)
                pos[more] = (cursor[0], -(depth + 1))
                xs.append(cursor[0]); cursor[0] += 1
            x = sum(xs) / len(xs)
        pos[name] = (x, -depth)
        return x

    place(len(levels) - 1, 0, 0)
    small = cursor[0] <= 16
    plt.figure(figsize=(max(10, 0.5 * cursor[0]), 6))
    plt.title(title, fontsize=13, fontweight='bold', pad=15)
    nodes = list(G.nodes)
    nx.draw_networkx_nodes(G, pos, node_size=3000 if small else 800,
                           node_color=[colors[n] for n in nodes], alpha=0.9)
    nx.draw_networkx_edges(G, pos, width=1.5, arrowsize=12, edge_color='#555555', arrows=True,
                           node_size=3000 if small else 800)
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=8 if small else 5,
                            font_weight='bold', font_color='white')
    plt.axis('off'); plt.tight_layout(); plt.show()

draw_top_levels(bin_t["levels"], 2,
                f"Baseline Binary MHT - Top 3 of {bin_t['depth']} Levels (arity 2)")
draw_top_levels(opt_t["levels"], opt_t["k"],
                f"PSO-Optimized {opt_t['k']}-ary MHT - Top 3 of {opt_t['depth']} Levels")

# --- HE time: baseline vs PSO ---
def annotate(ax, bars, fmt):
    for bar in bars:
        h = bar.get_height()
        ax.annotate(fmt.format(h), xy=(bar.get_x() + bar.get_width() / 2, h), xytext=(0, 4),
                    textcoords="offset points", ha='center', va='bottom', fontsize=9, fontweight='semibold')

phases = ['Encryption\n(T_enc)', 'Homomorphic\nComputation\n(T_comp)', 'Decryption\n(T_dec)', 'Total HE\n(T_total)']
base_vals = [res_base[k] for k in ('enc', 'comp', 'dec', 'total')]
opt_vals  = [res_opt[k]  for k in ('enc', 'comp', 'dec', 'total')]
x, w = np.arange(len(phases)), 0.36
fig, ax = plt.subplots(figsize=(10, 6))
b1 = ax.bar(x - w / 2, base_vals, w, color='#c0392b', label=f'Baseline')
b2 = ax.bar(x + w / 2, opt_vals, w, color='#2ecc71',
            label=f'PSO-optimized')
ax.axhline(plain_duration, color='#2b5c8f', linestyle='--', linewidth=1.5,
           label=f'Plaintext (T_plain = {plain_duration:.4f}s)')   # ~0 on a linear axis: read it in the legend
ax.set_xticks(x); ax.set_xticklabels(phases)
ax.set_ylabel('Execution Time (seconds)', fontsize=12, fontweight='bold')
ax.set_title('FHE Computational Overhead: Baseline vs PSO-Optimized', fontsize=13, fontweight='bold', pad=15)
annotate(ax, b1, '{:.3f}s'); annotate(ax, b2, '{:.3f}s')
ax.legend(); plt.grid(axis='y', linestyle='--', alpha=0.7); plt.tight_layout(); plt.show()

# --- Resource and integrity comparison ---
fig, axes = plt.subplots(1, 4, figsize=(16, 5))
panels = [("CPU time per run (s)", res_base["cpu"], res_opt["cpu"], '{:.2f}'),
          ("Peak memory increase (MB)", res_base["mem_mb"], res_opt["mem_mb"], '{:.1f}'),
          ("Ciphertext payload (MB)", res_base["payload_mb"], res_opt["payload_mb"], '{:.1f}'),
          ("MHT verification latency (ms)", bin_t["avg_latency"] * 1000, opt_t["avg_latency"] * 1000, '{:.1f}')]
for a, (title, bv, ov, fmt) in zip(axes, panels):
    bars = a.bar(['Baseline', 'PSO'], [bv, ov], color=['#c0392b', '#2ecc71'], width=0.55)
    annotate(a, bars, fmt)
    a.set_title(title, fontsize=11, fontweight='bold')
    a.grid(axis='y', linestyle='--', alpha=0.6)
plt.suptitle('Resource & Integrity Comparison', fontsize=13, fontweight='bold')
plt.tight_layout(); plt.show()

# ==========================================
# 11. INTERACTIVE COLUMN SELECTION FOR ATTACKS
# ==========================================
print("\n--- [Interactive Column Selection] ---")
attackable_cols = original_numeric_cols if original_numeric_cols else numeric_cols
for idx, col in enumerate(attackable_cols):
    print(f"  [{idx}] {col}")

user_input = input("\nEnter the column name or index number you want to target for attacks: ").strip()
if user_input.isdigit() and int(user_input) < len(attackable_cols):
    target_col = attackable_cols[int(user_input)]
elif user_input in attackable_cols:
    target_col = user_input
else:
    target_col = attackable_cols[0]
    print(f"[!] Invalid selection. Defaulting to: '{target_col}'")

print(f"[*] Target column selected for demonstration: {target_col}")

# ==========================================
# 12. INTERACTIVE THREAT MODEL WITH MHT CHOICE
# The MHT defence here is a PSO-optimized k-ary Merkle tree over the
# SERIALIZED CIPHERTEXTS registered by the data owner (one leaf per column).
# ==========================================
registered_ct_root = ciphertext_root(intercepted_transit_channel, best_arity)

print("\n--- [Threat Model Simulation Menu] ---")
print("Select security experiment to execute on target column:", target_col)
print("  [1] Malleability Attack (MODIFY ciphertext via algebraic scaling)")
print("  [2] Replay Attack (Inject historical/stale ciphertext into cloud pipeline)")
attack_choice = input("Enter option (1 or 2): ").strip()

use_mht = input("\nDo you want to apply the MHT Integrity Defense Layer? (y/n): ").strip().lower() == 'y'
if use_mht:
    print(f"[*] MHT Defense Mechanism: ENABLED ({best_arity}-ary tree, depth {optimal_mht_depth}; "
          f"verifying ciphertext Merkle root before cloud execution...)")
else:
    print("[!] MHT Defense Mechanism: DISABLED (Processing standard vulnerable FHE pipeline...)")

def print_attack_report(title, target, attack_desc, expected_label, expected_sum,
                        accepted_sum, outcome, detected_by, conclusion):
    """Shared, plain-language summary for both attack demos."""
    line = "-" * 62
    print(f"\n=== [{title}] ===")
    print(f"Target Column              : {target}")
    print(f"Attack Applied             : {attack_desc}")
    print(f"MHT Defense                : "
          f"{'ENABLED (' + str(best_arity) + '-ary tree, depth ' + str(optimal_mht_depth) + ')' if use_mht else 'DISABLED'}")
    print(line)
    print(f"{expected_label:<27}: ${expected_sum:,.2f}")
    if accepted_sum is None:
        print(f"{'Sum Accepted by Cloud':<27}: none (ciphertext was not processed)")
        print(f"{'Deviation from Expected':<27}: none")
    else:
        dev = accepted_sum - expected_sum
        pct = f" ({dev / expected_sum * 100:+.2f}%)" if expected_sum else ""
        print(f"{'Sum Accepted by Cloud':<27}: ${accepted_sum:,.2f}")
        print(f"{'Deviation from Expected':<27}: {'+' if dev >= 0 else '-'}${abs(dev):,.2f}{pct}")
    print(line)
    print(f"{'ATTACK RESULT':<27}: {outcome}")
    print(f"{'Detected By':<27}: {detected_by}")
    print(f"{'Conclusion':<27}: {conclusion}")

if attack_choice == "2":
    # ------------------------------------------
    # REPLAY ATTACK DEMONSTRATION
    # ------------------------------------------
    print("\n--- [Replay Attack Simulation] ---")
    print("[Simulator] Capturing clean transit snapshot representing 'Session 1'...")
    historical_stale_packet = intercepted_transit_channel[target_col]

    print("[Simulator] Advancing time/state: Modifying local dataset state and re-encrypting (Session 2)...")
    df[target_col] = df[target_col] * 1.5
    new_actual_sum = df[target_col].sum()
    session2_transit = dict(intercepted_transit_channel)
    session2_transit[target_col] = ts.ckks_vector(context, df[target_col].tolist()).serialize()
    session2_root = ciphertext_root(session2_transit, best_arity)      # root the cloud now expects

    print("\n[Attacker] Replaying stale historical packet from Session 1 into the cloud pipeline...")
    replayed_transit = dict(session2_transit)
    replayed_transit[target_col] = historical_stale_packet
    mht_blocked = use_mht and ciphertext_root(replayed_transit, best_arity) != session2_root

    replayed_sum, outcome, detected_by, conclusion = None, "", "", ""
    if mht_blocked:
        outcome = "ATTACK DETECTED (stale ciphertext rejected)"
        detected_by = "MHT ciphertext root mismatch"
        conclusion = "The replayed packet does not match the current session, so it was blocked."
    else:
        try:
            replayed_sum = ts.ckks_vector_from(context, historical_stale_packet).sum().decrypt()[0]
            outcome = "ATTACK SUCCEEDED (NOT DETECTED)"
            detected_by = "nothing - no integrity defense is active"
            conclusion = "The cloud processed outdated data as if it were current."
        except Exception as e:
            outcome = "ATTACK FAILED (cloud processing error)"
            detected_by = f"runtime error, not an integrity defense: {e}"
            conclusion = "The replay did not produce a result, but no integrity check caught it."

    print_attack_report("REPLAY ATTACK SUMMARY REPORT", target_col,
                        "stale Session-1 ciphertext replayed during Session 2",
                        "Current Sum (Session 2)", new_actual_sum, replayed_sum,
                        outcome, detected_by, conclusion)

else:
    # ------------------------------------------
    # MALLEABILITY ATTACK DEMONSTRATION
    # ------------------------------------------
    print("\n--- [Malleability Attack Simulation] ---")
    original_ciphertext = ts.ckks_vector_from(context, intercepted_transit_channel[target_col])
    original_sum = original_ciphertext.sum().decrypt()[0]

    try:
        malicious_multiplier = float(input("Enter malicious multiplier factor (e.g., 2.0, 5.0): ").strip())
    except ValueError:
        malicious_multiplier = 2.0

    print(f"\n[Attacker] Executing algebraic tampering with multiplier {malicious_multiplier}x...")
    tampered_vector = original_ciphertext * malicious_multiplier

    tampered_transit = dict(intercepted_transit_channel)
    tampered_transit[target_col] = tampered_vector.serialize()
    mht_blocked = use_mht and ciphertext_root(tampered_transit, best_arity) != registered_ct_root

    tampered_sum, outcome, detected_by, conclusion = None, "", "", ""
    if mht_blocked:
        outcome = "ATTACK DETECTED (tampered ciphertext rejected)"
        detected_by = "MHT ciphertext root mismatch"
        conclusion = "The modified ciphertext was blocked before any computation."
    else:
        try:
            tampered_sum = tampered_vector.sum().decrypt()[0]
            outcome = "ATTACK SUCCEEDED (NOT DETECTED)"
            detected_by = "nothing - no integrity defense is active"
            conclusion = (f"The cloud silently computed a result {malicious_multiplier}x "
                          f"larger than the true sum.")
        except Exception as e:
            outcome = "ATTACK FAILED (cloud processing error)"
            detected_by = f"runtime error, not an integrity defense: {e}"
            conclusion = "The tampering did not produce a result, but no integrity check caught it."

    print_attack_report("MALLEABILITY ATTACK SUMMARY REPORT", target_col,
                        f"every encrypted value multiplied by {malicious_multiplier}x",
                        "Expected Sum (untampered)", original_sum, tampered_sum,
                        outcome, detected_by, conclusion)
