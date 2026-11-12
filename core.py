"""
Logic of the three people in the scenario. No GUI code here (so it can be tested without a display).

  OwnerCore      Cloud User            holds the secret key, encrypts / decrypts, shares the audit ticket
  AuditorCore    Third-Party Auditor   holds ONLY hashes (the ticket) - no key, never sees data
  AdversaryCore  Attacker              holds a leaked storage credential - sees only ciphertext
"""
import hashlib
import io
import json
import math
import random
import time
from collections import namedtuple

import pandas as pd
import requests

from common import pack, root_of, sha_list, unpack

OPT_CHAIN = [60, 40, 40, 60]          # PSO-optimized CKKS modulus chain
SCALE = 2 ** 40
Reply = namedtuple("Reply", "status header blobs")


class ApiError(Exception):
    pass


class Api:
    def __init__(self, url, key):
        self.url, self.key = url.rstrip("/"), key

    def call(self, path, header=None, blobs=(), get=False):
        headers = {"X-Access-Key": self.key}
        try:
            if get:
                r = requests.get(self.url + path, headers=headers, timeout=(10, 60))
            else:
                r = requests.post(self.url + path, data=pack(header or {}, blobs),
                                  headers=headers, timeout=(10, 1800))
        except requests.RequestException as e:
            raise ApiError(f"Cannot reach the cloud server at {self.url}\n({type(e).__name__})") from None
        try:
            h, out = unpack(r.content)
        except Exception:
            raise ApiError(f"Unexpected reply from the server (HTTP {r.status_code}).") from None
        return Reply(r.status_code, h, out)

    def need_ok(self, reply):
        if reply.status != 200:
            raise ApiError(reply.header.get("error", f"HTTP {reply.status}"))
        return reply


def load_dataset(csv_bytes):
    """Same preprocessing as the framework: numeric cleaning + label-encoded text columns."""
    df = pd.read_csv(io.BytesIO(csv_bytes))
    num = df.select_dtypes(include=['number']).columns.tolist()
    txt = df.select_dtypes(include=['object', 'string', 'category']).columns.tolist()
    for c in num:
        df[c] = pd.to_numeric(df[c], errors='coerce').fillna(0)
    for c in txt:
        df[c] = df[c].fillna("NA").astype(str).str.strip().astype('category').cat.codes
        df[c] = df[c].apply(lambda x: 0 if x < 0 else x)
    names = num + txt
    return {"names": names, "numeric": num, "rows": len(df), "preview": df[names].head(8),
            "arrays": {c: df[c].to_numpy(dtype=float) for c in names}}


# =====================================================================================
class OwnerCore:
    def __init__(self, api, degree=16384, arity=4):
        self.api, self.degree, self.arity = api, degree, arity
        self.slots = degree // 2                      # PSO block size = CKKS slots
        self.data, self.ctx, self.ds_id, self.version = None, None, None, 0

    def set_mht(self, on):
        self.api.need_ok(self.api.call("/api/owner/config", {"mht": bool(on)}))

    def list_sources(self):
        """CSV files in the cloud bucket (source/ folder)."""
        return self.api.need_ok(self.api.call("/api/owner/sources")).header["files"]

    def load(self, filename):
        """Download the dataset from cloud storage; nothing is read from this computer's disk."""
        r = self.api.need_ok(self.api.call("/api/owner/source", {"name": filename}))
        self.data = load_dataset(r.blobs[0])
        return self.data

    def send_ticket(self):
        """Place the audit ticket (hashes only) in the cloud ticket box for the auditor."""
        return self.api.need_ok(self.api.call("/api/owner/ticket", {"ticket": self.ticket()})).header["name"]

    def _col_ids(self):
        return {n: f"c{i:02d}" for i, n in enumerate(self.data["names"])}

    def _encrypt_col(self, name):
        import tenseal as ts
        arr = self.data["arrays"][name]
        return [ts.ckks_vector(self.ctx, arr[b * self.slots:(b + 1) * self.slots].tolist()).serialize()
                for b in range(self.n_blocks)]

    def _register(self):
        return {"arity": self.arity, "root": root_of(self.leaves, self.arity).hex(),
                "leaf_hashes": [h.hex() for h in self.leaves]}

    def encrypt_upload(self, ds_id, progress):
        import tenseal as ts
        names = self.data["names"]
        self.ds_id, self.version = ds_id, 1
        self.n_blocks = math.ceil(self.data["rows"] / self.slots)
        progress(None, None, "Generating your private encryption keys...")
        self.ctx = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=self.degree,
                              coeff_mod_bit_sizes=OPT_CHAIN)
        self.ctx.global_scale = SCALE
        self.ctx.generate_galois_keys()
        public = self.ctx.serialize(save_public_key=True, save_secret_key=False,
                                    save_galois_keys=True, save_relin_keys=True)
        blobs = []
        for i, name in enumerate(names):
            blobs += self._encrypt_col(name)
            progress(i + 1, len(names), f"Encrypting column {i + 1} of {len(names)}...")
        self.leaves = sha_list(blobs)
        progress(None, None, "Uploading encrypted data to the cloud...")
        hdr = dict(self._register(), dataset=ds_id, cols=list(self._col_ids().values()),
                   n_blocks=self.n_blocks, version=1)
        self.api.need_ok(self.api.call("/api/owner/upload", hdr, [public] + blobs))
        return {"objects": len(blobs), "version": 1}

    def ticket(self):
        return dict(self._register(), dataset=self.ds_id, version=self.version,
                    issued_by="Alice (Cloud User)", issued_at=time.strftime("%Y-%m-%d %H:%M:%S"))

    def update(self, progress):
        """Monthly refresh: +10% on the first numeric column, uploaded as a new version."""
        names = self.data["names"]
        name = (self.data["numeric"] or names)[0]
        self.data["arrays"][name] = self.data["arrays"][name] * 1.10
        progress(None, None, f"Re-encrypting column '{name}'...")
        new_blobs = self._encrypt_col(name)
        first = names.index(name) * self.n_blocks
        indices = list(range(first, first + self.n_blocks))
        for i, b in zip(indices, new_blobs):
            self.leaves[i] = hashlib.sha256(b).digest()
        self.version += 1
        progress(None, None, "Uploading the new version...")
        hdr = dict(self._register(), dataset=self.ds_id, indices=indices, version=self.version)
        self.api.need_ok(self.api.call("/api/owner/update", hdr, new_blobs))
        return name, self.version

    def compute(self, names):
        """Ask the cloud for column sums on ENCRYPTED data, decrypt locally, compare with local data."""
        import tenseal as ts
        ids = self._col_ids()
        r = self.api.call("/api/owner/compute", {"dataset": self.ds_id, "cols": [ids[n] for n in names]})
        if r.status == 409:
            return {"refused": True, "message": r.header["error"], "rows": []}
        self.api.need_ok(r)
        rows = []
        for i, n in enumerate(names):
            cloud = sum(ts.ckks_vector_from(self.ctx, r.blobs[i * self.n_blocks + b]).decrypt()[0]
                        for b in range(self.n_blocks))
            local = float(self.data["arrays"][n].sum())
            rows.append({"name": n, "cloud": cloud, "local": local,
                         "match": abs(cloud - local) <= 1e-3 * max(abs(local), 1.0)})
        return {"refused": False, "message": "", "rows": rows}


# =====================================================================================
class AuditorCore:
    def __init__(self, api):
        self.api, self.ticket, self.history = api, None, []

    def list_tickets(self):
        return self.api.need_ok(self.api.call("/api/audit/tickets")).header["tickets"]

    def fetch_ticket(self, name):
        r = self.api.need_ok(self.api.call("/api/audit/ticket", {"name": name}))
        return self.load_ticket(json.loads(r.blobs[0]))

    def load_ticket(self, t):
        leaves = [bytes.fromhex(h) for h in t["leaf_hashes"]]
        if root_of(leaves, t["arity"]).hex() != t["root"]:
            raise ValueError("This ticket is internally inconsistent (its root does not match its leaf "
                             "hashes). Do not trust it.")
        t["_leaves"] = leaves
        self.ticket = t
        return t

    def audit(self, full, sample, progress):
        """Fetch ciphertext objects, hash them, compare with the ticket. The auditor never decrypts."""
        t = self.ticket
        n = len(t["_leaves"])
        idx = list(range(n)) if full else sorted(random.sample(range(n), min(sample, n)))
        rows, server_version = [], None
        for s in range(0, len(idx), 6):
            chunk = idx[s:s + 6]
            r = self.api.need_ok(self.api.call("/api/audit/challenge",
                                               {"dataset": t["dataset"], "indices": chunk}))
            server_version = r.header["version"]
            for i, blob in zip(chunk, r.blobs):
                h = hashlib.sha256(blob).digest()
                rows.append({"index": i, "name": f"obj-{i:03d}", "server_fp": h.hex()[:12],
                             "ticket_fp": t["_leaves"][i].hex()[:12], "ok": h == t["_leaves"][i],
                             "preview": blob[:64].hex()})
            progress(len(rows), len(idx))
        bad = [r for r in rows if not r["ok"]]
        result = {"full": full, "checked": len(rows), "total": n, "bad": len(bad), "rows": rows,
                  "server_version": server_version, "ticket_version": t["version"],
                  "passed": not bad, "time": time.strftime("%H:%M:%S")}
        self.history.append(result)
        return result


# =====================================================================================
class AdversaryCore:
    def __init__(self, api):
        self.api, self.snapshots, self._ctx = api, {}, {}

    def datasets(self):
        return self.api.need_ok(self.api.call("/api/status", get=True)).header["datasets"]

    def objects(self, ds):
        return self.api.need_ok(self.api.call("/api/storage/objects", {"dataset": ds})).header["objects"]

    def get(self, ds, index):
        return self.api.need_ok(self.api.call("/api/storage/get", {"dataset": ds, "index": index})).blobs[0]

    def put(self, ds, index, blob):
        r = self.api.call("/api/storage/put", {"dataset": ds, "index": index}, [blob])
        return r.status == 200, r.header.get("error", "")

    def snapshot(self, ds, progress):
        objs = self.objects(ds)
        snap = {}
        for k, o in enumerate(objs):
            snap[o["index"]] = self.get(ds, o["index"])
            progress(k + 1, len(objs))
        self.snapshots[ds] = snap
        return len(snap)

    def malleability(self, ds, index, factor):
        """Scale one encrypted object with the PUBLIC key material only - no secret key needed."""
        import tenseal as ts
        if ds not in self._ctx:
            blob = self.api.need_ok(self.api.call("/api/storage/context", {"dataset": ds})).blobs[0]
            self._ctx[ds] = ts.context_from(blob)
        forged = (ts.ckks_vector_from(self._ctx[ds], self.get(ds, index)) * factor).serialize()
        ok, msg = self.put(ds, index, forged)
        return {"accepted": ok, "message": msg}

    def replay(self, ds, progress):
        """Roll the stored dataset back to the stale snapshot (only objects that changed since)."""
        snap = self.snapshots[ds]
        changed = accepted = rejected = 0
        msg = ""
        for k, (i, stale) in enumerate(sorted(snap.items())):
            if self.get(ds, i) != stale:
                changed += 1
                ok, m = self.put(ds, i, stale)
                accepted += ok
                rejected += (not ok)
                msg = msg or m
            progress(k + 1, len(snap))
        return {"changed": changed, "accepted": accepted, "rejected": rejected, "message": msg}
