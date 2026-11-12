"""
THE ONE CLOUD SERVER of the PSO-optimized FHE + MHT framework.

All data lives in ONE Amazon S3 bucket:
    code/                            this server's own files (fetched at boot)
    config/demo_config.json          access keys for the demo (published at start-up)
    source/<file>.csv                the Cloud User's private plaintext datasets
    vault/<dataset>/obj-NNN.bin      ENCRYPTED objects (what the adversary attacks)
    vault/<dataset>/context.bin      public CKKS context (no secret key)
    vault/<dataset>/meta.json        Merkle root + leaf hashes registered by the owner
    tickets/<dataset>_vN.json        audit tickets (hashes only) for the auditor

Three callers, each with its own access key:
    owner      Cloud User            read source/, upload / update / compute, send tickets, switch MHT
    auditor    Third-Party Auditor   read tickets, read-only audit challenges on vault/
    adversary  leaked storage key    list / read / overwrite objects in vault/

MHT protection ON : verifies every upload, write and computation against the registered Merkle leaves.
MHT protection OFF: trusts whatever is stored.

  python3 cloud_server.py --bucket MY_BUCKET --port 8000 --publish-config
  python3 cloud_server.py --local-dir ./fake_bucket          (testing without AWS)
"""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import tenseal as ts

from common import pack, root_of, sha_list, unpack

CONFIG_FILE = "demo_config.json"
LOCK = threading.RLock()
STATE = {"mht": True, "where": ""}
ROLE_OF_KEY, META, CTX = {}, {}, {}
POOL = ThreadPoolExecutor(8)
DB = None


# ------------------------------------------------------------------ storage back-ends
class LocalStorage:
    """Folder on disk that behaves like a bucket (for testing without AWS)."""
    def __init__(self, root):
        self.root = os.path.abspath(root)
        os.makedirs(self.root, exist_ok=True)

    def _p(self, path):
        return os.path.join(self.root, *path.split("/"))

    def put(self, path, data):
        os.makedirs(os.path.dirname(self._p(path)), exist_ok=True)
        with open(self._p(path), "wb") as f:
            f.write(data)

    def get(self, path):
        try:
            with open(self._p(path), "rb") as f:
                return f.read()
        except FileNotFoundError:
            raise KeyError(path)

    def delete(self, path):
        if os.path.exists(self._p(path)):
            os.remove(self._p(path))

    def list(self, prefix):
        out = []
        for d, _, files in os.walk(self.root):
            for fn in files:
                full = os.path.join(d, fn)
                name = os.path.relpath(full, self.root).replace(os.sep, "/")
                if name.startswith(prefix):
                    out.append((name, os.path.getsize(full), os.path.getmtime(full)))
        return sorted(out)


class S3Storage:
    """Amazon S3 bucket, accessed with the EC2 instance's IAM role (no keys stored anywhere)."""
    def __init__(self, bucket_name):
        import boto3
        self.s3, self.bucket = boto3.client("s3"), bucket_name

    def put(self, path, data):
        self.s3.put_object(Bucket=self.bucket, Key=path, Body=data)

    def get(self, path):
        try:
            return self.s3.get_object(Bucket=self.bucket, Key=path)["Body"].read()
        except self.s3.exceptions.NoSuchKey:
            raise KeyError(path)

    def delete(self, path):
        self.s3.delete_object(Bucket=self.bucket, Key=path)

    def list(self, prefix):
        out = []
        for page in self.s3.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=prefix):
            out += [(o["Key"], o["Size"], o["LastModified"].timestamp()) for o in page.get("Contents", [])]
        return sorted(out)


# ------------------------------------------------------------------ helpers
class Reject(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code, self.msg = code, msg


def get_many(paths):
    return list(POOL.map(DB.get, paths))


def put_many(items):
    list(POOL.map(lambda kv: DB.put(*kv), items))


def obj_path(ds, i):
    return f"vault/{ds}/obj-{i:03d}.bin"


def safe_name(name):
    if not name or "/" in name or "\\" in name or ".." in name:
        raise Reject(400, "Invalid file name.")
    return name


def ds_of(hdr):
    ds = hdr.get("dataset")
    if ds not in META:
        raise Reject(404, "Dataset not found in cloud storage.")
    return ds, META[ds]


def ctx_of(ds):
    if ds not in CTX:
        CTX[ds] = ts.context_from(DB.get(f"vault/{ds}/context.bin"))
    return CTX[ds]


def leaves_of(m):
    return [bytes.fromhex(h) for h in m["leaves"]]


def save_meta(ds):
    DB.put(f"vault/{ds}/meta.json", json.dumps(META[ds]).encode())


def load_index():
    for name, _, _ in DB.list("vault/"):
        if name.endswith("/meta.json"):
            META[name.split("/")[1]] = json.loads(DB.get(name))


def load_keys():
    cfg = json.load(open(CONFIG_FILE)) if os.path.exists(CONFIG_FILE) else {}
    for field in ("owner_key", "auditor_key", "leaked_key"):
        cfg[field] = os.environ.get("FHE_" + field.upper()) or cfg.get(field) or secrets.token_hex(12)
    cfg.setdefault("server_url", "http://EXTERNAL_IP:8000")
    cfg.setdefault("pso_degree", 16384)
    cfg.setdefault("pso_arity", 4)
    cfg.setdefault("datasets", {"Dataset 1": "dataset1.csv", "Dataset 2": "dataset2.csv",
                                "Dataset 3": "dataset3.csv"})
    json.dump(cfg, open(CONFIG_FILE, "w"), indent=2)
    ROLE_OF_KEY.update({cfg["owner_key"]: "owner", cfg["auditor_key"]: "auditor",
                        cfg["leaked_key"]: "adversary"})


# ------------------------------------------------------------------ any role
def h_status(role, hdr, blobs):
    out = {"role": role, "storage": STATE["where"], "tenseal": getattr(ts, "__version__", "?"),
           "datasets": [{"id": k, "version": v["version"], "objects": v["n_objects"]}
                        for k, v in META.items()]}
    if role == "owner":
        out["mht"] = STATE["mht"]
    return 200, out, []


# ------------------------------------------------------------------ owner (Cloud User)
def h_config(role, hdr, blobs):
    STATE["mht"] = bool(hdr["mht"])
    return 200, {"mht": STATE["mht"]}, []


def h_sources(role, hdr, blobs):
    files = [n[len("source/"):] for n, _, _ in DB.list("source/") if n.endswith(".csv")]
    return 200, {"files": files}, []


def h_source(role, hdr, blobs):
    name = safe_name(hdr["name"])
    try:
        data = DB.get("source/" + name)
    except KeyError:
        raise Reject(404, f"'{name}' was not found in cloud storage (source/{name}).")
    return 200, {"name": name}, [data]


def h_upload(role, hdr, blobs):
    ds = safe_name(hdr["dataset"])
    ctx = ts.context_from(blobs[0])
    if ctx.is_private():
        raise Reject(400, "The uploaded context contains a secret key - refusing to store it.")
    cts, k = blobs[1:], int(hdr["arity"])
    leaves = [bytes.fromhex(h) for h in hdr["leaf_hashes"]]
    root = bytes.fromhex(hdr["root"])
    if STATE["mht"] and (sha_list(cts) != leaves or root_of(leaves, k) != root):
        raise Reject(409, "Upload rejected: data does not match the Merkle root (altered in transit).")
    put_many([(f"vault/{ds}/context.bin", blobs[0])] + [(obj_path(ds, i), b) for i, b in enumerate(cts)])
    for name, _, _ in DB.list(f"vault/{ds}/obj-"):               # remove leftovers of an older upload
        if int(name[-7:-4]) >= len(cts):
            DB.delete(name)
    with LOCK:
        META[ds] = {"version": int(hdr.get("version", 1)), "arity": k, "root": hdr["root"],
                    "leaves": hdr["leaf_hashes"], "cols": hdr["cols"],
                    "n_blocks": int(hdr["n_blocks"]), "n_objects": len(cts)}
        CTX[ds] = ctx
        save_meta(ds)
    return 200, {"stored": len(cts)}, []


def h_update(role, hdr, blobs):
    ds, m = ds_of(hdr)
    leaves = [bytes.fromhex(h) for h in hdr["leaf_hashes"]]
    root = bytes.fromhex(hdr["root"])
    if STATE["mht"]:
        cur = get_many([obj_path(ds, i) for i in range(m["n_objects"])])
        for i, b in zip(hdr["indices"], blobs):
            cur[i] = b
        if sha_list(cur) != leaves or root_of(leaves, m["arity"]) != root:
            raise Reject(409, "Update rejected: stored data does not match the new Merkle root.")
    put_many([(obj_path(ds, i), b) for i, b in zip(hdr["indices"], blobs)])
    with LOCK:
        m.update(leaves=hdr["leaf_hashes"], root=hdr["root"], version=int(hdr["version"]))
        save_meta(ds)
    return 200, {"version": m["version"]}, []


def h_compute(role, hdr, blobs):
    ds, m = ds_of(hdr)
    if STATE["mht"]:
        stored = get_many([obj_path(ds, i) for i in range(m["n_objects"])])
        bad = sum(a != b for a, b in zip(sha_list(stored), leaves_of(m)))
        if bad:
            raise Reject(409, f"Computation refused: {bad} stored object(s) fail Merkle verification "
                              f"(tampered or stale data detected).")
        fetch = stored.__getitem__
    else:
        fetch = lambda i: DB.get(obj_path(ds, i))
    ctx, out = ctx_of(ds), []
    for cid in hdr["cols"]:
        i = m["cols"].index(cid)
        for b in range(m["n_blocks"]):
            out.append(ts.ckks_vector_from(ctx, fetch(i * m["n_blocks"] + b)).sum().serialize())
    return 200, {"mht_checked": STATE["mht"]}, out


def h_ticket_put(role, hdr, blobs):
    t = hdr["ticket"]
    name = f"{safe_name(t['dataset'])}_v{int(t['version'])}.json"
    DB.put("tickets/" + name, json.dumps(t).encode())
    return 200, {"name": name}, []


# ------------------------------------------------------------------ auditor
def h_tickets(role, hdr, blobs):
    items = sorted(DB.list("tickets/"), key=lambda x: x[2], reverse=True)
    return 200, {"tickets": [n[len("tickets/"):] for n, _, _ in items if n.endswith(".json")]}, []


def h_ticket_get(role, hdr, blobs):
    name = safe_name(hdr["name"])
    try:
        return 200, {}, [DB.get("tickets/" + name)]
    except KeyError:
        raise Reject(404, "Ticket not found.")


def h_challenge(role, hdr, blobs):
    ds, m = ds_of(hdr)
    idx = [int(i) for i in hdr["indices"]]
    if any(i < 0 or i >= m["n_objects"] for i in idx):
        raise Reject(400, "Challenge index out of range.")
    return 200, {"version": m["version"], "objects": m["n_objects"]}, get_many([obj_path(ds, i) for i in idx])


# ------------------------------------------------------------------ adversary (leaked storage credential)
def h_objects(role, hdr, blobs):
    ds, _ = ds_of(hdr)
    objs = [{"index": int(n[-7:-4]), "name": n.split("/")[-1][:-4], "size": s}
            for n, s, _ in DB.list(f"vault/{ds}/obj-")]
    return 200, {"objects": objs}, []


def h_get(role, hdr, blobs):
    ds, _ = ds_of(hdr)
    return 200, {}, [DB.get(obj_path(ds, int(hdr["index"])))]


def h_context(role, hdr, blobs):
    ds, _ = ds_of(hdr)
    return 200, {}, [DB.get(f"vault/{ds}/context.bin")]


def h_put(role, hdr, blobs):
    ds, m = ds_of(hdr)
    i = int(hdr["index"])
    if STATE["mht"] and hashlib.sha256(blobs[0]).digest() != leaves_of(m)[i]:
        raise Reject(409, "Write rejected: the object does not match the Merkle leaf "
                          "registered by the data owner.")
    DB.put(obj_path(ds, i), blobs[0])
    return 200, {"stored": True}, []


ROUTES = {"/api/status": ("any", h_status),
          "/api/owner/config": ("owner", h_config), "/api/owner/sources": ("owner", h_sources),
          "/api/owner/source": ("owner", h_source), "/api/owner/upload": ("owner", h_upload),
          "/api/owner/update": ("owner", h_update), "/api/owner/compute": ("owner", h_compute),
          "/api/owner/ticket": ("owner", h_ticket_put),
          "/api/audit/tickets": ("auditor", h_tickets), "/api/audit/ticket": ("auditor", h_ticket_get),
          "/api/audit/challenge": ("auditor", h_challenge),
          "/api/storage/objects": ("adversary", h_objects), "/api/storage/get": ("adversary", h_get),
          "/api/storage/context": ("adversary", h_context), "/api/storage/put": ("adversary", h_put)}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, header, blobs=()):
        payload = pack(header, blobs)
        self.send_response(code)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _role(self):
        key = self.headers.get("X-Access-Key", "")
        for k, role in ROLE_OF_KEY.items():
            if hmac.compare_digest(key, k):
                return role
        return None

    def _handle(self, with_body):
        path = urlparse(self.path).path
        role, route = self._role(), ROUTES.get(path)
        code, note = 500, ""
        try:
            if role is None:
                self.close_connection = True
                code, note = 401, "invalid access key"
                return self._send(401, {"error": "Access denied: invalid access key."})
            if route is None:
                self.close_connection = True
                code = 404
                return self._send(404, {"error": "Unknown operation."})
            if route[0] not in ("any", role):
                self.close_connection = True
                code, note = 403, "role not allowed"
                return self._send(403, {"error": "Your account is not allowed to do this."})
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))) if with_body else b""
            hdr, blobs = unpack(body) if body else ({}, [])
            code, out_hdr, out_blobs = route[1](role, hdr, blobs)
            self._send(code, out_hdr, out_blobs)
        except Reject as e:
            code, note = e.code, e.msg
            self._send(e.code, {"error": e.msg})
        except Exception as e:                       # keep the service alive on bad input
            code, note = 500, f"{type(e).__name__}: {e}"
            self._send(500, {"error": note})
        finally:
            print(f"[{time.strftime('%H:%M:%S')}] {role or 'unknown':<9} {path:<22} -> {code} {note}", flush=True)

    def do_GET(self):
        self._handle(False)

    def do_POST(self):
        self._handle(True)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--bucket", help="Amazon S3 bucket name")
    ap.add_argument("--local-dir", help="folder to use instead of a bucket (testing only)")
    ap.add_argument("--publish-config", action="store_true",
                    help="copy demo_config.json (access keys) into the bucket under config/")
    ap.add_argument("--mht", choices=["on", "off"], default="on", help="initial MHT protection state")
    args = ap.parse_args()
    if not (args.bucket or args.local_dir):
        raise SystemExit("Give --bucket BUCKET_NAME (or --local-dir DIR for testing).")
    DB = S3Storage(args.bucket) if args.bucket else LocalStorage(args.local_dir)
    STATE["where"] = f"s3://{args.bucket}" if args.bucket else f"local:{args.local_dir}"
    STATE["mht"] = args.mht == "on"
    load_keys()
    if args.publish_config:
        DB.put("config/demo_config.json", open(CONFIG_FILE, "rb").read())
    load_index()
    print(f"Cloud server on {args.host}:{args.port} | storage {STATE['where']} | "
          f"{len(META)} dataset(s) in vault | MHT protection: {args.mht.upper()}", flush=True)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
