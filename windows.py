"""Three role windows. Each one shows ONLY what that person would see on their own computer."""
import json
import os
import queue
import random
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

from core import AdversaryCore, Api, AuditorCore, OwnerCore

THEMES = {
    "owner":     {"color": "#1f5fa8", "icon": "\U0001F464", "title": "Cloud User",
                  "persona": "Alice - owns the data", "key": "owner_key"},
    "auditor":   {"color": "#1e8449", "icon": "\U0001F50D", "title": "Third-Party Auditor",
                  "persona": "Bob - checks integrity, can NOT read data", "key": "auditor_key"},
    "adversary": {"color": "#a93226", "icon": "\U0001F575", "title": "Adversary",
                  "persona": "Mallory - leaked storage credential", "key": "leaked_key"},
}


def save_config(cfg):
    data = {k: v for k, v in cfg.items() if not k.startswith("_")}
    json.dump(data, open(cfg["_path"], "w"), indent=2)


def pick(parent, title, items):
    """Small modal list box; returns the chosen item or None."""
    win = tk.Toplevel(parent)
    win.title(title)
    win.transient(parent)
    lb = tk.Listbox(win, height=min(12, max(len(items), 3)), width=60, exportselection=False)
    for it in items:
        lb.insert("end", it)
    lb.selection_set(0)
    lb.pack(padx=12, pady=12)
    choice = []

    def ok():
        sel = lb.curselection()
        if sel:
            choice.append(items[sel[0]])
        win.destroy()

    lb.bind("<Double-Button-1>", lambda e: ok())
    ttk.Button(win, text="Open", command=ok).pack(pady=(0, 12))
    win.grab_set()
    win.wait_window()
    return choice[0] if choice else None


class Bus:
    """Lets the Control Room watch the story and switch perspectives."""
    def __init__(self):
        self.listeners, self.switch_fn = [], (lambda role: None)

    def emit(self, role, text):
        for fn in self.listeners:
            fn(role, text)

    def switch(self, role):
        self.switch_fn(role)


class RoleWindow(tk.Toplevel):
    ROLE = ""

    def __init__(self, master, cfg, bus, geometry):
        super().__init__(master)
        th = self.th = THEMES[self.ROLE]
        self.cfg, self.bus, self.q = cfg, bus, queue.Queue()
        self.api = self.core = None
        self.buttons = []
        self.title(f"{th['icon']} {th['title']} - {th['persona']}")
        self.geometry(geometry)
        self.minsize(860, 620)

        head = tk.Frame(self, bg=th["color"])
        head.pack(fill="x")
        tk.Label(head, text=f"{th['icon']}  {th['title']}", bg=th["color"], fg="white",
                 font=("Segoe UI", 20, "bold")).pack(side="left", padx=14, pady=8)
        tk.Label(head, text=f"{th['persona']}\nF1 Cloud User   F2 Auditor   F3 Adversary", bg=th["color"],
                 fg="white", justify="right").pack(side="right", padx=14)

        main = ttk.Frame(self, padding=8)
        main.pack(fill="both", expand=True)
        self._build_login(main)

        bottom = ttk.Frame(main)
        bottom.pack(side="bottom", fill="x")
        self.progress = ttk.Progressbar(bottom, mode="determinate")
        self.progress.pack(fill="x")
        self.status = ttk.Label(bottom, text="Please sign in to the cloud first.")
        self.status.pack(anchor="w")
        self.logbox = tk.Text(bottom, height=6, state="disabled", bg="#fafafa", font=("Consolas", 9))
        self.logbox.pack(fill="x")

        self.body = ttk.Frame(main)
        self.build_body(self.body)

        for key, role in (("<F1>", "owner"), ("<F2>", "auditor"), ("<F3>", "adversary")):
            self.bind(key, lambda e, r=role: self.bus.switch(r))
        self.after(80, self._poll)

    # ---------------------------------------------------------------- plumbing
    def mk_button(self, parent, text, command, **pack):
        b = ttk.Button(parent, text=text, command=command)
        b.pack(**(pack or {"side": "left", "padx": 4}))
        self.buttons.append(b)
        return b

    def set_busy(self, busy):
        for b in self.buttons:
            b.config(state="disabled" if busy else "normal")

    def set_progress(self, a, b, text=""):
        self.status.config(text=text)
        if a is None:
            self.progress.config(mode="indeterminate")
            self.progress.start(12)
        else:
            self.progress.stop()
            self.progress.config(mode="determinate", maximum=max(b, 1), value=a)

    def log(self, text):
        self.logbox.config(state="normal")
        self.logbox.insert("end", f"[{time.strftime('%H:%M:%S')}] {text}\n")
        self.logbox.see("end")
        self.logbox.config(state="disabled")

    def ui(self, fn):
        self.q.put(fn)

    def _poll(self):
        try:
            while True:
                self.q.get_nowait()()
        except queue.Empty:
            pass
        self.after(80, self._poll)

    def run_bg(self, work, done=None):
        def runner():
            try:
                res = work()
            except Exception as e:
                self.ui(lambda e=e: self._fail(e))
                return
            if done:
                self.ui(lambda: done(res))
        threading.Thread(target=runner, daemon=True).start()

    def _fail(self, e):
        self.set_busy(False)
        self.set_progress(0, 1, "Stopped.")
        self.log(f"ERROR: {e}")
        messagebox.showerror("Something went wrong", str(e), parent=self)

    def info(self, title, msg):
        self.log(title)
        messagebox.showinfo(title, msg, parent=self)

    def warn(self, title, msg):
        self.log(title)
        messagebox.showwarning(title, msg, parent=self)

    def error(self, title, msg):
        self.log(title)
        messagebox.showerror(title, msg, parent=self)

    def ask(self, title, msg):
        return messagebox.askyesno(title, msg, parent=self)

    # ---------------------------------------------------------------- login
    def _build_login(self, parent):
        f = ttk.LabelFrame(parent, text="Cloud login")
        f.pack(fill="x", pady=(0, 6))
        self.url_var = tk.StringVar(value=self.cfg.get("server_url", ""))
        self.key_var = tk.StringVar(value=self.cfg.get(self.th["key"], ""))
        ttk.Label(f, text="Server").grid(row=0, column=0, padx=6, pady=3, sticky="e")
        ttk.Entry(f, textvariable=self.url_var, width=38).grid(row=0, column=1, padx=4)
        ttk.Label(f, text="Access key").grid(row=0, column=2, padx=6, sticky="e")
        ttk.Entry(f, textvariable=self.key_var, show="*", width=30).grid(row=0, column=3, padx=4)
        self.login_btn = ttk.Button(f, text="Sign in", command=self._login)
        self.login_btn.grid(row=0, column=4, padx=6)
        self.login_msg = ttk.Label(f, text="Not signed in")
        self.login_msg.grid(row=0, column=5, padx=6)

    def _login(self):
        api = Api(self.url_var.get(), self.key_var.get())

        def done(r):
            if r.status != 200:
                return self.error("Login failed", r.header.get("error", "Access denied."))
            if r.header["role"] != self.ROLE:
                return self.error("Wrong account", f"This access key belongs to the "
                                  f"'{r.header['role']}' account, not '{self.ROLE}'.")
            self.api, self.core = api, self.make_core(api)
            self.login_msg.config(text=f"Signed in | {r.header.get('storage', '')}")
            self.body.pack(fill="both", expand=True)
            self.status.config(text="Signed in. Ready.")
            self.log(f"Signed in to {api.url} as {self.th['title']}")
            self.on_login(r.header)

        self.run_bg(lambda: api.call("/api/status", get=True), done)

    def make_core(self, api):
        raise NotImplementedError

    def on_login(self, header):
        pass

    def build_body(self, body):
        raise NotImplementedError


# =====================================================================================
class OwnerWindow(RoleWindow):
    ROLE = "owner"

    def make_core(self, api):
        return OwnerCore(api, self.cfg.get("pso_degree", 16384), self.cfg.get("pso_arity", 4))

    def build_body(self, body):
        f1 = ttk.LabelFrame(body, text="1   My data - downloaded from my private folder in cloud storage (source/)")
        f1.pack(fill="x", pady=4)
        row = ttk.Frame(f1)
        row.pack(fill="x", padx=6, pady=4)
        self.ds_var = tk.StringVar()
        self.ds_combo = ttk.Combobox(row, textvariable=self.ds_var, state="readonly", width=24,
                                     values=list(self.cfg.get("datasets", {}).values()))
        self.ds_combo.pack(side="left", padx=4)
        self.mk_button(row, "Refresh list", self._refresh)
        self.mk_button(row, "Load from cloud storage", self._load)
        self.info_lbl = ttk.Label(row, text="")
        self.info_lbl.pack(side="left", padx=10)
        self.preview = ttk.Treeview(f1, height=4, show="headings")
        self.preview.pack(fill="x", padx=6, pady=(0, 6))

        f2 = ttk.LabelFrame(body, text="2   Encrypt on this computer, store in the cloud (vault/)")
        f2.pack(fill="x", pady=4)
        row = ttk.Frame(f2)
        row.pack(fill="x", padx=6, pady=4)
        self.mk_button(row, "Encrypt & Upload", self._upload)
        self.mk_button(row, "Send audit ticket to auditor", self._send_ticket)
        self.mk_button(row, "Monthly update (new version)", self._update)
        self.mht_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(f2, text="Enable MHT integrity protection on the cloud server",
                        variable=self.mht_var, command=self._toggle_mht).pack(anchor="w", padx=10, pady=(0, 4))

        f3 = ttk.LabelFrame(body, text="3   Compute on ENCRYPTED data in the cloud, decrypt result here")
        f3.pack(fill="both", expand=True, pady=4)
        cols = ("Column", "Cloud result (decrypted)", "My local result", "Status")
        self.ctree = ttk.Treeview(f3, columns=cols, show="headings", height=7)
        for c, w in zip(cols, (180, 200, 200, 160)):
            self.ctree.heading(c, text=c)
            self.ctree.column(c, width=w)
        self.ctree.tag_configure("good", background="#d5f5e3")
        self.ctree.tag_configure("bad", background="#f5b7b1")
        self.ctree.pack(fill="both", expand=True, padx=6, pady=4)
        row = ttk.Frame(f3)
        row.pack(fill="x", padx=6, pady=(0, 6))
        self.mk_button(row, "Compute selected column", lambda: self._compute(False))
        self.mk_button(row, "Compute ALL columns & compare", lambda: self._compute(True))

    def on_login(self, header):
        self.mht_var.set(header.get("mht", True))
        self._refresh()

    # ------------------------------------------------------------ actions
    def _ds_id(self):
        return os.path.splitext(self.ds_var.get() or "dataset")[0].lower().replace(" ", "-")

    def _refresh(self):
        def done(files):
            self.ds_combo.config(values=files)
            if files and not self.ds_var.get():
                self.ds_var.set(files[0])
            self.log(f"Cloud storage source/: {len(files)} CSV file(s) found")

        self.run_bg(self.core.list_sources, done)

    def _load(self):
        name = self.ds_var.get()
        if not name:
            return self.warn("No dataset selected", "Choose a file from the cloud storage list first.")
        self.set_busy(True)
        self.set_progress(None, None, f"Downloading {name} from cloud storage...")

        def done(d):
            self.set_busy(False)
            self.set_progress(0, 1, "Dataset loaded.")
            self.info_lbl.config(text=f"{d['rows']} rows x {len(d['names'])} columns")
            prev = d["preview"]
            shown = list(prev.columns)[:8]
            self.preview.delete(*self.preview.get_children())
            self.preview["columns"] = shown
            for c in shown:
                self.preview.heading(c, text=c)
                self.preview.column(c, width=100)
            for _, r in prev.iterrows():
                self.preview.insert("", "end", values=[r[c] for c in shown])
            self.ctree.delete(*self.ctree.get_children())
            for n in d["names"]:
                self.ctree.insert("", "end", iid=n, values=(n, "-", "-", "-"))
            self.log(f"Loaded {name} from cloud storage: {d['rows']} rows")

        self.run_bg(lambda: self.core.load(name), done)

    def _upload(self):
        if not self.core.data:
            return self.warn("Nothing to upload", "Load a dataset first.")
        self.set_busy(True)
        ds_id = self._ds_id()

        def work():
            return self.core.encrypt_upload(
                ds_id, lambda a, b, t: self.ui(lambda: self.set_progress(a, b, t)))

        def done(res):
            self.set_busy(False)
            self.set_progress(1, 1, "Upload complete.")
            self.bus.emit("owner", f"Uploaded '{ds_id}' encrypted to cloud storage (v1, "
                                   f"MHT {'ON' if self.mht_var.get() else 'OFF'})")
            self.info("Upload complete",
                      f"'{ds_id}' was encrypted on this computer and stored in cloud storage as "
                      f"{res['objects']} encrypted objects (vault/{ds_id}/).\n\nThe cloud holds only "
                      f"ciphertext. Your secret key never left this computer.")
            self._send_ticket(ask_first=True)

        self.run_bg(work, done)

    def _send_ticket(self, ask_first=False):
        if not self.core.ds_id:
            return self.warn("Nothing uploaded yet", "Upload a dataset first.")
        if ask_first and not self.ask(
                "Share with the auditor?",
                "Send the audit ticket to the Third-Party Auditor now?\n\nThe ticket contains only "
                "hashes (fingerprints), so the auditor can verify the cloud copy without seeing any data."):
            return

        def done(name):
            self.bus.emit("owner", f"Sent audit ticket '{name}' to the auditor")
            self.info("Ticket sent", f"The audit ticket was placed in the cloud ticket box:\n"
                                     f"tickets/{name}\n\nTell the auditor to open it.")

        self.run_bg(self.core.send_ticket, done)

    def _update(self):
        if not self.core.ds_id:
            return self.warn("Nothing uploaded yet", "Upload a dataset first.")
        col = (self.core.data["numeric"] or self.core.data["names"])[0]
        if not self.ask("Monthly update",
                        f"Simulate a regular data refresh?\n\nColumn '{col}' will be increased by 10%, "
                        f"re-encrypted and uploaded as a NEW VERSION."):
            return
        self.set_busy(True)

        def done(res):
            self.set_busy(False)
            self.set_progress(1, 1, "Update complete.")
            self.bus.emit("owner", f"Updated '{self.core.ds_id}' to version {res[1]}")
            self.info("Update complete", f"Version {res[1]} is now in cloud storage (column '{res[0]}').")
            self._send_ticket(ask_first=True)

        self.run_bg(lambda: self.core.update(lambda a, b, t: self.ui(lambda: self.set_progress(a, b, t))), done)

    def _toggle_mht(self):
        on = self.mht_var.get()
        if not on and not self.ask(
                "Disable MHT protection?",
                "Without MHT protection the cloud server will NOT verify stored or uploaded data.\n"
                "Anyone with write access could silently change your data.\n\nDisable it anyway?"):
            self.mht_var.set(True)
            return

        def done(_):
            self.bus.emit("owner", f"MHT protection on the cloud is now {'ON' if on else 'OFF'}")
            self.info("MHT protection " + ("ENABLED" if on else "DISABLED"),
                      "The cloud server will now verify every upload, write and computation."
                      if on else "The cloud server no longer verifies your data.")

        self.run_bg(lambda: self.core.set_mht(on), done)

    def _compute(self, everything):
        if not self.core.ds_id:
            return self.warn("Nothing uploaded yet", "Upload a dataset first.")
        names = list(self.core.data["names"]) if everything else list(self.ctree.selection())
        if not names:
            return self.warn("Select a column", "Click a column in the table first.")
        self.set_busy(True)
        self.set_progress(None, None, "Cloud is computing on encrypted data...")

        def done(res):
            self.set_busy(False)
            self.set_progress(1, 1, "Done.")
            if res["refused"]:
                self.bus.emit("owner", "Cloud REFUSED to compute: integrity check failed")
                return self.error("Cloud refused to compute", res["message"])
            bad = []
            for r in res["rows"]:
                ok = r["match"]
                self.ctree.item(r["name"], tags=("good" if ok else "bad",),
                                values=(r["name"], f"{r['cloud']:,.2f}", f"{r['local']:,.2f}",
                                        "match" if ok else "MISMATCH"))
                if not ok:
                    bad.append(r["name"])
            if bad:
                self.bus.emit("owner", f"Results DO NOT match local data: {', '.join(bad)}")
                self.warn("Results do not match!",
                          f"The cloud's answer differs from your local data for: {', '.join(bad)}.\n\n"
                          f"The data stored in the cloud may have been corrupted. "
                          f"Ask the Third-Party Auditor to run an audit.")
            else:
                self.bus.emit("owner", "Cloud results match local data")
                self.info("All results match", f"The cloud's answers for {len(res['rows'])} column(s) match "
                                               f"your local data.")

        self.run_bg(lambda: self.core.compute(names), done)


# =====================================================================================
class AuditorWindow(RoleWindow):
    ROLE = "auditor"

    def make_core(self, api):
        return AuditorCore(api)

    def build_body(self, body):
        ttk.Label(body, text="You hold NO decryption key. You only see encrypted bytes and fingerprints.",
                  foreground="#1e8449").pack(anchor="w", pady=(0, 4))
        f1 = ttk.LabelFrame(body, text="1   Audit ticket received from the data owner")
        f1.pack(fill="x", pady=4)
        row = ttk.Frame(f1)
        row.pack(fill="x", padx=6, pady=4)
        self.mk_button(row, "Open ticket from the cloud", self._load_ticket)
        self.ticket_lbl = ttk.Label(row, text="No ticket loaded")
        self.ticket_lbl.pack(side="left", padx=10)

        f2 = ttk.LabelFrame(body, text="2   Audit the cloud copy")
        f2.pack(fill="x", pady=4)
        row = ttk.Frame(f2)
        row.pack(fill="x", padx=6, pady=4)
        self.mode = tk.StringVar(value="full")
        ttk.Radiobutton(row, text="Full audit (every object)", variable=self.mode, value="full").pack(side="left", padx=4)
        ttk.Radiobutton(row, text="Random sample of", variable=self.mode, value="sample").pack(side="left", padx=4)
        self.sample_var = tk.StringVar(value="10")
        ttk.Spinbox(row, from_=1, to=500, width=5, textvariable=self.sample_var).pack(side="left")
        ttk.Label(row, text="objects").pack(side="left", padx=(2, 12))
        self.mk_button(row, "Run audit", self._audit)

        self.verdict = tk.Label(body, text="No audit run yet", font=("Segoe UI", 16, "bold"),
                                bg="#ecf0f1", fg="#555555", pady=8)
        self.verdict.pack(fill="x", pady=4)

        cols = ("Object", "Cloud copy fingerprint", "Ticket fingerprint", "Result")
        self.rtree = ttk.Treeview(body, columns=cols, show="headings", height=8)
        for c, w in zip(cols, (110, 230, 230, 170)):
            self.rtree.heading(c, text=c)
            self.rtree.column(c, width=w)
        self.rtree.tag_configure("good", background="#d5f5e3")
        self.rtree.tag_configure("bad", background="#f5b7b1")
        self.rtree.pack(fill="both", expand=True, pady=4)
        self.rtree.bind("<<TreeviewSelect>>", self._show_preview)
        self.rows = {}

        f3 = ttk.LabelFrame(body, text="What the auditor sees of the actual data (select an object above)")
        f3.pack(fill="x", pady=4)
        self.preview = tk.Text(f3, height=3, wrap="char", font=("Consolas", 9), state="disabled", bg="#fafafa")
        self.preview.pack(fill="x", padx=6, pady=4)

    def _load_ticket(self):
        def listed(names):
            if not names:
                return self.warn("No tickets yet", "The cloud ticket box is empty. Ask the data owner to send one.")
            choice = pick(self, "Audit tickets in cloud storage", names)
            if not choice:
                return

            def loaded(t):
                self.ticket_lbl.config(text=f"{t['dataset']}  |  version {t['version']}  |  "
                                            f"{len(t['_leaves'])} objects  |  root {t['root'][:12]}...")
                self.bus.emit("auditor", f"Received ticket for '{t['dataset']}' v{t['version']}")
                self.info("Ticket loaded", f"Ticket from {t['issued_by']}\nDataset: {t['dataset']} "
                                           f"(version {t['version']})\nObjects to verify: {len(t['_leaves'])}\n\n"
                                           f"The ticket is consistent. You can now audit the cloud copy.")

            self.run_bg(lambda: self.core.fetch_ticket(choice), loaded)

        self.run_bg(self.core.list_tickets, listed)

    def _audit(self):
        if not self.core.ticket:
            return self.warn("No ticket", "Load the audit ticket from the data owner first.")
        full = self.mode.get() == "full"
        try:
            sample = int(self.sample_var.get())
        except ValueError:
            sample = 10
        self.set_busy(True)

        def work():
            return self.core.audit(full, sample, lambda a, b: self.ui(
                lambda: self.set_progress(a, b, f"Checking encrypted objects {a}/{b}...")))

        def done(res):
            self.set_busy(False)
            self.rtree.delete(*self.rtree.get_children())
            self.rows = {}
            for r in res["rows"]:
                iid = self.rtree.insert("", "end", tags=("good" if r["ok"] else "bad",),
                                        values=(r["name"], r["server_fp"], r["ticket_fp"],
                                                "match" if r["ok"] else "MISMATCH"))
                self.rows[iid] = r
            kind = "full audit" if res["full"] else f"sample of {res['checked']}/{res['total']}"
            note = ""
            if res["server_version"] != res["ticket_version"]:
                note = (f"\n\nNote: the cloud reports version {res['server_version']} but your ticket is "
                        f"version {res['ticket_version']}.")
            if res["passed"]:
                self.verdict.config(text=f"AUDIT PASSED  ({kind})", bg="#d5f5e3", fg="#1e8449")
                self.bus.emit("auditor", f"Audit PASSED ({kind})")
                extra = "" if res["full"] else "\n\nA sample cannot prove every object is intact - run a full audit for certainty."
                self.info("Audit passed", f"All {res['checked']} checked objects match the owner's registered "
                                          f"Merkle tree. The cloud copy is intact.{extra}{note}")
            else:
                names = ", ".join(r["name"] for r in res["rows"] if not r["ok"])
                self.verdict.config(text=f"AUDIT FAILED - DATA CORRUPTED  ({res['bad']} bad object(s))",
                                    bg="#f5b7b1", fg="#922b21")
                self.bus.emit("auditor", f"Audit FAILED: data corrupted ({names})")
                self.error("AUDIT FAILED - data corrupted",
                           f"{res['bad']} of {res['checked']} checked objects do NOT match what the owner "
                           f"stored:\n{names}\n\nThe data on the cloud server was modified after upload. "
                           f"Notify the data owner immediately.{note}")

        self.run_bg(work, done)

    def _show_preview(self, _event):
        sel = self.rtree.selection()
        if not sel:
            return
        r = self.rows[sel[0]]
        self.preview.config(state="normal")
        self.preview.delete("1.0", "end")
        self.preview.insert("end", f"{r['name']}  first bytes of the ciphertext:\n{r['preview']}...\n"
                                   f"(encrypted - unreadable without the owner's secret key)")
        self.preview.config(state="disabled")


# =====================================================================================
class AdversaryWindow(RoleWindow):
    ROLE = "adversary"

    def make_core(self, api):
        return AdversaryCore(api)

    def build_body(self, body):
        ttk.Label(body, text="You found a leaked cloud-storage credential. You can read and overwrite "
                             "stored objects - but everything is encrypted.", foreground="#a93226",
                  wraplength=820).pack(anchor="w", pady=(0, 4))
        f1 = ttk.LabelFrame(body, text="1   Cloud storage reachable with the stolen credential")
        f1.pack(fill="both", expand=True, pady=4)
        row = ttk.Frame(f1)
        row.pack(fill="x", padx=6, pady=4)
        self.ds_var = tk.StringVar()
        self.ds_combo = ttk.Combobox(row, textvariable=self.ds_var, state="readonly", width=22)
        self.ds_combo.pack(side="left", padx=4)
        self.mk_button(row, "Refresh", self._refresh)
        cols = ("Object", "Size")
        self.otree = ttk.Treeview(f1, columns=cols, show="headings", height=8)
        for c, w in zip(cols, (200, 160)):
            self.otree.heading(c, text=c)
            self.otree.column(c, width=w)
        self.otree.pack(fill="both", expand=True, padx=6)
        self.otree.bind("<<TreeviewSelect>>", self._peek)
        self.peek = tk.Text(f1, height=3, wrap="char", font=("Consolas", 9), state="disabled", bg="#fafafa")
        self.peek.pack(fill="x", padx=6, pady=4)

        f2 = ttk.LabelFrame(body, text="2   Attacks")
        f2.pack(fill="x", pady=4)
        row = ttk.Frame(f2)
        row.pack(fill="x", padx=6, pady=4)
        self.mk_button(row, "A. Copy all objects (snapshot)", self._snapshot)
        self.mk_button(row, "B. Malleability attack on selected object", self._malleability)
        self.mk_button(row, "C. Replay the old snapshot", self._replay)
        self.outcome = tk.Label(body, text="No attack launched yet", font=("Segoe UI", 15, "bold"),
                                bg="#ecf0f1", fg="#555555", pady=8)
        self.outcome.pack(fill="x", pady=4)

    def on_login(self, header):
        self._refresh()

    def _set_outcome(self, ok, text):
        self.outcome.config(text=text, bg="#fadbd8" if ok else "#d6eaf8", fg="#922b21" if ok else "#1f618d")

    def _refresh(self):
        current = self.ds_var.get()

        def work():
            dss = self.core.datasets()
            ds = current or (dss[0]["id"] if dss else "")
            return [d["id"] for d in dss], ds, (self.core.objects(ds) if ds else [])

        def done(res):
            ids, ds, objs = res
            self.ds_combo.config(values=ids)
            self.ds_var.set(ds)
            self.otree.delete(*self.otree.get_children())
            for o in objs:
                self.otree.insert("", "end", iid=str(o["index"]), values=(o["name"], f"{o['size']:,} bytes"))
            self.log(f"Storage listing: {len(ids)} dataset(s), {len(objs)} object(s) in '{ds}'")

        self.run_bg(work, done)

    def _peek(self, _event):
        sel = self.otree.selection()
        ds = self.ds_var.get()
        if not sel or not ds:
            return

        def done(blob):
            self.peek.config(state="normal")
            self.peek.delete("1.0", "end")
            self.peek.insert("end", f"{blob[:64].hex()}...\n(ciphertext - meaningless without the owner's secret key)")
            self.peek.config(state="disabled")

        self.run_bg(lambda: self.core.get(ds, int(sel[0])), done)

    def _snapshot(self):
        ds = self.ds_var.get()
        if not ds:
            return self.warn("No dataset", "Refresh the storage listing first.")
        self.set_busy(True)

        def done(n):
            self.set_busy(False)
            self.set_progress(1, 1, "Snapshot saved.")
            self.bus.emit("adversary", f"Copied {n} encrypted objects of '{ds}' (snapshot)")
            self.info("Snapshot saved", f"Copied {n} encrypted objects of '{ds}'.\n\nKeep them: you can replay "
                                        f"this old version later, after the owner updates the data.")

        self.run_bg(lambda: self.core.snapshot(ds, lambda a, b: self.ui(
            lambda: self.set_progress(a, b, f"Copying objects {a}/{b}..."))), done)

    def _malleability(self):
        ds, sel = self.ds_var.get(), self.otree.selection()
        if not ds or not sel:
            return self.warn("Select an object", "Click one object in the list first.")
        factor = simpledialog.askfloat("Malleability attack",
                                       "Multiply every value inside the selected encrypted object by:",
                                       initialvalue=2.0, minvalue=0.01, parent=self)
        if factor is None:
            return
        self.set_busy(True)
        self.set_progress(None, None, "Forging the ciphertext and writing it back to the cloud...")

        def done(res):
            self.set_busy(False)
            self.set_progress(1, 1, "Done.")
            if res["accepted"]:
                self._set_outcome(True, "ATTACK SUCCEEDED - forged object accepted by the cloud")
                self.bus.emit("adversary", f"Malleability attack x{factor} SUCCEEDED")
                self.info("Attack succeeded", f"The cloud accepted the forged object.\nEvery value in that block "
                                              f"is now multiplied by {factor}, and the server raised no alarm.")
            else:
                self._set_outcome(False, "ATTACK BLOCKED by the cloud server")
                self.bus.emit("adversary", f"Malleability attack x{factor} BLOCKED")
                self.error("Attack blocked", f"The cloud rejected the modified object:\n\n{res['message']}")

        self.run_bg(lambda: self.core.malleability(ds, int(sel[0]), factor), done)

    def _replay(self):
        ds = self.ds_var.get()
        if ds not in self.core.snapshots:
            return self.warn("No snapshot", "Take a snapshot first (button A), then wait for the owner "
                                            "to update the data.")
        self.set_busy(True)

        def done(res):
            self.set_busy(False)
            self.set_progress(1, 1, "Done.")
            if res["changed"] == 0:
                return self.info("Nothing to replay", "The cloud still holds exactly the version you copied.\n\n"
                                 "Switch to the Cloud User (F1), let them run a monthly update, then come back.")
            if res["accepted"]:
                self._set_outcome(True, f"ATTACK SUCCEEDED - {res['accepted']} stale object(s) restored")
                self.bus.emit("adversary", f"Replay attack SUCCEEDED ({res['accepted']} stale objects restored)")
                self.info("Attack succeeded", f"The cloud accepted {res['accepted']} outdated object(s).\n"
                                              f"The dataset is silently rolled back to the old version.")
            else:
                self._set_outcome(False, "ATTACK BLOCKED by the cloud server")
                self.bus.emit("adversary", f"Replay attack BLOCKED ({res['rejected']} rejected)")
                self.error("Attack blocked", f"The cloud rejected all {res['rejected']} stale object(s):\n\n"
                                             f"{res['message']}")

        self.run_bg(lambda: self.core.replay(ds, lambda a, b: self.ui(
            lambda: self.set_progress(a, b, f"Replaying objects {a}/{b}..."))), done)


WINDOWS = {"owner": OwnerWindow, "auditor": AuditorWindow, "adversary": AdversaryWindow}
