"""
Demo launcher.

  python launcher.py                  Control Room + all three people (switch perspective with F1/F2/F3)
  python launcher.py --role auditor   only one person's window (run it on a different computer)
"""
import argparse
import json
import os
import random
import time
import tkinter as tk
from tkinter import messagebox, ttk

from windows import THEMES, WINDOWS, Bus, save_config


def load_config(path):
    if not os.path.exists(path):
        raise SystemExit(f"{path} not found. Download demo_config.json from the S3 bucket "
                         f"(config/ folder) and set server_url.")
    cfg = json.load(open(path))
    cfg["_path"] = path
    cfg.setdefault("datasets", {"Dataset 1": "dataset1.csv", "Dataset 2": "dataset2.csv", "Dataset 3": "dataset3.csv"})
    return cfg


class ControlRoom:
    """The director's panel: switch perspective, plan the three dataset tests, watch the story."""

    def __init__(self, root, cfg, bus):
        self.root, self.cfg, self.bus = root, cfg, bus
        root.title("Demo Control Room")
        root.geometry("420x700+10+10")
        root.attributes("-topmost", True)
        tk.Label(root, text="Demo Control Room", font=("Segoe UI", 16, "bold")).pack(pady=(10, 2))
        tk.Label(root, text="One cloud server - three people", fg="#555555").pack()

        f = ttk.LabelFrame(root, text="Switch perspective (or press F1 / F2 / F3)")
        f.pack(fill="x", padx=10, pady=8)
        for role, key in (("owner", "F1"), ("auditor", "F2"), ("adversary", "F3")):
            th = THEMES[role]
            tk.Button(f, text=f"{th['icon']}  {th['title']}   [{key}]", bg=th["color"], fg="white",
                      activebackground=th["color"], font=("Segoe UI", 11, "bold"), pady=6,
                      command=lambda r=role: bus.switch(r)).pack(fill="x", padx=8, pady=3)

        p = ttk.LabelFrame(root, text="Test plan: 3 datasets with MHT ON, then 1 random dataset with MHT OFF")
        p.pack(fill="x", padx=10, pady=4)
        ttk.Label(p, text="CSV file names inside the cloud bucket (source/ folder):").pack(anchor="w", padx=8, pady=(4, 0))
        self.vars = {}
        for name in cfg["datasets"]:
            row = ttk.Frame(p)
            row.pack(fill="x", padx=6, pady=2)
            ttk.Label(row, text=name, width=10).pack(side="left")
            v = tk.StringVar(value=cfg["datasets"][name])
            v.trace_add("write", lambda *a, n=name, v=v: self._set_file(n, v.get()))
            self.vars[name] = v
            ttk.Entry(row, textvariable=v, width=30).pack(side="left")
        ttk.Button(p, text="Pick the random dataset for the MHT-OFF test", command=self._pick).pack(
            fill="x", padx=6, pady=6)
        self.pick_lbl = ttk.Label(p, text="MHT-OFF test dataset: (not drawn yet)")
        self.pick_lbl.pack(anchor="w", padx=8, pady=(0, 6))

        t = ttk.LabelFrame(root, text="Story timeline")
        t.pack(fill="both", expand=True, padx=10, pady=8)
        self.timeline = tk.Text(t, state="disabled", wrap="word", font=("Segoe UI", 9), bg="#fafafa")
        self.timeline.pack(fill="both", expand=True, padx=4, pady=4)
        for role in THEMES:
            self.timeline.tag_configure(role, foreground=THEMES[role]["color"])
        bus.listeners.append(self.add_event)

    def _set_file(self, name, value):
        self.cfg["datasets"][name] = value.strip()
        save_config(self.cfg)

    def _pick(self):
        ready = [n for n, p in self.cfg["datasets"].items() if p]
        if not ready:
            return messagebox.showwarning("No datasets", "Set at least one dataset path first.", parent=self.root)
        choice = random.choice(ready)
        self.pick_lbl.config(text=f"MHT-OFF test dataset: {choice}")
        self.add_event("owner", f"Random draw: the MHT-OFF test will use '{choice}' (run it once)")
        messagebox.showinfo("Random draw", f"The MHT-OFF test will be run once on:\n\n{choice}\n\n"
                                           f"Finish the MHT-ON tests first, then switch the owner's "
                                           f"MHT protection off.", parent=self.root)

    def add_event(self, role, text):
        th = THEMES[role]
        self.timeline.config(state="normal")
        self.timeline.insert("end", f"[{time.strftime('%H:%M:%S')}] {th['icon']} {th['title']}: {text}\n", role)
        self.timeline.see("end")
        self.timeline.config(state="disabled")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", choices=list(WINDOWS), help="open only this person's window")
    ap.add_argument("--config", default="demo_config.json")
    args = ap.parse_args()
    cfg = load_config(args.config)

    root = tk.Tk()
    ttk.Style().theme_use("clam")
    bus = Bus()
    sw, sh = root.winfo_screenwidth(), root.winfo_screenheight()

    if args.role:
        root.withdraw()
        win = WINDOWS[args.role](root, cfg, bus, f"{min(980, sw - 80)}x{min(760, sh - 80)}+40+20")
        win.protocol("WM_DELETE_WINDOW", root.destroy)
        root.mainloop()
        return

    ControlRoom(root, cfg, bus)
    x = 440
    geometry = f"{min(980, sw - x - 20)}x{min(780, sh - 80)}+{x}+10"
    wins = {role: cls(root, cfg, bus, geometry) for role, cls in WINDOWS.items()}

    def switch(role):
        w = wins[role]
        w.deiconify()
        w.lift()
        w.focus_force()
        root.lift()                                   # keep the Control Room visible

    bus.switch_fn = switch
    for w in wins.values():
        w.protocol("WM_DELETE_WINDOW", root.destroy)
    switch("owner")
    root.mainloop()


if __name__ == "__main__":
    main()
