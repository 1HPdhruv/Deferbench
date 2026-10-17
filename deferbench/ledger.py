"""Provenance ledger: authored content units, untrusted inputs, approvals. Lives OUTSIDE the workspace."""
from __future__ import annotations
import hashlib
import json
import os
import time


class LedgerLocationError(Exception):
    pass


def _inside(child: str, parent: str) -> bool:
    child, parent = os.path.realpath(child), os.path.realpath(parent)
    return child == parent or child.startswith(parent + os.sep)


class Ledger:
    def __init__(self, ledger_dir: str, workspace: str):
        self.dir = os.path.realpath(ledger_dir)
        self.ws = os.path.realpath(workspace)
        if _inside(self.dir, self.ws) or _inside(self.ws, self.dir):
            raise LedgerLocationError("ledger directory must be outside (and not contain) the untrusted workspace")
        os.makedirs(self.dir, exist_ok=True)
        key = hashlib.sha256(self.ws.encode()).hexdigest()[:16]
        self.path = os.path.join(self.dir, f"{key}.json")
        self.snap_path = os.path.join(self.dir, f"{key}.snap.json")
        self.data = self._load(self.path) or {"version": 1, "workspace": self.ws, "step": 0, "untrusted": [],
                                              "authored": {}, "approvals": {}, "pending": {}}

    @staticmethod
    def _load(p):
        try:
            return json.load(open(p))
        except Exception:
            return None

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f: json.dump(self.data, f)
        os.replace(tmp, self.path)

    def load_snap(self):
        return self._load(self.snap_path) or {}

    def save_snap(self, snap):
        tmp = self.snap_path + ".tmp"
        with open(tmp, "w") as f: json.dump(snap, f)
        os.replace(tmp, self.snap_path)

    # -- untrusted inputs
    def add_untrusted(self, source: str, session: str):
        self.data["untrusted"].append({"source": source, "session": session, "step": self.data["step"], "t": time.time()})

    def taint(self, session: str):
        u = [x["source"] for x in self.data["untrusted"] if x["session"] == session]
        return u[-1] if u else None

    # -- authored units
    def record(self, relpath: str, unit_hash: str, text: str, session: str, how: str, derived_from: str | None = None):
        files = self.data["authored"].setdefault(relpath, {})
        t = self.taint(session)
        old = files.get(unit_hash)
        if old and old.get("after_untrusted") and not t:
            return  # keep the more conservative provenance
        files[unit_hash] = {"line": text[:200], "step": self.data["step"], "session": session, "how": how,
                            "after_untrusted": t, "derived_from": derived_from}

    def lookup(self, relpath: str, unit_hash: str):
        return self.data["authored"].get(relpath, {}).get(unit_hash)

    def find_anywhere(self, unit_hash: str):
        for f, units in self.data["authored"].items():
            if unit_hash in units: return f, units[unit_hash]
        return None

    def tainted_units(self, exclude_ext=()):
        n = []
        for f, units in self.data["authored"].items():
            if f.lower().endswith(tuple(exclude_ext)): continue
            n += [(f, h) for h, r in units.items() if r.get("after_untrusted")]
        return n

    # -- approvals bind (action, closure content hash)
    def approve(self, action_hash: str, closure_hash: str, note: str = ""):
        self.data["approvals"][action_hash] = {"closure_hash": closure_hash, "step": self.data["step"], "note": note}

    def approval(self, action_hash: str):
        return self.data["approvals"].get(action_hash)
