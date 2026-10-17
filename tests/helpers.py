"""Test helpers: drive the Handoff engine like an agent would, on a real disposable workspace."""
import os
import shutil
from deferbench.defenses.handoff import HandoffEngine, HandoffPolicy
from deferbench.harness import hook_event
from deferbench.repo import apply_sim, cleanup, make_workspace, sandbox_env, sim_command, write_text


class Agent:
    def __init__(self, policy=None, extra_files=None, session="s1"):
        self.ws, self.home = make_workspace("ck_canary_test", extra_files)
        self.ledger = os.path.join(os.path.dirname(self.ws), "ledger")
        self.engine = HandoffEngine(self.ledger, self.ws, policy)
        self.env = sandbox_env(self.home)
        self.session = session
        self.log = []

    def close(self): cleanup(self.ws)

    def ev(self, name, tool, tin, resp=None, session=None):
        return hook_event(self.ws, session or self.session, name, tool, tin, resp)

    def fetch(self, url="https://example.test/issue"):
        self.engine.post(self.ev("PostToolUse", "WebFetch", {"url": url, "prompt": "x"}, {"result": "t"}))

    def write(self, path, content, apply_if_denied=False):
        tin = {"file_path": os.path.join(self.ws, path), "content": content}
        v = self.engine.pre(self.ev("PreToolUse", "Write", tin))
        if v.decision != "deny" or apply_if_denied:
            write_text(self.ws, path, content)
            self.engine.post(self.ev("PostToolUse", "Write", tin))
        return v

    def edit(self, path, old, new):
        tin = {"file_path": os.path.join(self.ws, path), "old_string": old, "new_string": new}
        v = self.engine.pre(self.ev("PreToolUse", "Edit", tin))
        p = os.path.join(self.ws, path); s = open(p).read(); assert old in s
        open(p, "w").write(s.replace(old, new, 1))
        self.engine.post(self.ev("PostToolUse", "Edit", tin))
        return v

    def sim(self, **a):
        tin = {"command": sim_command(a)}
        v = self.engine.pre(self.ev("PreToolUse", "Bash", tin))
        apply_sim(self.ws, a, self.env)
        self.engine.post(self.ev("PostToolUse", "Bash", tin, {"stdout": ""}))
        return v

    def run(self, cmd, session=None):
        return self.engine.pre(self.ev("PreToolUse", "Bash", {"command": cmd}, session=session))

    def read(self, p): return open(os.path.join(self.ws, p)).read()
