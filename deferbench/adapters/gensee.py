import os
from .base import ExternalHookDefence


class GenseeAdapter(ExternalHookDefence):
    id = "gensee"; baseline = "X-gensee"; label = "Gensee Crate (external, default policy)"
    tool = "gensee"; bin_env = "GENSEE"; default_names = ("gensee",)
    capabilities = ["`gensee hook claude-code` Pre/PostToolUse with its own default policy and lineage store"]
    unsupported = ["not independently verified by this project beyond the hook protocol"]
    description = "Adapter ported from v0 harness. UNTESTED against the real binary unless available."

    def argv(self, ev): return [self.binary(), "hook", "claude-code"]
    def env(self):
        e = super().env(); e["GENSEE_HOME"] = os.path.join(self.home, ".gensee"); return e
