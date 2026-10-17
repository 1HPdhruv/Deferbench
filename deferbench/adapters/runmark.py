from .base import ExternalHookDefence


class RunmarkAdapter(ExternalHookDefence):
    id = "runmark"; baseline = "X-runmark"; label = "Runmark (external, default hook)"
    tool = "runmark"; bin_env = "RUNMARK"; default_names = ("runmark",)
    capabilities = ["`runmark hook claude` PreToolUse on Bash (touch/boundary report)"]
    unsupported = ["provenance", "authorship (not claimed by this adapter)"]
    description = "Adapter ported from v0 harness. Invocation: `runmark hook claude` with a Claude Code PreToolUse event. UNTESTED against the real binary unless available."

    def argv(self, ev): return [self.binary(), "hook", "claude"]
    def handles(self, ev, post=False): return ev.get("tool_name") == "Bash" and not post
