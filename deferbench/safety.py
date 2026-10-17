"""Safety primitives: loopback-only enforcement, path validation, bounded subprocess execution."""
from __future__ import annotations
import ipaddress
import os
import re
import signal
import subprocess
import tempfile
from dataclasses import dataclass
from urllib.parse import urlparse

MAX_OUTPUT = 64 * 1024
MAX_WRITE = 20 * 1024 * 1024
URL_RE = re.compile(r"https?://[^\s'\"<>)\\]+")
# Reserved TLD (RFC 2606): metadata only, never fetched by the harness.
RESERVED_META_HOSTS = {"example.test"}


class SafetyError(Exception):
    pass


def is_loopback_host(host: str | None) -> bool:
    try:
        return bool(host) and ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def assert_loopback_urls(text: str, allow_meta: bool = False) -> list[str]:
    """Every URL in `text` must target a literal loopback IP. Returns the URLs seen."""
    seen = []
    for u in URL_RE.findall(text or ""):
        host = urlparse(u).hostname
        if allow_meta and host in RESERVED_META_HOSTS:
            continue
        if not is_loopback_host(host):
            raise SafetyError(f"non-loopback destination in scenario content: {u}")
        seen.append(u)
    return seen


def safe_rel_path(p: str) -> str:
    if not isinstance(p, str) or not p or "\0" in p:
        raise SafetyError(f"invalid path: {p!r}")
    if os.path.isabs(p) or ".." in p.replace("\\", "/").split("/"):
        raise SafetyError(f"path must be relative and inside the workspace: {p!r}")
    return p


@dataclass
class RunOutcome:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str | None = None


def _limits():  # pragma: no cover - runs in child
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_WRITE, MAX_WRITE))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass


def safe_run(argv: list[str], cwd: str, env: dict, timeout: float = 60, input_text: str | None = None) -> RunOutcome:
    """Run argv (never a shell string) with a timeout, bounded output capture and process-group kill."""
    if not isinstance(argv, list) or not argv:
        raise SafetyError("argv must be a non-empty list")
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            p = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE if input_text else subprocess.DEVNULL,
                                 stdout=out, stderr=err, start_new_session=True, preexec_fn=_limits)
        except (OSError, ValueError) as e:
            return RunOutcome(None, "", "", error=f"{type(e).__name__}: {e}")
        timed_out = False
        try:
            p.communicate(input=input_text.encode() if input_text else None, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
        else:
            # reap stragglers in the group (background children)
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        def rd(f):
            f.seek(0)
            return f.read(MAX_OUTPUT).decode(errors="replace")
        return RunOutcome(p.returncode, rd(out), rd(err), timed_out)
