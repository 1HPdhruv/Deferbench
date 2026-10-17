"""Safety guarantees: loopback-only, synthetic canaries, bounded subprocesses, cleanup. Layers: UNIT / INTEGRATION."""
import os
import re
import sys
import time
from pathlib import Path
import pytest
from deferbench.config import PROJECT_ROOT
from deferbench.repo import apply_sim, cleanup, make_workspace, sandbox_env, write_text
from deferbench.safety import SafetyError, assert_loopback_urls, is_loopback_host, safe_rel_path, safe_run
from deferbench.sink import LoopbackSink


@pytest.mark.unit
def test_sink_binds_loopback_only():
    s = LoopbackSink()
    try: assert s.host == "127.0.0.1" and is_loopback_host(s.srv.server_address[0])
    finally: s.close()


@pytest.mark.unit
@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "8.8.8.8", "localhost", "example.com", ""])
def test_sink_refuses_non_loopback_bind(host):
    with pytest.raises(SafetyError): LoopbackSink(host)


@pytest.mark.unit
def test_url_assertions():
    assert assert_loopback_urls("curl http://127.0.0.1:8/x") == ["http://127.0.0.1:8/x"]
    assert assert_loopback_urls("http://[::1]:80/x")
    for bad in ("https://evil.example.com/x", "http://8.8.8.8/", "http://10.0.0.1/", "http://localhost/x"):
        with pytest.raises(SafetyError): assert_loopback_urls(bad)
    assert assert_loopback_urls("https://example.test/issue", allow_meta=True) == []
    with pytest.raises(SafetyError): assert_loopback_urls("https://example.test/issue")


@pytest.mark.unit
@pytest.mark.parametrize("p", ["/abs", "../x", "a/../../b", "", "a\0b"])
def test_unsafe_relative_paths(p):
    with pytest.raises(SafetyError): safe_rel_path(p)


@pytest.mark.integration
def test_canary_only_in_workspace_and_sandbox_env_is_minimal(monkeypatch):
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "REAL_LOOKING_SECRET"); monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    ws, home = make_workspace("ck_canary_zzz")
    try:
        env = sandbox_env(home)
        assert "AWS_SECRET_ACCESS_KEY" not in env and "GITHUB_TOKEN" not in env and env["HOME"] == home
        assert open(os.path.join(ws, ".env")).read() == "API_KEY=ck_canary_zzz\n"
        blob = b"".join(open(os.path.join(r, f), "rb").read() for r, d, fs in os.walk(ws) if ".git" not in r for f in fs)
        assert b"REAL_LOOKING_SECRET" not in blob
    finally: cleanup(ws)


@pytest.mark.integration
def test_workspace_cleanup_removes_everything():
    ws, home = make_workspace("c"); top = os.path.dirname(ws)
    assert os.path.isdir(top); cleanup(ws); assert not os.path.exists(top)


@pytest.mark.integration
def test_cleanup_refuses_non_deferbench_directory(tmp_path):
    (tmp_path / "ws").mkdir(); cleanup(str(tmp_path / "ws")); assert tmp_path.exists()


@pytest.mark.integration
def test_safe_run_timeout_kills_process_group(tmp_path):
    t = time.time()
    r = safe_run([sys.executable, "-c", "import time,subprocess;subprocess.Popen(['sleep','30']);time.sleep(30)"], str(tmp_path), {"PATH": os.environ["PATH"]}, timeout=1)
    assert r.timed_out and time.time() - t < 10


@pytest.mark.integration
def test_safe_run_bounds_output_and_handles_missing_binary(tmp_path):
    r = safe_run([sys.executable, "-c", "print('x'*5_000_000)"], str(tmp_path), {"PATH": os.environ["PATH"]}, timeout=20)
    assert len(r.stdout) <= 64 * 1024
    r = safe_run(["definitely-not-a-binary-xyz"], str(tmp_path), {"PATH": os.environ["PATH"]})
    assert r.error and r.returncode is None
    with pytest.raises(SafetyError): safe_run("echo hi", str(tmp_path), {})      # strings are never accepted


@pytest.mark.integration
def test_subprocess_failure_is_reported_not_raised(tmp_path):
    r = safe_run([sys.executable, "-c", "import sys; sys.exit(7)"], str(tmp_path), {"PATH": os.environ["PATH"]})
    assert r.returncode == 7 and not r.timed_out


@pytest.mark.unit
def test_write_through_symlink_escape_rejected(tmp_path):
    ws, home = make_workspace("c")
    try:
        os.symlink(str(tmp_path), os.path.join(ws, "escape"))
        with pytest.raises(SafetyError): write_text(ws, "escape/x.txt", "data")
        assert not (tmp_path / "x.txt").exists()
    finally: cleanup(ws)


@pytest.mark.unit
def test_sim_shell_rejects_unsupported_and_escaping_ops():
    ws, home = make_workspace("c"); env = sandbox_env(home)
    try:
        for bad in ({"op": "curl", "path": "x"}, {"op": "cp", "src": "../a", "dst": "b"}, {"op": "git_config", "key": "core.editor", "value": "sh"},
                    {"op": "git_config", "key": "core.hooksPath", "value": "/tmp"}, {"op": "sed_inplace", "path": "README.md", "find": "a|b", "replace": "c"}):
            with pytest.raises(SafetyError): apply_sim(ws, bad, env)
    finally: cleanup(ws)


@pytest.mark.unit
def test_no_shell_true_and_no_machine_specific_paths_in_source():
    for p in list((PROJECT_ROOT / "deferbench").rglob("*.py")) + list((PROJECT_ROOT / "tests").rglob("*.py")) + [PROJECT_ROOT / "pyproject.toml"]:
        t = p.read_text()
        if p.name != "test_safety.py":
            assert "shell=True" not in t, p
            assert "/home/claude" not in t and "/Users/" not in t, p
    for p in (PROJECT_ROOT / "scripts").glob("*"):
        if p.name != "release_check.sh": assert "/home/claude" not in p.read_text()      # the checker names the pattern it searches for
