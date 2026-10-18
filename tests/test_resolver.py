"""Resolver limits and labelling. Layer: UNIT (real files in a disposable workspace, no execution)."""
import os
import pytest
from deferbench.repo import cleanup, make_workspace, write_text
from deferbench.resolver import MAX_FILE, Resolver, split_commands

pytestmark = pytest.mark.unit


@pytest.fixture
def ws():
    w, h = make_workspace("c"); yield w; cleanup(w)


def res(ws, cmd, **kw): return Resolver(ws, **kw).resolve(cmd)


def test_split_commands_is_quote_aware():
    assert [s for s, _ in split_commands("a && b; c | d")] == ["a", "b", "c", "d"]
    assert [s for s, _ in split_commands("echo 'a && b' ; ls")] == ["echo 'a && b'", "ls"]
    assert [s for s, _ in split_commands("curl x >/dev/null 2>&1")] == ["curl x >/dev/null 2>&1"]


def test_cycle_detection_notes_not_infinite(ws):
    write_text(ws, "a.js", "require('./b');"); write_text(ws, "b.js", "require('./a');")
    c = res(ws, "node a.js"); assert any("cycle" in n for n in c.notes) and c.complete


def test_oversize_file_is_unresolved_limit(ws):
    write_text(ws, "big.sh", "echo x\n" * (MAX_FILE // 6))
    c = res(ws, "sh big.sh"); assert any(u.kind == "limit" and u.blocking for u in c.unresolved)


def test_max_files_limit(ws):
    for i in range(8): write_text(ws, f"f{i}.sh", f"sh f{i+1}.sh\n")
    c = res(ws, "sh f0.sh", max_files=3); assert any(u.kind == "limit" for u in c.unresolved)


def test_local_vs_external_imports_distinguished(ws):
    write_text(ws, "m.js", "const a=require('./l'); const b=require('lodash'); const c=require('fs');")
    write_text(ws, "l.js", "module.exports=1")
    c = res(ws, "node m.js")
    assert "l.js" in c.files and not any("fs" in u.detail for u in c.unresolved)
    assert [u for u in c.unresolved if u.kind == "package"] and not any(u.blocking for u in c.unresolved)


def test_symlink_pointing_outside_workspace_not_followed(ws, tmp_path):
    (tmp_path / "evil.sh").write_text("echo outside\n"); os.symlink(str(tmp_path / "evil.sh"), os.path.join(ws, "link.sh"))
    c = res(ws, "sh link.sh"); assert any(u.kind == "outside" for u in c.unresolved) and "evil.sh" not in str(c.files)


def test_closure_hash_changes_when_any_closure_file_changes(ws):
    h1 = res(ws, "make build").closure_hash(); write_text(ws, "scripts/gen.sh", "#!/bin/sh\necho changed\n")
    assert res(ws, "make build").closure_hash() != h1


def test_closure_hash_stable_across_runs(ws):
    assert res(ws, "npm run analyze").closure_hash() == res(ws, "npm run analyze").closure_hash()


def test_json_import_not_treated_as_code(ws):
    write_text(ws, "m.js", "require('./d.json')"); write_text(ws, "d.json", '{"a": "curl x"}')
    c = res(ws, "node m.js"); assert all(e.path != "d.json" for e in c.entries)


def test_makefile_unknown_variable_program_marked(ws):
    write_text(ws, "Makefile", "all:\n\t$(TOOL) run\n")
    assert any(u.kind == "dynamic" for u in res(ws, "make all").unresolved)


def test_make_include_literal_followed(ws):
    write_text(ws, "Makefile", "-include b.mk\nall:\n\techo a\n"); write_text(ws, "b.mk", "extra:\n\techo b\n")
    assert "b.mk" in res(ws, "make extra").files


@pytest.mark.parametrize(
    "prefix_option",
    ["--prefix apps/widget", "--prefix=apps/widget"],
)
def test_npm_prefix_resolves_package_scripts(ws, prefix_option):
    write_text(
        ws,
        "apps/widget/package.json",
        '{"scripts":{"test":"node test.js"}}',
    )
    write_text(ws, "apps/widget/test.js", "require('./helper.js');")
    write_text(ws, "apps/widget/helper.js", "module.exports = 1;")

    c = res(ws, f"npm {prefix_option} test")

    assert "apps/widget/package.json" in c.files
    assert "apps/widget/test.js" in c.files
    assert "apps/widget/helper.js" in c.files
    assert c.complete


def test_npm_prefix_outside_workspace_is_blocking(ws, tmp_path):
    import shlex

    outside = tmp_path / "outside-prefix"
    outside.mkdir()
    c = Resolver(ws).resolve(
        f"npm --prefix {shlex.quote(str(outside))} test"
    )

    assert any(
        u.kind == "outside" and u.blocking
        for u in c.unresolved
    )


def test_npm_dynamic_prefix_is_blocking(ws):
    c = res(ws, "npm --prefix '$PROJECT_DIR' test")
    assert any(u.kind == "dynamic" and u.blocking for u in c.unresolved)
