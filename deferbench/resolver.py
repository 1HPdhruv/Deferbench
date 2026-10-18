"""Bounded execution-closure resolver.

Given a shell command and a workspace, compute which workspace file content the command will cause to
execute for the *supported* mechanisms (npm scripts/lifecycle, Makefile, shell/Python/Node entry files and
their statically resolvable local imports, pytest conftest/config, git hooks/core.hooksPath/alias, direnv).

It is NOT a shell, npm, make or JS interpreter. Anything it cannot resolve statically is recorded as an
`Unresolved` item (blocking or informational) instead of being silently skipped.
"""
from __future__ import annotations
import json
import os
import re
import shlex
import sys
from dataclasses import dataclass, field
from .signals import sha, uhash, norm

MAX_FILE = 256 * 1024
NODE_BUILTINS = {"fs", "path", "os", "http", "https", "child_process", "crypto", "util", "events", "stream", "url",
                 "net", "zlib", "assert", "buffer", "readline", "module", "process", "timers", "tty", "dns", "vm",
                 "worker_threads", "cluster", "querystring", "string_decoder", "perf_hooks", "async_hooks", "http2"}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
PYS = {"python", "python3", "python3.11", "python3.12", "python3.13"}
CONTROL = {"if", "then", "else", "elif", "do", "while", "until", "fi", "done", "{", "}", "!", "time", "exec", "command",
           "nohup", "builtin"}
GIT_HOOKS = {"commit": ["pre-commit", "prepare-commit-msg", "commit-msg", "post-commit"], "push": ["pre-push"],
             "checkout": ["post-checkout"], "switch": ["post-checkout"], "merge": ["pre-merge-commit", "post-merge"],
             "rebase": ["pre-rebase"], "am": ["applypatch-msg", "pre-applypatch", "post-applypatch"]}
NO_VERIFY_SKIPS = {"pre-commit", "commit-msg", "pre-merge-commit", "pre-push"}
GIT_CFG_EXEC = re.compile(r"^\s*(fsmonitor|sshCommand|pager|editor|textconv|clean|smudge|process|program|helper|askPass)\s*=", re.I)
NPM_INSTALL_LIFECYCLE = ["preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"]


@dataclass
class Entry:
    path: str          # path relative to workspace (realpath-resolved)
    lineno: int | None
    text: str
    via: list[str]

    def to_dict(self):
        return {"file": self.path, "lineno": self.lineno, "text": self.text[:300], "via": self.via}


@dataclass
class Unresolved:
    kind: str          # dynamic | opaque | limit | missing | package | outside | unsupported | dependency-lifecycle
    detail: str
    blocking: bool = True

    def to_dict(self):
        return {"kind": self.kind, "detail": self.detail, "blocking": self.blocking}


@dataclass
class Closure:
    command: str
    cwd: str
    entries: list[Entry] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)       # relpath -> sha256 of content read
    unresolved: list[Unresolved] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        return not any(u.blocking for u in self.unresolved)

    def closure_hash(self) -> str:
        return sha(json.dumps({"c": self.command, "f": sorted(self.files.items())}))

    def unit_hash_of(self, e: Entry) -> str:
        return uhash(e.text)


def split_commands(s: str):
    """Quote-aware split on && || ; | & newline. Returns [(segment, op_before)]."""
    out, cur, q, i, prev = [], [], None, 0, ""
    while i < len(s):
        c = s[i]
        if q:
            cur.append(c)
            if c == "\\" and q == '"' and i + 1 < len(s): cur.append(s[i + 1]); i += 1
            elif c == q: q = None
        elif c in "'\"": q = c; cur.append(c)
        elif c == "\\" and i + 1 < len(s): cur.append(c + s[i + 1]); i += 1
        elif c == "#" and (not cur or cur[-1] in " \t"):
            while i < len(s) and s[i] != "\n": i += 1
            continue
        elif s.startswith("&&", i) or s.startswith("||", i):
            out.append(("".join(cur), prev)); cur = []; prev = s[i:i + 2]; i += 1
        elif c in ";\n&|":
            if c == "&" and i > 0 and s[i - 1] == ">": cur.append(c)
            elif c == "&" and i + 1 < len(s) and s[i + 1] == ">": cur.append(c)
            else:
                out.append(("".join(cur), prev)); cur = []; prev = c
        else: cur.append(c)
        i += 1
    out.append(("".join(cur), prev))
    return [(a.strip(), b) for a, b in out if a.strip()]


class Ctx:
    def __init__(self, cwd): self.cwd = cwd


class Resolver:
    def __init__(self, workspace: str, max_depth: int = 8, max_files: int = 300):
        self.ws = os.path.realpath(workspace)
        self.max_depth, self.max_files = max_depth, max_files
        self.c: Closure | None = None
        self._seen: set = set()

    # ---- helpers
    def rel(self, p: str) -> str:
        return os.path.relpath(os.path.realpath(p), self.ws)

    def _inside(self, real: str) -> bool:
        return real == self.ws or real.startswith(self.ws + os.sep)

    def _unres(self, kind, detail, blocking=True):
        u = Unresolved(kind, detail[:200], blocking)
        if all((x.kind, x.detail) != (u.kind, u.detail) for x in self.c.unresolved):
            self.c.unresolved.append(u)

    def _read(self, path: str, via: list[str]):
        """Return (relpath, text) for a workspace file, or None (and record why)."""
        real = os.path.realpath(path)
        if not self._inside(real):
            self._unres("outside", f"{path} resolves outside workspace (symlink or absolute path); not analysed")
            return None
        if not os.path.isfile(real): return None
        try:
            if os.path.getsize(real) > MAX_FILE:
                self._unres("limit", f"{self.rel(real)} exceeds {MAX_FILE} bytes; not analysed"); return None
            text = open(real, encoding="utf-8", errors="replace").read()
        except OSError as e:
            self._unres("missing", f"{path}: {e}", False); return None
        if len(self.c.files) >= self.max_files and self.rel(real) not in self.c.files:
            self._unres("limit", "file limit reached"); return None
        r = self.rel(real)
        self.c.files[r] = sha(text)
        return r, text

    def _add_lines(self, r: str, text: str, via: list[str]):
        for n, ln in enumerate(text.splitlines(), 1):
            if norm(ln): self.c.entries.append(Entry(r, n, ln, list(via)))

    # ---- entry point
    def resolve(self, command: str, cwd: str | None = None) -> Closure:
        cwd = os.path.realpath(cwd or self.ws)
        self.c = Closure(command, self.ws); self._seen = set()
        self._shell_string(command, Ctx(cwd), [], 0)
        return self.c

    # ---- shell
    def _shell_string(self, s: str, ctx: Ctx, via: list[str], depth: int):
        if depth > self.max_depth:
            self._unres("limit", f"depth limit {self.max_depth} reached at: {s[:60]}"); return
        for seg, op in split_commands(s):
            self._simple(seg, op, ctx, via, depth)

    def _simple(self, seg: str, op: str, ctx: Ctx, via: list[str], depth: int):
        if "$(" in seg or "`" in seg or "<(" in seg:
            self._unres("dynamic", f"command substitution: {seg[:80]}")
        try:
            t = shlex.split(seg)
        except ValueError:
            self._unres("opaque", f"unparsable: {seg[:80]}"); return
        while t and (t[0] in CONTROL or re.match(r"^[A-Za-z_]\w*=", t[0])): t = t[1:]
        if not t or t[0] in ("for", "case", "esac", "in", "function"): return
        if re.match(r"^\w+\(\)$", t[0]): return
        prog, args = t[0], t[1:]
        base = os.path.basename(prog)
        if prog.startswith("$"):
            self._unres("dynamic", f"program from variable: {prog}"); return
        if op == "|" and base in SHELLS and not [a for a in args if not a.startswith("-")]:
            self._unres("opaque", f"stdin piped into {base}: content not analysable"); return
        if base == "cd" and args:
            tgt = os.path.realpath(os.path.join(ctx.cwd, args[0]))
            if self._inside(tgt): ctx.cwd = tgt
            return
        if base in ("eval",): self._unres("dynamic", f"eval: {seg[:80]}"); return
        if base in ("xargs", "parallel"): self._unres("opaque", f"{base} builds commands from input"); return
        if base in ("npx", "pnpx", "bunx"):
            if "--no-install" in args or "--no" in args: self._unres("package", f"{base} local binary: {seg[:60]}", False)
            else: self._unres("opaque", f"{base} may fetch and execute a package: {seg[:60]}")
            return
        if base in ("npm", "pnpm", "yarn", "bun"): return self._npm(base, args, ctx, via, depth)
        if base in ("make", "gmake"): return self._make(args, ctx, via, depth)
        if base in ("pytest", "py.test") or (base in PYS and args[:2] == ["-m", "pytest"]):
            return self._pytest(args[2:] if base in PYS else args, ctx, via, depth)
        if base in PYS: return self._python(args, ctx, via, depth)
        if base == "node": return self._node_cmd(args, ctx, via, depth)
        if base in SHELLS: return self._sh_cmd(base, args, ctx, via, depth)
        if base in ("source", "."):
            if args: self._shell_file(os.path.join(ctx.cwd, args[0]), ctx, via + [f"{base} {args[0]}"], depth + 1)
            return
        if base == "git": return self._git(args, ctx, via, depth)
        if base == "direnv":
            self._shell_file(os.path.join(self.ws, ".envrc"), Ctx(ctx.cwd), via + ["direnv loads .envrc"], depth + 1); return
        if "/" in prog:  # direct path execution
            return self._direct(prog, ctx, via, depth)

    def _direct(self, prog, ctx, via, depth):
        p = os.path.join(ctx.cwd, prog)
        got = self._read(p, via)
        if not got:
            if os.path.exists(p) is False: self._unres("missing", f"{prog} not found", False)
            return
        r, text = got
        first = text.splitlines()[0] if text else ""
        v = via + [f"direct exec {prog}"]
        if "node" in first and first.startswith("#!"): self._node_file(os.path.realpath(p), v, depth + 1)
        elif "python" in first and first.startswith("#!"): self._py_file(os.path.realpath(p), v, depth + 1)
        else: self._shell_text(r, text, Ctx(ctx.cwd), v, depth + 1)

    def _sh_cmd(self, prog, args, ctx, via, depth):
        if "-c" in args:
            i = args.index("-c")
            if i + 1 < len(args): self._shell_string(args[i + 1], ctx, via + [f"{prog} -c"], depth + 1)
            return
        files = [a for a in args if not a.startswith("-")]
        if not files:
            self._unres("opaque", f"{prog} reading script from stdin"); return
        self._shell_file(os.path.join(ctx.cwd, files[0]), ctx, via + [f"{prog} {files[0]}"], depth + 1)

    def _shell_file(self, path, ctx, via, depth):
        real = os.path.realpath(path)
        key = ("sh", real)
        if key in self._seen: return
        self._seen.add(key)
        got = self._read(path, via)
        if got: self._shell_text(got[0], got[1], Ctx(ctx.cwd), via, depth)
        elif not os.path.exists(path): self._unres("missing", f"{path} not found", False)

    def _shell_text(self, r, text, ctx, via, depth):
        self._add_lines(r, text, via)
        term = None; buf = []
        for ln in text.splitlines():
            if term:
                if ln.strip() == term: term = None
                continue
            m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?", ln)
            if m: term = m.group(1)
            if ln.lstrip().startswith("#") or not ln.strip(): continue
            buf.append(ln)
        self._shell_string("\n".join(buf), ctx, via, depth)

    # ---- npm
    def _npm(self, prog, args, ctx, via, depth):
        npm_ctx = Ctx(ctx.cwd)
        cleaned = []
        prefix_seen = False
        i = 0

        while i < len(args):
            arg = args[i]

            if arg == "--":
                cleaned.extend(args[i:])
                break

            prefix = None
            if prog == "npm" and arg == "--prefix":
                if (prefix_seen or i + 1 >= len(args)
                        or args[i + 1].startswith("-")):
                    self._unres("opaque", "npm --prefix missing a path or repeated")
                    return
                prefix = args[i + 1]
                i += 2
            elif prog == "npm" and arg.startswith("--prefix="):
                if prefix_seen:
                    self._unres("opaque", "npm --prefix repeated")
                    return
                prefix = arg.split("=", 1)[1]
                i += 1
            else:
                cleaned.append(arg)
                i += 1
                continue

            prefix_seen = True
            if (not prefix or prefix.startswith("~")
                    or any(ch in prefix for ch in ("$", "`", "*", "?", "[", "]", "{", "}"))):
                self._unres("dynamic", "npm --prefix path is empty or uses expansion/glob syntax")
                return

            target = os.path.realpath(os.path.join(ctx.cwd, prefix))
            if not self._inside(target):
                self._unres("outside", f"npm --prefix resolves outside workspace: {prefix}")
                return
            if not os.path.isdir(target):
                self._unres("missing", f"npm --prefix directory not found: {prefix}")
                return

            npm_ctx.cwd = target

        sub = [a for a in cleaned if not a.startswith("-")]
        if not sub:
            if not prefix_seen:
                return
            # npm with no explicit command defaults to install.
            sub = ["install"]

        if sub[0] in ("exec", "x", "dlx"):
            self._unres("opaque", f"{prog} {sub[0]} fetches/executes a package")
            return
        if sub[0] in ("run", "run-script", "rum", "urn"):
            if len(sub) < 2:
                return
            name = sub[1]
        elif sub[0] in ("test", "t", "tst"):
            name = "test"
        elif sub[0] in ("start", "stop", "restart"):
            name = sub[0]
        elif sub[0] in ("install", "i", "ci", "add", "update", "rebuild",
                        "link", "install-test", "it", "ic"):
            self._npm_lifecycle(prog, NPM_INSTALL_LIFECYCLE, npm_ctx, via, depth)
            self._npm_local_deps(prog, npm_ctx, via, depth)
            self._unres(
                "dependency-lifecycle",
                f"{prog} {sub[0]}: lifecycle scripts of installed dependencies are not resolved",
                False,
            )
            return
        elif prog == "yarn" and len(sub) >= 1:
            name = sub[0]
        else:
            return

        self._npm_lifecycle(
            prog, ["pre" + name, name, "post" + name], npm_ctx, via, depth
        )

    def _pkg(self, ctx):
        d = ctx.cwd
        while True:
            p = os.path.join(d, "package.json")
            if os.path.isfile(p): return p
            if d == self.ws or not self._inside(os.path.dirname(d)): return None
            d = os.path.dirname(d)

    def _npm_lifecycle(self, prog, keys, ctx, via, depth):
        pj = self._pkg(ctx)
        if not pj: return
        got = self._read(pj, via)
        if not got: return
        r, text = got
        try:
            scripts = json.loads(text).get("scripts", {}) or {}
        except (json.JSONDecodeError, AttributeError):
            self._unres("opaque", f"{r} unparsable"); return
        for k in keys:
            if k in scripts and isinstance(scripts[k], str):
                ln = next((n for n, l in enumerate(text.splitlines(), 1) if f'"{k}"' in l), None)
                v = via + [f"{prog} script '{k}'"]
                self.c.entries.append(Entry(r, ln, f"scripts.{k} = {scripts[k]}", v))
                self._shell_string(scripts[k], Ctx(os.path.dirname(pj)), v, depth + 1)

    def _npm_local_deps(self, prog, ctx, via, depth, seen=None):
        """Lifecycle scripts of file:/link: dependencies (local, statically resolvable). Registry deps stay unresolved."""
        pj = self._pkg(ctx)
        if not pj or depth > self.max_depth: return
        try: data = json.loads(open(pj, encoding="utf-8", errors="replace").read())
        except Exception: return
        for sect in ("dependencies", "devDependencies", "optionalDependencies"):
            for name, spec in (data.get(sect) or {}).items():
                if not isinstance(spec, str) or not spec.startswith(("file:", "link:")): continue
                d = os.path.realpath(os.path.join(os.path.dirname(pj), spec.split(":", 1)[1]))
                key = ("dep", d)
                if key in self._seen: continue
                self._seen.add(key)
                if not self._inside(d): self._unres("outside", f"local dependency {name} outside workspace"); continue
                sub = os.path.join(d, "package.json")
                got = self._read(sub, via)
                if not got: self._unres("missing", f"local dependency {name}: {spec} has no package.json", False); continue
                r, text = got
                try: sc = json.loads(text).get("scripts", {}) or {}
                except Exception: self._unres("opaque", f"{r} unparsable"); continue
                for k in ("preinstall", "install", "postinstall", "prepare"):
                    if isinstance(sc.get(k), str):
                        ln = next((n for n, l in enumerate(text.splitlines(), 1) if f'"{k}"' in l), None)
                        v = via + [f"{prog} local dependency '{name}' lifecycle '{k}'"]
                        self.c.entries.append(Entry(r, ln, f"scripts.{k} = {sc[k]}", v))
                        self._shell_string(sc[k], Ctx(d), v, depth + 1)
                self._npm_local_deps(prog, Ctx(d), via + [f"dependency {name}"], depth + 1)

    # ---- make
    def _make(self, args, ctx, via, depth):
        mf, targets, cwd, skip = None, [], ctx.cwd, False
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("-f", "--file", "--makefile") and i + 1 < len(args): mf = args[i + 1]; i += 2; continue
            if a in ("-C", "--directory") and i + 1 < len(args): cwd = os.path.join(ctx.cwd, args[i + 1]); i += 2; continue
            if a in ("-j", "-l", "-I", "-o", "-W") and i + 1 < len(args) and args[i + 1].isdigit(): i += 2; continue
            if a.startswith("-") or "=" in a: i += 1; continue
            targets.append(a); i += 1
        if mf: path = os.path.join(cwd, mf)
        else:
            try: names = set(os.listdir(cwd))
            except OSError: names = set()
            path = next((os.path.join(cwd, n) for n in ("GNUmakefile", "makefile", "Makefile") if n in names), None)
        if not path: self._unres("missing", "no Makefile found", False); return
        self._make_file(path, targets, Ctx(cwd), via, depth)

    def _parse_make(self, path, via, depth, rules, order, vars_, seen=None):
        got = self._read(path, via)
        if not got: return
        r, text = got
        lines = text.splitlines(); i = 0; cur = None; logical = []
        while i < len(lines):
            ln = lines[i]; n0 = i + 1
            while ln.endswith("\\") and i + 1 < len(lines): i += 1; ln = ln[:-1] + " " + lines[i].lstrip()
            i += 1
            if not ln.strip() or ln.lstrip().startswith("#"): continue
            if ln.startswith("\t"):
                if cur is not None:
                    for t in cur: rules[t]["recipe"].append((r, n0, ln.strip()))
                continue
            m = re.match(r"^(?:export\s+)?([A-Za-z_][\w.]*)\s*([:?+]{0,2})=\s*(.*)$", ln)
            if m and not re.match(r"^[^=]*:[^=]*$", ln.split("=")[0] + ":"): pass
            if m:
                if m.group(2) == "+": vars_[m.group(1)] = (vars_.get(m.group(1), ("", 0, r))[0] + " " + m.group(3), n0, r)
                elif m.group(2) == "?" and m.group(1) in vars_: pass
                else: vars_[m.group(1)] = (m.group(3), n0, r)
                cur = None; continue
            m = re.match(r"^\s*-?include\s+(.+)$", ln)
            if m:
                for inc in shlex.split(m.group(1)):
                    if "$" in inc: self._unres("dynamic", f"make include {inc}")
                    elif (key := ("mk", os.path.realpath(os.path.join(os.path.dirname(path), inc)))) not in self._seen:
                        self._seen.add(key); self._parse_make(os.path.join(os.path.dirname(path), inc), via, depth, rules, order, vars_)
                cur = None; continue
            m = re.match(r"^([^\s:#=][^:=#]*?)\s*:(?!=)\s*([^#]*)", ln)
            if m and not re.match(r"^\s*(ifeq|ifneq|ifdef|ifndef|else|endif)\b", ln):
                tg = m.group(1).split(); deps = m.group(2).replace("|", " ").split()
                for t in tg:
                    rules.setdefault(t, {"deps": [], "recipe": []})["deps"] += deps
                    if not t.startswith(".") and t not in order and "%" not in t: order.append(t)
                cur = tg; continue
            cur = None

    def _make_file(self, path, targets, ctx, via, depth):
        rules, order, vars_ = {}, [], {}
        self._parse_make(path, via, depth, rules, order, vars_)
        real = os.path.realpath(path); mk = self.rel(real)
        if not targets: targets = order[:1]
        seen = set()
        def expand(s, used, d=0):
            def sub(m):
                name = m.group(1) or m.group(2)
                if name == "MAKE": return "make"
                if name in vars_:
                    used.add(name); return expand(vars_[name][0], used, d + 1) if d < 5 else ""
                if len(name) == 1 and name in "@<^*?%+": return m.group(0)
                if name.startswith("shell ") or name.startswith("shell\t"): self._unres("dynamic", f"$(shell) in {mk}"); return ""
                return m.group(0)
            return re.sub(r"\$\(([^)]+)\)|\$\{([^}]+)\}", sub, s).replace("$$", "$")
        def walk(tg, dd):
            if tg in seen: return
            seen.add(tg)
            if tg not in rules:
                if not os.path.exists(os.path.join(ctx.cwd, tg)): self._unres("missing", f"make target '{tg}' has no rule", False)
                return
            if dd > self.max_depth: self._unres("limit", "make dependency depth"); return
            for d in rules[tg]["deps"]: walk(d, dd + 1)
            for fr, n, rline in rules[tg]["recipe"]:
                used = set(); line = rline.lstrip("@-+ ")
                exp = expand(line, used)
                v = via + [f"make target '{tg}'"]
                self.c.entries.append(Entry(fr, n, rline, v))
                for u in used: self.c.entries.append(Entry(vars_[u][2], vars_[u][1], f"{u} = {vars_[u][0]}", v))
                if re.search(r"\$\(|\$\{", exp.replace("$(MAKE)", "")) and re.match(r"^\s*[\$]", exp):
                    self._unres("dynamic", f"make recipe program from unexpanded variable: {exp[:60]}")
                self._shell_string(exp, Ctx(ctx.cwd), v, depth + 1)
        for tg in targets: walk(tg, 0)

    # ---- python
    def _python(self, args, ctx, via, depth):
        if args[:1] == ["-m"] and len(args) > 1:
            mod = args[1]
            f = self._find_py_module(mod, [ctx.cwd]); 
            if f: self._py_file(f, via + [f"python -m {mod}"], depth + 1)
            return
        if "-c" in args:
            self._unres("package", "python -c inline code (in the command itself, not delayed)", False); return
        files = [a for a in args if not a.startswith("-")]
        if files: self._py_file(os.path.realpath(os.path.join(ctx.cwd, files[0])), via + [f"python {files[0]}"], depth + 1)

    def _find_py_module(self, mod, roots):
        parts = mod.split(".")
        for root in roots:
            for cand in (os.path.join(root, *parts) + ".py", os.path.join(root, *parts, "__init__.py")):
                if os.path.isfile(cand) and self._inside(os.path.realpath(cand)): return cand
        return None

    def _py_file(self, real, via, depth):
        key = ("py", real)
        if key in self._seen: self.c.notes.append(f"cycle/duplicate: {self.rel(real)}"); return
        self._seen.add(key)
        if depth > self.max_depth: self._unres("limit", f"python import depth at {self.rel(real)}"); return
        got = self._read(real, via)
        if not got: return
        r, text = got
        self._add_lines(r, text, via)
        roots = [os.path.dirname(real), self.ws]
        for ln in text.splitlines():
            s = ln.strip()
            if s.startswith("#"): continue
            m = re.match(r"^from\s+(\.*)([\w.]*)\s+import\s+(.+)$", s)
            mods = []
            if m:
                dots, name, names = m.groups()
                if dots:
                    base = os.path.dirname(real)
                    for _ in range(len(dots) - 1): base = os.path.dirname(base)
                    f = self._find_py_module(name, [base]) if name else os.path.join(base, "__init__.py")
                    if name == "" :
                        for n in re.split(r"[,\s]+", names.strip("() ")):
                            g = self._find_py_module(n, [base])
                            if g: mods.append(g)
                    elif f: mods.append(f)
                else:
                    f = self._find_py_module(name, roots)
                    if f: mods.append(f)
                    else: self._pkg_import(name)
            else:
                m = re.match(r"^import\s+(.+)$", s)
                if m:
                    for part in m.group(1).split(","):
                        name = part.strip().split(" as ")[0].strip()
                        if not name: continue
                        f = self._find_py_module(name, roots)
                        if f: mods.append(f)
                        else: self._pkg_import(name)
            for f in mods: self._py_file(os.path.realpath(f), via + [f"import → {self.rel(f)}"], depth + 1)
            if re.search(r"__import__\(\s*[^'\"\s)]|import_module\(\s*[^'\"\s)]|\b(exec|eval)\(\s*[^'\"\s)]", s):
                self._unres("dynamic", f"dynamic import/exec in {r}:{s[:60]}")
            if re.match(r"^pytest_plugins\s*=", s):
                for n in re.findall(r"['\"]([\w.]+)['\"]", s):
                    f = self._find_py_module(n, roots)
                    if f: self._py_file(os.path.realpath(f), via + [f"pytest_plugins → {n}"], depth + 1)

    def _pkg_import(self, name):
        top = name.split(".")[0]
        if top and top not in getattr(sys, "stdlib_module_names", set()):
            self._unres("package", f"python package import '{top}' (third-party, not analysed)", False)

    # ---- pytest
    def _pytest(self, args, ctx, via, depth):
        takes = {"-p", "-c", "-k", "-m", "-o", "-W", "--ignore", "--deselect", "--rootdir", "--confcutdir", "--import-mode",
                 "--basetemp", "-n", "--junitxml", "--maxfail", "--tb", "-r", "--durations", "--ignore-glob"}
        targets, i = [], 0
        plugins, cfg = [], None
        while i < len(args):
            a = args[i]
            if a in takes and i + 1 < len(args):
                if a == "-p": plugins.append(args[i + 1])
                if a == "-c": cfg = args[i + 1]
                i += 2; continue
            if a.startswith("-p") and len(a) > 2 and not a.startswith("--"): plugins.append(a[2:])
            if not a.startswith("-"): targets.append(a.split("::")[0])
            i += 1
        v0 = via + ["pytest"]
        roots = [ctx.cwd]
        cfgs = [cfg] if cfg else ["pytest.ini", ".pytest.ini", "tox.ini", "setup.cfg", "pyproject.toml"]
        for c in cfgs:
            got = self._read(os.path.join(ctx.cwd, c), v0)
            if not got: continue
            r, text = got
            sect = None; hit = False
            for n, ln in enumerate(text.splitlines(), 1):
                m = re.match(r"^\s*\[([^\]]+)\]", ln)
                if m: sect = m.group(1); continue
                if sect and re.match(r"^(pytest|tool:pytest|tool\.pytest\.ini_options)$", sect):
                    hit = True; self.c.entries.append(Entry(r, n, ln, v0 + [f"pytest config {r}"]))
                    mm = re.match(r"^\s*addopts\s*=\s*(.*)$", ln)
                    if mm: plugins += re.findall(r"-p\s*([\w.]+)", mm.group(1))
            if hit: break
        for p in plugins:
            f = self._find_py_module(p, roots)
            if f: self._py_file(os.path.realpath(f), v0 + [f"plugin {p}"], depth + 1)
            else: self._unres("package", f"pytest plugin '{p}' (not a local file)", False)
        targets = targets or ["."]
        files, dirs = [], set()
        for t in targets:
            p = os.path.realpath(os.path.join(ctx.cwd, t))
            if not self._inside(p): self._unres("outside", f"pytest target {t} outside workspace"); continue
            if os.path.isfile(p): files.append(p); dirs.add(os.path.dirname(p))
            elif os.path.isdir(p):
                dirs.add(p)
                n = 0
                for root, ds, fs in os.walk(p):
                    ds[:] = sorted(d for d in ds if d not in (".git", "node_modules", ".venv", "venv", "__pycache__"))
                    dirs.add(root)
                    for f in sorted(fs):
                        if re.match(r"test_.*\.py$|.*_test\.py$", f): files.append(os.path.join(root, f)); n += 1
                    if n > 500: self._unres("limit", "pytest collection limit"); break
        convs = set()
        for d in dirs:
            cur = d
            while True:
                cf = os.path.join(cur, "conftest.py")
                if os.path.isfile(cf): convs.add(os.path.realpath(cf))
                if cur == self.ws or not cur.startswith(self.ws): break
                cur = os.path.dirname(cur)
        for f in sorted(convs): self._py_file(f, v0 + ["conftest.py (auto-loaded)"], depth + 1)
        for f in sorted(files): self._py_file(os.path.realpath(f), v0 + ["test collection"], depth + 1)

    # ---- node
    def _node_cmd(self, args, ctx, via, depth):
        files, i = [], 0
        while i < len(args):
            a = args[i]
            if a in ("-e", "-p", "--eval", "--print"): self._unres("package", "node inline code (in the command itself)", False); return
            if a in ("-r", "--require", "--import", "--loader") and i + 1 < len(args):
                self._node_entry(args[i + 1], ctx, via + [f"node {a} {args[i+1]}"], depth); i += 2; continue
            if a == "--test": self._unres("unsupported", "node --test discovers test files; not resolved"); i += 1; continue
            if not a.startswith("-"): files.append(a); break
            i += 1
        if files: self._node_entry(files[0], ctx, via + [f"node {files[0]}"], depth)

    def _node_entry(self, f, ctx, via, depth):
        p = os.path.join(ctx.cwd, f)
        real = self._js_resolve(p)
        if real: self._node_file(real, via, depth + 1)
        else: self._unres("missing", f"node entry {f} not found", False)

    def _js_resolve(self, base):
        for cand in (base, base + ".js", base + ".cjs", base + ".mjs", base + ".json",
                     os.path.join(base, "index.js"), os.path.join(base, "index.mjs")):
            if os.path.isfile(cand): return os.path.realpath(cand)
        return None

    def _node_file(self, real, via, depth):
        key = ("js", real)
        if key in self._seen: self.c.notes.append(f"import cycle/duplicate: {self.rel(real)}"); return
        self._seen.add(key)
        if depth > self.max_depth: self._unres("limit", f"JS import depth at {self.rel(real)}"); return
        got = self._read(real, via)
        if not got: return
        r, text = got
        if real.endswith(".json"): return
        self._add_lines(r, text, via)
        src = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
        for ln in src.splitlines():
            s = ln.strip()
            if s.startswith("//"): continue
            specs = re.findall(r"require\(\s*(['\"])([^'\"]+)\1\s*\)", s) + re.findall(r"\bfrom\s+(['\"])([^'\"]+)\1", s) \
                + re.findall(r"\bimport\(\s*(['\"])([^'\"]+)\1\s*\)", s) + re.findall(r"^\s*import\s+(['\"])([^'\"]+)\1", s)
            for _, sp in specs:
                if sp.startswith(("./", "../", "/")) or sp in (".", ".."):
                    tgt = self._js_resolve(os.path.join(os.path.dirname(real), sp))
                    if tgt: self._node_file(tgt, via + [f"require('{sp}') → {self.rel(tgt)}"], depth + 1)
                    else: self._unres("missing", f"{r}: local import '{sp}' not found", False)
                elif sp.startswith("node:") or sp in NODE_BUILTINS: pass
                elif sp.startswith(("#", "@/", "~/")): self._unres("dynamic", f"{r}: unresolved alias '{sp}'")
                else: self._unres("package", f"{r}: external package '{sp}' (not analysed)", False)
            if re.search(r"\brequire\(\s*[^'\"\s)]", s) or re.search(r"\bimport\(\s*[^'\"\s)]", s) or re.search(r"require\(\s*[`]", s):
                self._unres("dynamic", f"{r}: non-literal require/import: {s[:70]}")
            if re.search(r"\b(eval|new Function)\s*\(", s):
                self._unres("dynamic", f"{r}: eval/Function: {s[:70]}")

    # ---- git
    def _git(self, args, ctx, via, depth):
        gd = os.path.join(self.ws, ".git")
        if not os.path.isdir(gd): return
        i = 0; opts = []
        while i < len(args):
            if args[i] in ("-C", "-c") and i + 1 < len(args): i += 2; continue
            if args[i].startswith("-"): i += 1; continue
            break
        sub = args[i] if i < len(args) else ""
        rest = args[i + 1:]
        cfg_text = ""
        got = self._read(os.path.join(gd, "config"), via)
        hooks_dir = os.path.join(gd, "hooks")
        if got:
            r, cfg_text = got; sect = ""
            for n, ln in enumerate(cfg_text.splitlines(), 1):
                m = re.match(r"^\s*\[([^\]]+)\]", ln)
                if m: sect = m.group(1).lower(); continue
                mm = re.match(r"^\s*hooksPath\s*=\s*(.+?)\s*$", ln, re.I)
                if mm and sect == "core":
                    hp = mm.group(1).strip('"')
                    hooks_dir = hp if os.path.isabs(hp) else os.path.join(self.ws, hp)
                    self.c.entries.append(Entry(r, n, ln, via + ["git core.hooksPath"]))
                if GIT_CFG_EXEC.match(ln) and sect != "user":
                    v = via + [f"git config [{sect}] executes"]
                    self.c.entries.append(Entry(r, n, ln, v))
                    val = ln.split("=", 1)[1].strip().strip('"')
                    if val: self._shell_string(val, Ctx(self.ws), v, depth + 1)
                if sect == "alias" and sub and re.match(rf"^\s*{re.escape(sub)}\s*=", ln):
                    val = ln.split("=", 1)[1].strip().strip('"')
                    v = via + [f"git alias '{sub}'"]
                    self.c.entries.append(Entry(r, n, ln, v))
                    if val.startswith("!"): self._shell_string(val[1:], Ctx(self.ws), v, depth + 1)
                    else: self._git(shlex.split(val), ctx, v, depth + 1)
        hp_real = os.path.realpath(hooks_dir)
        if not self._inside(hp_real):
            self._unres("outside", f"core.hooksPath points outside workspace: {hooks_dir}"); return
        no_verify = any(a in ("--no-verify", "-n") or (a.startswith("-") and not a.startswith("--") and "n" in a[1:] and sub == "commit" and False) for a in rest)
        if sub == "commit": no_verify = no_verify or any(re.match(r"^-[a-zA-Z]*n[a-zA-Z]*$", a) for a in rest)
        for hk in GIT_HOOKS.get(sub, []):
            if no_verify and hk in NO_VERIFY_SKIPS: continue
            p = os.path.join(hooks_dir, hk)
            if not os.path.lexists(p): continue
            real = os.path.realpath(p)
            if not os.access(real, os.X_OK):
                self.c.notes.append(f"git hook '{hk}' present but not executable (git will not run it)"); continue
            self._exec_file(real, ctx, via + [f"git hook '{hk}'"], depth + 1)

    def _exec_file(self, real, ctx, via, depth):
        got = self._read(real, via)
        if not got: return
        r, text = got; first = text.splitlines()[0] if text else ""
        if first.startswith("#!") and "node" in first: self._node_file(real, via, depth)
        elif first.startswith("#!") and "python" in first: self._py_file(real, via, depth)
        else:
            key = ("sh", real)
            if key in self._seen: return
            self._seen.add(key); self._shell_text(r, text, Ctx(self.ws), via, depth)


def resolve(command: str, workspace: str, cwd: str | None = None, **kw) -> Closure:
    return Resolver(workspace, **kw).resolve(command, cwd)
