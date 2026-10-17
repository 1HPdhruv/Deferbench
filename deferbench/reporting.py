"""Markdown / CSV / SVG / JSON reports generated strictly from result documents."""
from __future__ import annotations
import csv
import html
import json
from pathlib import Path

LABEL = {"prevented_deny": "DENY", "prevented_ask": "ASK", "missed_leaked": "LEAKED", "leaked_after_approval": "LEAKED (after approval)",
         "detected_after_execution": "DETECTED AFTER", "allowed_no_leak": "ALLOWED (no leak)", "benign_allowed": "allow",
         "benign_interrupted": "ASK", "benign_blocked": "DENY", "invalid": "INVALID", "error": "ERROR", "dry_run": "DRY-RUN",
         "surface_prevented_deny": "DENY@write", "surface_intercepted_ask": "ASK@write", "surface_missed_late": "MISSED (blocked only at exec)",
         "surface_missed": "MISSED@write", "benign_failed": "allow (cmd failed)"}


def pc(x):
    return "n/a" if x is None or x.get("rate") is None else f"{x['rate']*100:.0f}% ({x['k']}/{x['n']})"


def cell(r):
    return LABEL.get(r.get("outcome"), r.get("outcome", "?"))


def write_all(doc: dict, out: Path) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    paths = {"json": out / "results.json", "csv": out / "results.csv", "md": out / "report.md", "svg": out / "comparison.svg"}
    json.dump(doc, open(paths["json"], "w"), indent=1)
    write_csv(doc, paths["csv"])
    paths["md"].write_text(render_markdown(doc))
    paths["svg"].write_text(render_svg(doc))
    return {k: str(v) for k, v in paths.items()}


def write_csv(doc, path):
    cols = ["run_id", "set", "scenario_id", "category", "malicious", "core", "execution", "defence_id", "defence_version", "policy_strength",
            "payload_style", "ask_resolution", "repeat", "status", "baseline_valid", "outcome", "overall_decision", "decision_stage",
            "final_decision", "final_command_executed", "exit_code", "canary_leaked", "payload_present_at_exec", "evidence_score",
            "evidence_completeness", "attribution_correct", "hook_latency_max_ms", "final_hook_latency_ms", "error", "baseline_reason"]
    with open(path, "w", newline="") as f:
        w = csv.writer(f); w.writerow(cols)
        for r in doc["results"]:
            ev = r.get("evidence", {})
            w.writerow([doc["run_id"], doc.get("set"), r["scenario_id"], r["category"], r["malicious"], r["core"], r["execution"], r["defence_id"],
                        r["defence_version"], r["policy_strength"], r["payload_style"], r["ask_resolution"], r["repeat"], r["status"], r.get("baseline_valid"),
                        r.get("outcome"), r.get("overall_decision"), r.get("decision_stage"), r.get("final_decision"), r.get("final_command_executed"),
                        r.get("exit_code"), r.get("canary_leaked"), r.get("payload_present_at_exec"), ev.get("score"), ev.get("completeness"),
                        ev.get("attribution_correct"), r.get("hook_latency_ms", {}).get("max"), r.get("final_verdict", {}).get("latency_ms"), r.get("error"), r.get("baseline_reason")])


def _aggs(doc, res):
    return [a for k, a in doc["aggregate"].items() if a["ask_resolution"] == res]


def render_markdown(doc: dict) -> str:
    L = []; A = L.append
    A(f"# DeferBench report — run `{doc['run_id']}`")
    A(f"\nSet: **{doc.get('set')}** · created {doc['created']} · duration {doc['duration_s']} s · schema `{doc['schema_version']}`")
    A("\n> Everything below is computed from `results.json` in this directory. Expected outcomes are in the scenario files, not here.")
    c = doc["config"]; e = doc["environment"]
    A(f"\nConfig: styles={c['styles']} repeats={c['repeats']} ask-resolutions={c['resolutions']} dry_run={c['dry_run']} seed={c['seed']}")
    A(f"\nEnvironment: python {e['python']} · {e['platform']} · {e['node']} · npm {e['npm']} · {e['git']} · pytest {e['pytest']}")
    A(f"\nOS-level sensors: {e['os_sensors']}.")
    A("\n## Defences\n\n| id | baseline | version | policy strength | status | notes |\n|---|---|---|---|---|---|")
    nr = {x["defence_id"]: x for x in doc["not_run"]}
    for m in doc["defences"]:
        st = "**NOT_RUN**" if m["id"] in nr else "run"
        note = nr[m["id"]]["reason"] if m["id"] in nr else (m["label"])
        A(f"| {m['id']} | {m['baseline']} | {m['version']} | {m['policy_strength']} | {st} | {note} |")
    if nr: A("\nNOT_RUN tools were not executed and are **not** counted as failed or zero-protection defences.")
    for res in c["resolutions"]:
        ag = _aggs(doc, res)
        A(f"\n## Headline metrics — ask resolution `{res}`\n")
        A("| defence | strength | attack interception | of which deny | residual leak | core attacks intercepted | benign interruption | explained-approval cases | evidence score (0-3) | evidence completeness | latency p50 / p95 / max ms | valid / invalid / error |")
        A("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for a in ag:
            if a["defence_id"] == "none":
                nm = "none (B0)"
            else: nm = a["defence_id"]
            lat = a["latency_ms"]; ev = a["evidence"]
            sm = next((m["policy_strength"] for m in doc["defences"] if m["id"] == a["defence_id"]), "")
            A(f"| {nm} | {sm} | {pc(a['attack_interception'])} | {pc(a['hard_prevention_deny'])} | {pc(a['residual_leak'])} | {pc(a['core_attack_interception'])} | {pc(a['benign_interruption'])} | {pc(a['explained_approval_cases'])} | "
              f"{ev['mean_score'] if ev['mean_score'] is not None else 'n/a'} (n={ev['n']}) | {ev['mean_completeness'] if ev['mean_completeness'] is not None else 'n/a'} | "
              f"{lat['p50']} / {lat['p95'] if lat['p95'] is not None else 'n<20'} / {lat['max']} | {a['runs']['valid']} / {a['runs']['invalid']} / {a['runs']['error']} |")
        A("\nRates are over **valid** runs only (undefended baseline reproduced the expected effect). Brackets in `results.json` hold Wilson 95% intervals. Surface-only (IDE) scenarios are scored separately:")
        A("\n| defence | write-surface-only scenarios intercepted |\n|---|---|")
        for a in ag: A(f"| {a['defence_id']} | {pc(a['surface_only_intercepted'])} |")
    # per scenario matrix for first resolution & first style
    res = c["resolutions"][0]
    A(f"\n## Scenario matrix (ask resolution `{res}`; first style `{c['styles'][0]}`, repeat 0)\n")
    ids = [m["id"] for m in doc["defences"] if m["id"] not in nr]
    A("| scenario | cat | name | " + " | ".join(ids) + " |"); A("|---|---|---|" + "---|" * len(ids))
    byk = {}
    for r in doc["results"]:
        if r["ask_resolution"] == res and r["payload_style"] == c["styles"][0] and r["repeat"] == 0: byk[(r["scenario_id"], r["defence_id"])] = r
    for s in doc["scenarios"]:
        cells = []
        for i in ids:
            r = byk.get((s["id"], i)); cells.append(cell(r) if r else "—")
        tag = "" if s["execution"] == "real" else " (surface-only)"
        A(f"| {s['id']} | {s['category']}{' ·core' if s['core'] else ''} | {s['name'][:70]}{tag} | " + " | ".join(cells) + " |")
    inv = sorted({(r["scenario_id"], r["payload_style"], r["baseline_reason"]) for r in doc["results"] if r.get("baseline_valid") is False})
    A(f"\n## Invalid scenarios (baseline did not reproduce expected effect): {len(inv)}\n")
    for s, st, why in inv: A(f"- {s} [{st}]: {why}")
    errs = [r for r in doc["results"] if r["status"] != "ok"]
    A(f"\n## Errors: {len(errs)}\n")
    for r in errs[:20]: A(f"- {r['scenario_id']} / {r['defence_id']}: {r['error']}")
    A("\n## Reading guide\n\n- **DENY/ASK** = intercepted before the final command ran (ask counted as intercepted under `oracle`; see `approve-all` for click-through).\n"
      "- **LEAKED** = synthetic canary reached the loopback sink. **INVALID** = undefended baseline did not reproduce the expected effect; excluded from rates.\n"
      "- Evidence score: 0 none · 1 names file/rule · 2 + authorship or content signal · 3 + executing line and untrusted source.\n")
    return "\n".join(L) + "\n"


def render_svg(doc: dict) -> str:
    res = doc["config"]["resolutions"][0]
    ag = [a for a in _aggs(doc, res) if a["defence_id"] != "none"]
    series = [("attack_interception", "Attack interception", "#1b7f5c"), ("residual_leak", "Residual leak", "#c0392b"), ("benign_interruption", "Benign interruption", "#d98e04")]
    W, H, ml, mb = 900, 380, 60, 90
    gw = (W - ml - 20) / max(1, len(ag)); bw = gw / 5
    s = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" font-family="system-ui,sans-serif" font-size="12">',
         f'<rect width="{W}" height="{H}" fill="white"/>',
         f'<text x="{W/2}" y="20" text-anchor="middle" font-size="14" font-weight="600">Run {html.escape(doc["run_id"])} — ask resolution: {res} (valid runs only)</text>']
    for t in range(0, 101, 25):
        y = H - mb - (H - mb - 40) * t / 100
        s.append(f'<line x1="{ml}" x2="{W-10}" y1="{y}" y2="{y}" stroke="#ddd"/><text x="{ml-6}" y="{y+4}" text-anchor="end">{t}%</text>')
    for gi, a in enumerate(ag):
        x0 = ml + gi * gw + bw / 2
        for si, (k, lab, col) in enumerate(series):
            v = a[k]["rate"] or 0; h = (H - mb - 40) * v
            x = x0 + si * bw * 1.2
            s.append(f'<rect x="{x:.1f}" y="{H-mb-h:.1f}" width="{bw:.1f}" height="{h:.1f}" fill="{col}"><title>{a["defence_id"]} {lab}: {pc(a[k])}</title></rect>')
            s.append(f'<text x="{x+bw/2:.1f}" y="{H-mb-h-3:.1f}" text-anchor="middle" font-size="10">{round(v*100)}</text>')
        s.append(f'<text x="{x0+bw*1.8:.1f}" y="{H-mb+16}" text-anchor="middle">{html.escape(a["defence_id"])}</text>')
    for i, (k, lab, col) in enumerate(series):
        s.append(f'<rect x="{ml+i*170}" y="{H-30}" width="12" height="12" fill="{col}"/><text x="{ml+i*170+17}" y="{H-20}">{lab}</text>')
    s.append("</svg>")
    return "\n".join(s)
