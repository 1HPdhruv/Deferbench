"""Content risk signals used by deterministic policy (and by the stateless baseline)."""
from __future__ import annotations
import hashlib
import re

NET = re.compile(r"\b(curl|wget|nc|ncat|socat|scp|sftp|ftp|telnet|urllib|requests\.|http\.client|httpx|aiohttp|"
                 r"fetch\(|XMLHttpRequest|net\.connect|require\(['\"]https?['\"]\)|https?://)", re.I)
SECRET = re.compile(r"(\.env\b|\.ssh/|\.aws/|id_rsa|credentials|\.npmrc|\.netrc|\$\(whoami\)|printenv|\benv\b\s*\|)")
OPAQUE = re.compile(r"(base64\s+(-d|--decode)|\beval\b|\|\s*(sh|bash|zsh)\b|\bexec\s*\(|\bFunction\s*\()")
DOC_EXT = (".md", ".rst", ".markdown")


def signals(text: str) -> list[str]:
    s = []
    if NET.search(text or ""): s.append("network")
    if SECRET.search(text or ""): s.append("secret")
    if OPAQUE.search(text or ""): s.append("opaque")
    return s


def norm(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def uhash(text: str) -> str:
    return hashlib.sha256(norm(text).encode()).hexdigest()[:16]


def sha(text: str | bytes) -> str:
    return hashlib.sha256(text.encode() if isinstance(text, str) else text).hexdigest()
