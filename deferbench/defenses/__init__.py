"""Defence registry. Built-in defences always available; external adapters report availability."""
from __future__ import annotations
from .base import Defence
from .none import NoDefence
from .denylist import Denylist
from .static_expansion import StaticExpansion
from .handoff import HandoffDefence, HandoffHookDefence
from .blanket import BlanketGate


def registry() -> dict[str, Defence]:
    from ..adapters import external_defences
    d = {x.id: x for x in (NoDefence(), Denylist(), StaticExpansion(), HandoffDefence(), HandoffHookDefence(), BlanketGate())}
    for x in external_defences(): d[x.id] = x
    return d
