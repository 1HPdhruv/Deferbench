from .gensee import GenseeAdapter
from .gryph import GryphAdapter, GryphBlanketAdapter, GryphExampleAdapter
from .runmark import RunmarkAdapter
from .v0 import HandoffV0


def external_defences():
    return [HandoffV0(), GenseeAdapter(), GryphAdapter(), GryphExampleAdapter(), GryphBlanketAdapter(), RunmarkAdapter()]
