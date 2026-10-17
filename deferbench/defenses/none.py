from .base import Defence


class NoDefence(Defence):
    id = "none"; baseline = "B0"; label = "No defence (command-level approval only, auto-approved)"
    description = ("Allows every action. Used to confirm that each scenario's expected effect reproduces "
                   "undefended; a scenario whose B0 result differs from expectation is INVALID for scoring.")
