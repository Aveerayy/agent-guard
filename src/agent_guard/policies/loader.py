"""Policy loader — discover and load policies from files and directories."""

from __future__ import annotations

from pathlib import Path

from agent_guard.core.policy import Policy


def load_policies(path: str | Path) -> list[Policy]:
    """Load policies from a file or directory.

    - If path is a YAML file, loads a single policy.
    - If path is a directory, loads all .yaml/.yml files recursively.
    """
    p = Path(path)
    if p.is_file():
        return [Policy.from_yaml(p)]

    if p.is_dir():
        policies = []
        for f in sorted(p.rglob("*.yaml")) + sorted(p.rglob("*.yml")):
            try:
                policies.append(Policy.from_yaml(f))
            except Exception as e:
                raise ValueError(f"Failed to load policy from {f}: {e}") from e
        return policies

    raise FileNotFoundError(f"Policy path not found: {path}")


def merge_policies(policies: list[Policy], name: str = "merged") -> Policy:
    """Merge multiple policies into one, preserving rule priority order."""
    all_rules = []
    for policy in policies:
        all_rules.extend(policy.rules)
    all_rules.sort(key=lambda r: r.priority, reverse=True)
    default = policies[-1].default_effect if policies else Policy().default_effect
    return Policy(name=name, rules=all_rules, default_effect=default)
