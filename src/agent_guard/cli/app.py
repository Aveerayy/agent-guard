"""Agent Guard CLI — manage policies, scan for issues, generate reports."""

from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from agent_guard.core.engine import Guard
from agent_guard.core.policy import Effect, Policy
from agent_guard.policies.builtin import get_builtin, list_builtins
from agent_guard.policies.loader import load_policies

console = Console()


@click.group()
@click.version_option(version="0.2.0", prog_name="agent-guard")
def main() -> None:
    """Agent Guard — Simple, powerful governance for AI agents."""
    pass


@main.command()
def info() -> None:
    """Show Agent Guard info and capabilities."""
    console.print(
        Panel.fit(
            "[bold cyan]Agent Guard[/bold cyan] v0.2.0\n\n"
            "Simple, powerful governance for AI agents.\n\n"
            "[bold]Capabilities:[/bold]\n"
            "  • Policy engine with YAML rules & fluent Python API\n"
            "  • Ed25519 agent identity & trust scoring\n"
            "  • Execution sandboxing with permission levels\n"
            "  • Hash-chained audit logging\n"
            "  • Agent-to-agent secure mesh\n"
            "  • Token governance — discover, inventory, risk-score credentials\n"
            "  • Runtime injection detection on tool arguments\n"
            "  • Output PII/secrets filtering & redaction\n"
            "  • Real-time web dashboard with token monitoring\n"
            "  • Circuit breakers & SLO tracking\n"
            "  • LangChain, OpenAI, CrewAI, AutoGen integrations\n\n"
            "[bold]OWASP Agentic Top 10:[/bold] 10/10 risks covered",
            title="About",
            border_style="cyan",
        )
    )


@main.command(name="policies")
def list_policies_cmd() -> None:
    """List available built-in policy templates."""
    table = Table(title="Built-in Policy Templates")
    table.add_column("Name", style="cyan bold")
    table.add_column("Description", style="white")
    table.add_column("Default Effect", style="yellow")
    table.add_column("Rules", justify="right", style="green")

    for name in list_builtins():
        policy = get_builtin(name)
        table.add_row(
            name,
            policy.description,
            policy.default_effect.value,
            str(len(policy.rules)),
        )

    console.print(table)


@main.command()
@click.argument("name")
@click.option("--output", "-o", help="Output file path (default: stdout)")
def export(name: str, output: str | None) -> None:
    """Export a built-in policy as YAML."""
    import yaml

    policy = get_builtin(name)
    data = {
        "name": policy.name,
        "description": policy.description,
        "version": policy.version,
        "default_effect": policy.default_effect.value,
        "rules": [
            {
                "name": r.name,
                "action": r.action,
                "effect": r.effect.value,
                **({"reason": r.reason} if r.reason else {}),
                **({"priority": r.priority} if r.priority else {}),
                **({"agents": r.agents} if r.agents else {}),
                **({"conditions": [c.model_dump() for c in r.conditions]} if r.conditions else {}),
            }
            for r in policy.rules
        ],
    }

    yaml_str = yaml.dump(data, default_flow_style=False, sort_keys=False)

    if output:
        Path(output).write_text(yaml_str)
        console.print(f"[green]✓[/green] Exported '{name}' policy to {output}")
    else:
        console.print(yaml_str)


@main.command()
@click.argument("path", type=click.Path(exists=True))
def validate(path: str) -> None:
    """Validate a policy YAML file."""
    try:
        policies = load_policies(path)
        for policy in policies:
            console.print(
                f"[green]✓[/green] [bold]{policy.name}[/bold]: "
                f"{len(policy.rules)} rules, default={policy.default_effect.value}"
            )
            for rule in policy.rules:
                icon = (
                    "✅"
                    if rule.effect == Effect.ALLOW
                    else ("🔍" if rule.effect == Effect.AUDIT else "🚫")
                )
                console.print(f"  {icon} {rule.name or rule.action}: {rule.effect.value}")
        console.print(f"\n[green bold]All {len(policies)} policies valid.[/green bold]")
    except Exception as e:
        console.print(f"[red bold]✗ Validation failed:[/red bold] {e}")
        sys.exit(1)


@main.command()
@click.argument("policy_path", type=click.Path(exists=True))
@click.argument("action")
@click.option("--agent-id", "-a", default="test-agent", help="Agent ID to test")
def test(policy_path: str, action: str, agent_id: str) -> None:
    """Test an action against a policy."""
    guard = Guard()
    for policy in load_policies(policy_path):
        guard.add_policy(policy)

    decision = guard.evaluate(action, agent_id=agent_id)

    if decision.allowed:
        icon = "[green bold]✓ ALLOWED[/green bold]"
    else:
        icon = "[red bold]✗ DENIED[/red bold]"

    console.print(
        Panel(
            f"{icon}\n\n"
            f"[bold]Action:[/bold] {action}\n"
            f"[bold]Agent:[/bold] {agent_id}\n"
            f"[bold]Effect:[/bold] {decision.effect.value}\n"
            f"[bold]Rule:[/bold] {decision.matched_rule}\n"
            f"[bold]Reason:[/bold] {decision.reason}\n"
            f"[bold]Time:[/bold] {decision.evaluation_time_ms:.4f} ms",
            title="Policy Test Result",
            border_style="green" if decision.allowed else "red",
        )
    )


@main.command()
@click.option("--name", "-n", default="my-agent", help="Agent ID")
@click.option("--role", "-r", default="default", help="Agent role")
def identity(name: str, role: str) -> None:
    """Generate a new agent identity."""
    from agent_guard.identity.agent_id import AgentIdentity

    agent = AgentIdentity.create(name, role=role)
    card = agent.to_card()

    console.print(
        Panel(
            f"[bold]Agent ID:[/bold] {card['agent_id']}\n"
            f"[bold]Role:[/bold] {card['role']}\n"
            f"[bold]Fingerprint:[/bold] {card['fingerprint']}\n"
            f"[bold]Public Key:[/bold] {card['public_key'][:32]}...",
            title="New Agent Identity",
            border_style="cyan",
        )
    )

    console.print(
        "\n[dim]Private key generated in memory. "
        "Use identity.export_private_key_pem() to save.[/dim]"
    )


@main.command()
def owasp() -> None:
    """Show OWASP Agentic Top 10 coverage map."""
    table = Table(title="OWASP Agentic Top 10 Coverage")
    table.add_column("Risk", style="white")
    table.add_column("ID", style="cyan")
    table.add_column("Agent Guard Control", style="green")

    risks = [
        ("Agent Goal Hijacking", "ASI-01", "Policy engine blocks unauthorized actions"),
        ("Excessive Capabilities", "ASI-02", "Policy rules enforce least-privilege"),
        ("Identity & Privilege Abuse", "ASI-03", "Ed25519 identity + trust scoring"),
        ("Uncontrolled Code Execution", "ASI-04", "Sandbox with permission levels"),
        ("Insecure Output Handling", "ASI-05", "Output PII/secrets filter + audit logging"),
        ("Memory Poisoning", "ASI-06", "Hash-chained audit detects tampering"),
        ("Unsafe Inter-Agent Comms", "ASI-07", "Mesh with trust-gated channels"),
        ("Cascading Failures", "ASI-08", "Circuit breakers + SLO enforcement"),
        ("Human-Agent Trust Deficit", "ASI-09", "Full audit trail + reporting"),
        ("Rogue Agents", "ASI-10", "Kill switch + trust scoring + isolation"),
    ]

    for risk, risk_id, control in risks:
        table.add_row(risk, risk_id, f"✅ {control}")

    console.print(table)


@main.command()
@click.option("--host", "-h", default="127.0.0.1", help="Bind address")
@click.option("--port", "-p", default=7700, type=int, help="Port number")
@click.option("--no-browser", is_flag=True, help="Don't open browser automatically")
def dashboard(host: str, port: int, no_browser: bool) -> None:
    """Launch the real-time governance dashboard."""
    from agent_guard.dashboard.server import run_dashboard

    guard = Guard()
    guard.add_policy(Policy.standard())

    console.print(
        f"[cyan bold]Agent Guard Dashboard[/cyan bold] starting on "
        f"[underline]http://{host}:{port}[/underline]"
    )
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")

    run_dashboard(guard, host=host, port=port, open_browser=not no_browser)


@main.group()
def tokens() -> None:
    """Token governance — discover, inventory, and audit access tokens."""
    pass


@tokens.command(name="scan")
@click.option("--dotenv", "-e", default=None, help="Path to .env file to include")
@click.option(
    "--config",
    "-c",
    "config_path",
    default=None,
    help="MCP/agent config JSON to scan",
)
def tokens_scan(dotenv: str | None, config_path: str | None) -> None:
    """Scan environment and config files for access tokens."""
    from agent_guard.tokens.inventory import TokenInventory
    from agent_guard.tokens.risk import RiskScorer
    from agent_guard.tokens.scanner import TokenScanner

    inventory = TokenInventory()
    scanner = TokenScanner(inventory=inventory)
    scorer = RiskScorer()

    records = scanner.scan_environment(dotenv_path=dotenv)
    if config_path:
        records += scanner.scan_config(config_path)

    scorer.score_all(records)

    if not records:
        console.print("[yellow]No tokens discovered.[/yellow]")
        return

    table = Table(title=f"Discovered Tokens ({len(records)})")
    table.add_column("Provider", style="cyan")
    table.add_column("Type", style="white")
    table.add_column("Masked Value", style="dim")
    table.add_column("Source", style="yellow")
    table.add_column("Detail", style="white")
    table.add_column("Risk", justify="right")

    for t in records:
        risk_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
        }.get(t.risk_level.value, "white")
        table.add_row(
            t.provider.value,
            t.token_type.value,
            t.masked_value,
            t.source.value,
            t.source_detail,
            f"[{risk_style}]{t.risk_score} ({t.risk_level.value})[/{risk_style}]",
        )

    console.print(table)


@tokens.command(name="list")
@click.option("--risk", "-r", default=None, help="Filter by risk level")
@click.option("--provider", "-p", default=None, help="Filter by provider")
@click.option("--stale", is_flag=True, help="Show only stale tokens")
@click.option("--max-age", default=90, type=int, help="Max age in days for stale")
def tokens_list(
    risk: str | None,
    provider: str | None,
    stale: bool,
    max_age: int,
) -> None:
    """List discovered tokens with optional filters."""
    from agent_guard.tokens.inventory import (
        RiskLevel,
        TokenInventory,
        TokenProvider,
    )
    from agent_guard.tokens.risk import RiskScorer
    from agent_guard.tokens.scanner import TokenScanner

    inventory = TokenInventory()
    scanner = TokenScanner(inventory=inventory)
    scanner.scan_environment()
    RiskScorer().score_all(list(inventory.list_tokens()))

    risk_filter = None
    if risk:
        try:
            risk_filter = RiskLevel(risk.lower())
        except ValueError:
            console.print(f"[red]Unknown risk level: {risk}[/red]")
            return

    provider_filter = None
    if provider:
        try:
            provider_filter = TokenProvider(provider.lower())
        except ValueError:
            console.print(f"[red]Unknown provider: {provider}[/red]")
            return

    if stale:
        records = inventory.stale_tokens(max_age)
    else:
        records = inventory.list_tokens(
            risk_level=risk_filter,
            provider=provider_filter,
        )

    if not records:
        console.print("[yellow]No tokens match the filter.[/yellow]")
        return

    table = Table(title=f"Tokens ({len(records)})")
    table.add_column("Provider", style="cyan")
    table.add_column("Masked Value", style="dim")
    table.add_column("Source", style="yellow")
    table.add_column("Age (days)", justify="right")
    table.add_column("Uses", justify="right")
    table.add_column("Risk", justify="right")

    for t in records:
        risk_style = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "green",
        }.get(t.risk_level.value, "white")
        table.add_row(
            t.provider.value,
            t.masked_value,
            t.source_detail or t.source.value,
            f"{t.age_days:.0f}",
            str(t.use_count),
            f"[{risk_style}]{t.risk_score}[/{risk_style}]",
        )

    console.print(table)


main.add_command(tokens)


@main.command()
def init() -> None:
    """Initialize Agent Guard in the current project."""
    policies_dir = Path("policies")
    policies_dir.mkdir(exist_ok=True)

    policy = Policy.standard()
    import yaml

    data = {
        "name": policy.name,
        "description": policy.description,
        "version": policy.version,
        "default_effect": policy.default_effect.value,
        "rules": [
            {
                "name": r.name,
                "action": r.action,
                "effect": r.effect.value,
                **({"reason": r.reason} if r.reason else {}),
            }
            for r in policy.rules
        ],
    }

    policy_file = policies_dir / "standard.yaml"
    policy_file.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))

    console.print("[green bold]✓ Agent Guard initialized![/green bold]\n")
    console.print(f"  Created: {policy_file}")
    console.print("\n[bold]Next steps:[/bold]")
    console.print("  1. Edit policies/standard.yaml to customize rules")
    console.print("  2. Add to your agent code:")
    console.print("     [cyan]from agent_guard import Guard[/cyan]")
    console.print("     [cyan]guard = Guard()[/cyan]")
    console.print('     [cyan]guard.load_policy("policies/standard.yaml")[/cyan]')
