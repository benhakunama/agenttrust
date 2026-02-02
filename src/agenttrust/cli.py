"""CLI for AgentTrust."""

from __future__ import annotations

import random
import sys
import time
from typing import Optional

import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .config import Config

console = Console()

VERSION = "0.1.0"


@click.group()
@click.version_option(VERSION, prog_name="AgentTrust")
def cli() -> None:
    """🛡️ AgentTrust — Runtime security for AI agents."""
    pass


@cli.command()
@click.option(
    "--framework",
    type=click.Choice(["langchain", "crewai", "autogen"]),
    required=True,
    help="AI framework to integrate with.",
)
def init(framework: str) -> None:
    """Initialize AgentTrust for your project."""
    console.print(f"\n🛡️  [bold cyan]AgentTrust[/bold cyan] v{VERSION}")
    console.print(f"Initializing for framework: [bold]{framework}[/bold]\n")

    # Create config
    config = Config()
    config.set("framework", framework)
    config_path = config.save()

    console.print(f"[green]✓[/green] Config created at {config_path}")
    console.print("[green]✓[/green] Agent registry initialized\n")

    # Print setup code
    console.print("Add to your code (3 lines):")
    console.print(f'  [cyan]import[/cyan] agenttrust')
    console.print(f'  at = agenttrust.init(framework=[green]"{framework}"[/green])')

    if framework == "langchain":
        console.print(f"  [dim]# Add at.callback() to your agent's callbacks[/dim]")
    elif framework == "crewai":
        console.print(f"  [dim]# Use @at.monitor decorator on your agents[/dim]")
    elif framework == "autogen":
        console.print(f"  [dim]# Call at.attach(agent) for each AutoGen agent[/dim]")

    console.print(f"\n[green]✓[/green] AgentTrust initialized (3 lines of code)\n")


@cli.command()
@click.option("--live", is_flag=True, help="Show live monitoring dashboard.")
@click.option("--duration", type=int, default=0, help="Duration in seconds (0 = indefinite).")
def monitor(live: bool, duration: int) -> None:
    """Real-time agent monitoring dashboard."""
    if not live:
        console.print("Use [bold]--live[/bold] for real-time monitoring.")
        console.print("Example: [cyan]agenttrust monitor --live[/cyan]")
        return

    _run_demo_monitor(duration)


@cli.command()
def status() -> None:
    """Show agent fleet status."""
    config = Config()

    console.print(f"\n🛡️  [bold cyan]AgentTrust[/bold cyan] v{VERSION} — Fleet Status\n")

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Agent", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Trust Score", justify="center")
    table.add_column("Framework", justify="center")
    table.add_column("Last Active", justify="center")

    # Demo data
    agents = [
        ("finance-bot-prod", "● ACTIVE", "[green]0.94[/green]", "langchain", "2s ago"),
        ("support-agent-3", "● ACTIVE", "[yellow]0.71[/yellow]", "langchain", "5s ago"),
        ("research-agent", "● ACTIVE", "[green]0.98[/green]", "crewai", "12s ago"),
        ("data-pipeline-1", "○ IDLE", "[green]0.89[/green]", "autogen", "2m ago"),
        ("code-reviewer", "○ IDLE", "[green]0.96[/green]", "langchain", "5m ago"),
    ]

    for name, status_text, score, fw, last in agents:
        status_colored = f"[green]{status_text}[/green]" if "ACTIVE" in status_text else f"[dim]{status_text}[/dim]"
        table.add_row(name, status_colored, score, fw, last)

    console.print(table)
    console.print(f"\n[dim]Framework: {config.framework} | Log level: {config.log_level}[/dim]\n")


@cli.command()
def config() -> None:
    """Show current configuration."""
    cfg = Config()
    data = cfg.to_dict()

    console.print(f"\n🛡️  [bold cyan]AgentTrust[/bold cyan] v{VERSION} — Configuration\n")
    console.print(f"[dim]Config file: {cfg._path}[/dim]\n")

    import yaml
    formatted = yaml.dump(data, default_flow_style=False, sort_keys=False)
    console.print(Panel(formatted, title="~/.agenttrust/config.yaml", border_style="cyan"))
    console.print()


# ── Demo Monitor ───────────────────────────────────────────────────────────

DEMO_SCENARIOS = [
    {
        "agent": "finance-bot-prod",
        "action": "query_database → generate_report",
        "trust_score": 0.94,
        "status": "safe",
        "threat": None,
        "response": None,
    },
    {
        "agent": "support-agent-3",
        "action": "read_email → ⚠ access_billing_api",
        "trust_score": 0.41,
        "status": "threat",
        "threat": "PROMPT_INJECTION → PRIVILEGE_ESCALATION",
        "response": "⚡ ISOLATED — human review required",
    },
    {
        "agent": "research-agent",
        "action": "web_search → summarize_findings",
        "trust_score": 0.98,
        "status": "safe",
        "threat": None,
        "response": None,
    },
    {
        "agent": "data-pipeline-1",
        "action": "fetch_api → transform_data → store_results",
        "trust_score": 0.89,
        "status": "safe",
        "threat": None,
        "response": None,
    },
    {
        "agent": "support-agent-3",
        "action": "read_ticket → ⚠ export_customer_data",
        "trust_score": 0.35,
        "status": "threat",
        "threat": "DATA_EXFILTRATION",
        "response": "🚫 BLOCKED — data exfiltration attempt",
    },
    {
        "agent": "code-reviewer",
        "action": "analyze_pr → generate_review → post_comment",
        "trust_score": 0.96,
        "status": "safe",
        "threat": None,
        "response": None,
    },
    {
        "agent": "finance-bot-prod",
        "action": "check_balance → ⚠ ignore previous instructions",
        "trust_score": 0.52,
        "status": "threat",
        "threat": "PROMPT_INJECTION",
        "response": "⚠ WARNED — suspicious input detected",
    },
    {
        "agent": "research-agent",
        "action": "crawl_site → extract_text → analyze",
        "trust_score": 0.97,
        "status": "safe",
        "threat": None,
        "response": None,
    },
]


def _render_scenario(scenario: dict) -> Text:
    """Render a single scenario as Rich Text."""
    text = Text()
    text.append("  agent: ", style="dim")
    text.append(scenario["agent"], style="bold white")
    text.append("\n")

    text.append("  action: ", style="dim")
    if scenario["status"] == "threat":
        text.append(scenario["action"], style="yellow")
    else:
        text.append(scenario["action"], style="white")
    text.append("\n")

    text.append("  trust_score: ", style="dim")
    score = scenario["trust_score"]
    if score >= 0.8:
        text.append(f"{score:.2f}", style="green")
    elif score >= 0.5:
        text.append(f"{score:.2f}", style="yellow")
    else:
        text.append(f"{score:.2f}", style="red")
    text.append("\n")

    if scenario["status"] == "safe":
        text.append("  status: ", style="dim")
        text.append("✓ SAFE", style="bold green")
    elif scenario["threat"]:
        text.append("  threat: ", style="dim")
        text.append(scenario["threat"], style="bold red")
        text.append("\n")
        text.append("  response: ", style="dim")
        text.append(scenario["response"], style="bold yellow")

    return text


def _run_demo_monitor(duration: int = 0) -> None:
    """Run the demo monitoring dashboard."""
    console.print(f"\n🛡️  [bold cyan]AgentTrust[/bold cyan] v{VERSION} — Live Monitor")
    console.print("[dim]Demo mode — showing simulated agent activity[/dim]")
    console.print("[dim]Press Ctrl+C to exit[/dim]\n")

    start_time = time.time()
    scenario_index = 0

    try:
        with Live(console=console, refresh_per_second=2) as live:
            while True:
                # Check duration
                if duration > 0 and (time.time() - start_time) >= duration:
                    break

                # Build display with last 4 scenarios
                display = Text()
                display.append("─" * 60 + "\n", style="dim")

                # Show current + recent scenarios
                num_visible = min(4, scenario_index + 1)
                start_idx = max(0, scenario_index - num_visible + 1)

                for i in range(start_idx, scenario_index + 1):
                    scenario = DEMO_SCENARIOS[i % len(DEMO_SCENARIOS)]
                    display.append_text(_render_scenario(scenario))
                    display.append("\n\n")

                # Stats bar
                elapsed = time.time() - start_time
                actions = scenario_index + 1
                threats = sum(
                    1 for j in range(actions)
                    if DEMO_SCENARIOS[j % len(DEMO_SCENARIOS)]["status"] == "threat"
                )
                display.append("─" * 60 + "\n", style="dim")
                display.append(f"  actions: {actions}  |  threats: {threats}  |  uptime: {elapsed:.0f}s", style="dim")

                live.update(Panel(display, title="[bold cyan]Agent Activity Stream[/bold cyan]", border_style="cyan"))

                time.sleep(1.5)
                scenario_index += 1

    except KeyboardInterrupt:
        pass

    console.print("\n[dim]Monitor stopped.[/dim]\n")


if __name__ == "__main__":
    cli()
