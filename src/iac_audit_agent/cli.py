from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Optional

import typer
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

load_dotenv()

app = typer.Typer(help="iac-audit-agent — LangGraph-powered IaC security, compliance & cost auditing")
console = Console()

_SEVERITY_COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "blue",
    "INFO": "dim",
}


@app.command()
def audit(
    path: str = typer.Argument(..., help="IaC directory or file to audit"),
    format: str = typer.Option("rich", help="Output format: rich | json | markdown"),
    skip_human_review: bool = typer.Option(False, "--skip-human-review", help="Auto-approve human review checkpoints"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Write report to file"),
) -> None:
    """Run the full LangGraph audit agent against a Terraform or CloudFormation path."""
    from iac_audit_agent.graph import build_graph

    console.print(Panel.fit(f"[bold]IaC Audit Agent[/bold]\nTarget: [cyan]{path}[/cyan]", border_style="blue"))

    graph = build_graph(with_checkpointer=True)
    run_id = uuid.uuid4().hex[:8]
    config = {"configurable": {"thread_id": run_id}}

    initial_state = {
        "iac_path": path, "iac_type": "unknown", "raw_content": "", "resources": [],
        "security_findings": [], "compliance_findings": [], "cost_findings": [],
        "cost_savings_estimate": 0.0, "all_findings": [], "severity_score": 0.0,
        "requires_human_review": False, "human_decision": None, "human_notes": None,
        "report": None, "error": None,
    }

    with console.status("[bold green]Running parallel audit nodes…"):
        result = graph.invoke(initial_state, config=config)

    if result.get("error"):
        console.print(f"[red]Error:[/red] {result['error']}")
        raise typer.Exit(1)

    if result.get("requires_human_review") and result.get("report") is None:
        findings = result.get("all_findings", [])
        critical = [f for f in findings if f.severity == "CRITICAL"]
        high = [f for f in findings if f.severity == "HIGH"]
        console.print(Panel(
            f"[bold red]{len(critical)} CRITICAL  |  {len(high)} HIGH findings[/bold red]\n"
            f"Score: [red]{result.get('severity_score', 0):.1f}/10[/red]",
            title="⚠️  Human Review Required", border_style="red",
        ))
        for f in (critical + high)[:5]:
            console.print(f"  [red]•[/red] [{f.severity}] {f.resource_type}.{f.resource} — {f.message[:90]}")

        if skip_human_review:
            decision = "approve"
            console.print("[yellow]--skip-human-review → auto-approving[/yellow]")
        else:
            decision = typer.prompt("\nDecision", default="approve",
                                    prompt_suffix=" [approve / override / reject]: ").strip().lower()

        graph.update_state(config, {"human_decision": decision}, as_node="human_review")
        with console.status("[bold green]Resuming agent…"):
            result = graph.invoke(None, config=config)

    if result.get("error"):
        console.print(f"[red]Error:[/red] {result['error']}")
        raise typer.Exit(1)

    report = result.get("report", {})

    if format == "json":
        text = json.dumps(report, indent=2, default=str)
        _write_or_print(text, output, console)
        return

    if format == "markdown":
        text = _to_markdown(report)
        _write_or_print(text, output, console)
        return

    _print_rich_report(report, console)
    if output:
        Path(output).write_text(json.dumps(report, indent=2, default=str))
        console.print(f"\nReport saved to [cyan]{output}[/cyan]")


def _print_rich_report(report: dict, console: Console) -> None:
    summary = report.get("summary", {})
    score = report.get("severity_score", 0.0)
    score_color = "red" if score >= 7 else "yellow" if score >= 4 else "green"
    console.print(f"\n[bold]Run:[/bold] {report.get('run_id')}")
    console.print(f"[bold]IaC type:[/bold] {report.get('iac_type')}")
    console.print(f"[bold]Severity score:[/bold] [{score_color}]{score:.1f} / 10[/{score_color}]")
    console.print(f"[bold]Cost savings:[/bold] ${summary.get('cost_savings_estimate_usd_monthly', 0):.0f} / mo\n")

    tbl = Table(title="Findings summary", show_header=True, header_style="bold")
    tbl.add_column("Severity")
    tbl.add_column("Count", justify="right")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = summary.get(sev, 0)
        if count:
            col = _SEVERITY_COLORS[sev]
            tbl.add_row(f"[{col}]{sev}[/{col}]", f"[{col}]{count}[/{col}]")
    console.print(tbl)
    console.print()

    for f in report.get("findings", []):
        sev = f.get("severity", "INFO")
        col = _SEVERITY_COLORS.get(sev, "white")
        console.print(f"[{col}][{sev}][/{col}] [dim]({f.get('category')})[/dim]  "
                      f"[bold]{f.get('resource_type')}.{f.get('resource')}[/bold]  "
                      f"[dim]→ {f.get('rule')}[/dim]")
        console.print(f"   {f.get('message')}")
        console.print(f"   [dim]Fix: {f.get('remediation')}[/dim]\n")


def _to_markdown(report: dict) -> str:
    summary = report.get("summary", {})
    lines = [
        "# IaC Audit Report", "",
        f"**Run ID:** `{report.get('run_id')}`  ",
        f"**IaC type:** {report.get('iac_type')}  ",
        f"**Severity score:** {report.get('severity_score', 0):.1f} / 10  ",
        f"**Human reviewed:** {report.get('human_reviewed')}  ",
        "", "## Summary", "",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = summary.get(sev, 0)
        if n:
            lines.append(f"- **{sev}:** {n}")
    lines.append(f"- **Estimated savings:** ${summary.get('cost_savings_estimate_usd_monthly', 0):.0f} / mo")
    lines += ["", "## Findings", ""]
    for f in report.get("findings", []):
        lines += [
            f"### [{f.get('severity')}] `{f.get('resource_type')}.{f.get('resource')}` — {f.get('rule')}",
            "",
            f"**Category:** {f.get('category')}  ",
            f"**Message:** {f.get('message')}  ",
            f"**Remediation:** {f.get('remediation')}  ",
            "",
        ]
    return "\n".join(lines)


def _write_or_print(text: str, output: Optional[str], console: Console) -> None:
    if output:
        Path(output).write_text(text)
        console.print(f"Report written to [cyan]{output}[/cyan]")
    else:
        print(text)


if __name__ == "__main__":
    app()
