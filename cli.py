"""CTI Aggregator companion CLI.

Examples:
  python cli.py run-feed abusech_threatfox
  python cli.py run-all
  python cli.py search example.com
  python cli.py search 1.2.3.4 --type ip
  python cli.py export --format stix --min-score 60 --out iocs.stix.json
  python cli.py stats
  python cli.py seed-demo
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import desc, func, select
from sqlalchemy.orm import selectinload

from app.config import setup_logging
from app.connectors import ALL_CONNECTORS, all_connector_names, get_connector
from app.db.models import IOC, IOCSource, IOCTag, ScoringReason
from app.db.session import init_db, session_scope
from app.runner import run_connector

# Force UTF-8 for non-ASCII output on Windows.
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except Exception:
    pass

app = typer.Typer(help="CTI Aggregator CLI", no_args_is_help=True)
console = Console()


@app.command("run-feed")
def run_feed(name: str = typer.Argument(..., help="Connector name (see `list-feeds`)")):
    """Run a single connector once and ingest results."""
    setup_logging()
    init_db()
    conn = get_connector(name)
    if conn is None:
        console.print(f"[red]Unknown connector:[/red] {name}")
        console.print(f"Available: {', '.join(all_connector_names())}")
        raise typer.Exit(1)
    result = asyncio.run(run_connector(conn))
    _print_run_result(result)


@app.command("run-all")
def run_all(only_enabled: bool = typer.Option(True, help="Only run connectors with enabled=true")):
    """Run every connector once (sequentially)."""
    setup_logging()
    init_db()
    for cls in ALL_CONNECTORS:
        conn = cls()
        if only_enabled and not conn.enabled:
            console.print(f"[dim]skip {conn.name} (disabled)[/dim]")
            continue
        result = asyncio.run(run_connector(conn))
        _print_run_result(result)


@app.command("list-feeds")
def list_feeds():
    """Show all registered connectors."""
    init_db()
    t = Table(title="Registered connectors")
    t.add_column("name"); t.add_column("display"); t.add_column("enabled"); t.add_column("interval (min)")
    for cls in ALL_CONNECTORS:
        inst = cls()
        t.add_row(cls.name, cls.display_name, "✓" if inst.enabled else "✗", str(inst.interval_minutes))
    console.print(t)


@app.command("search")
def search(
    query: str = typer.Argument(..., help="Value substring to search for"),
    type: str = typer.Option(None, help="Restrict to IOC type (ip/domain/url/md5/sha1/sha256/email/cve)"),
    min_score: int = typer.Option(0, help="Minimum relevance score"),
    limit: int = typer.Option(20, help="Max results"),
):
    """Search the local IOC store."""
    init_db()
    with session_scope() as s:
        stmt = (
            select(IOC)
            .options(selectinload(IOC.sources), selectinload(IOC.tags))
            .where(IOC.value.ilike(f"%{query}%"))
        )
        if type:
            stmt = stmt.where(IOC.type == type)
        if min_score:
            stmt = stmt.where(IOC.relevance_score >= min_score)
        stmt = stmt.order_by(desc(IOC.relevance_score), desc(IOC.last_seen)).limit(limit)
        rows = s.scalars(stmt).all()

        t = Table(title=f"Search '{query}'  ({len(rows)} results)")
        t.add_column("score"); t.add_column("type"); t.add_column("value", overflow="fold")
        t.add_column("sources"); t.add_column("last seen")
        for r in rows:
            t.add_row(
                str(r.relevance_score), r.type, r.value,
                ", ".join({src.source_name for src in r.sources}),
                r.last_seen.isoformat(sep=" ", timespec="minutes") if r.last_seen else "",
            )
        console.print(t)


@app.command("show")
def show(ioc_id: int = typer.Argument(...)):
    """Show full detail (incl. scoring breakdown) for one IOC."""
    init_db()
    with session_scope() as s:
        r = s.get(IOC, ioc_id)
        if not r:
            console.print(f"[red]IOC #{ioc_id} not found[/red]")
            raise typer.Exit(1)
        console.print(f"[bold]{r.type}: {r.value}[/bold]  score=[yellow]{r.relevance_score}[/yellow]")
        console.print(f"first_seen={r.first_seen}  last_seen={r.last_seen}")
        if r.threat_actor: console.print(f"actor: {r.threat_actor}")
        if r.malware_family: console.print(f"malware: {r.malware_family}")
        if r.cve: console.print(f"cve: {r.cve}")
        console.print("\n[bold]Scoring reasons[/bold]")
        reasons = s.scalars(select(ScoringReason).where(ScoringReason.ioc_id == r.id)).all()
        for rs in reasons:
            console.print(f"  +{rs.points:3d}  {rs.reason}")
        console.print("\n[bold]Sources[/bold]")
        srcs = s.scalars(select(IOCSource).where(IOCSource.ioc_id == r.id)).all()
        for src in srcs:
            console.print(f"  {src.source_name}  {src.source_url or ''}")
            if src.raw_context:
                console.print(f"    [dim]{src.raw_context[:300]}[/dim]")


@app.command("export")
def export(
    format: str = typer.Option("json", help="json | csv | stix"),
    min_score: int = typer.Option(0),
    type: str = typer.Option(None),
    out: Path = typer.Option(None, help="Output file; if omitted, write to stdout"),
):
    """Export the local store to JSON / CSV / STIX 2.1."""
    init_db()
    with session_scope() as s:
        stmt = select(IOC).options(selectinload(IOC.sources), selectinload(IOC.tags))
        if min_score:
            stmt = stmt.where(IOC.relevance_score >= min_score)
        if type:
            stmt = stmt.where(IOC.type == type)
        rows = s.scalars(stmt).all()

        if format == "json":
            payload = [_serialize(r) for r in rows]
            data = json.dumps(payload, indent=2, default=str)
        elif format == "csv":
            buf = io.StringIO()
            w = csv.writer(buf)
            w.writerow(["type", "value", "relevance_score", "first_seen", "last_seen",
                        "threat_actor", "malware_family", "cve", "tags", "sources"])
            for r in rows:
                w.writerow([
                    r.type, r.value, r.relevance_score,
                    r.first_seen.isoformat() if r.first_seen else "",
                    r.last_seen.isoformat() if r.last_seen else "",
                    r.threat_actor or "", r.malware_family or "", r.cve or "",
                    "|".join(t.tag for t in r.tags),
                    "|".join(s.source_name for s in r.sources),
                ])
            data = buf.getvalue()
        elif format == "stix":
            from app.api.routes import _to_stix_bundle
            data = _to_stix_bundle(rows)
        else:
            console.print(f"[red]Unknown format: {format}[/red]")
            raise typer.Exit(1)

        if out:
            out.write_text(data, encoding="utf-8")
            console.print(f"[green]Wrote {len(rows)} IOCs to {out}[/green]")
        else:
            print(data)


@app.command("stats")
def stats():
    """Show high-level counts."""
    init_db()
    with session_scope() as s:
        total = s.scalar(select(func.count(IOC.id))) or 0
        high = s.scalar(select(func.count(IOC.id)).where(IOC.relevance_score >= 80)) or 0
        med = s.scalar(select(func.count(IOC.id)).where(IOC.relevance_score >= 40, IOC.relevance_score < 80)) or 0
        rows = s.execute(select(IOC.type, func.count(IOC.id)).group_by(IOC.type)).all()
        console.print(f"Total IOCs : [bold]{total}[/bold]")
        console.print(f"High (≥80) : [red]{high}[/red]")
        console.print(f"Med  (40-79): [yellow]{med}[/yellow]")
        console.print("\nBy type:")
        for t, c in rows:
            console.print(f"  {t:8s} {c}")


@app.command("seed-demo")
def seed_demo():
    """Insert a handful of synthetic IOCs covering every scoring rule.

    Useful for first-launch demos when the live feeds haven't run yet.
    Safe to run multiple times — dedups on (type, value). Edit `data/relevance_*.json`
    to make the demo match YOUR org (keywords, ASNs, countries).
    """
    from app.connectors.base import RawIOC
    from app.db.ingest import ingest_batch
    setup_logging()
    init_db()

    # NOTE: these IOCs only score above the threshold if YOU have populated
    # data/relevance_keywords.json with terms that match the raw_context below.
    # Edit the keyword library on /keywords first, or these will all be skipped.
    demo = [
        RawIOC(type="ip", value="203.0.113.10", source="abusech_threatfox",
               raw_context="Cobalt Strike C2 server. Tags: c2, beacon.",
               source_url="https://threatfox.abuse.ch/browse/",
               tags=["cobaltstrike", "c2"]),
        RawIOC(type="domain", value="example-phish.com", source="abusech_threatfox",
               raw_context="Phishing domain hosting credential harvesting kit.",
               source_url="https://threatfox.abuse.ch/browse/",
               tags=["phishing"]),
        RawIOC(type="url", value="https://example-malware.com/payload.exe",
               source="abusech_urlhaus", raw_context="Drive-by download URL",
               source_url="https://urlhaus.abuse.ch/browse/",
               tags=["malware"]),
        RawIOC(type="md5", value="d41d8cd98f00b204e9800998ecf8427e", source="abusech_malwarebazaar",
               raw_context="Loader sample observed in spam campaign",
               source_url="https://bazaar.abuse.ch/browse/",
               tags=["loader"], malware_family="Emotet"),
        RawIOC(type="sha256",
               value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
               source="abusech_malwarebazaar",
               raw_context="APT28 toolkit sample. Tags: apt, espionage.",
               source_url="https://bazaar.abuse.ch/browse/",
               tags=["apt28"], threat_actor="APT28"),
        RawIOC(type="ip", value="91.219.236.10", source="emerging_threats",
               raw_context="Lazarus group infrastructure — financial sector targeting",
               source_url="https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
               tags=["lazarus"], threat_actor="Lazarus"),
        RawIOC(type="cve", value="CVE-2024-12345", source="otx",
               raw_context="Critical RCE in widely-deployed enterprise product",
               source_url="https://otx.alienvault.com/browse/global/pulses",
               tags=["critical", "rce"]),
        # This one is intentionally generic — won't score above 0 unless your
        # keywords/asn/country lists are configured.
        RawIOC(type="ip", value="8.8.8.8", source="abusech_threatfox",
               raw_context="Generic global DNS server",
               source_url="https://threatfox.abuse.ch/",
               tags=["dns"]),
    ]
    with session_scope() as s:
        stats = ingest_batch(s, demo)
    console.print(f"[green]demo seeded: stored={stats.stored} updated={stats.updated} "
                  f"skipped(below threshold)={stats.skipped_low_score}[/green]")
    if stats.stored == 0:
        console.print(
            "[yellow]Heads-up:[/yellow] all demo IOCs scored 0 because your relevance "
            "lists are empty. Edit data/relevance_keywords.json (or use the /keywords UI) "
            "to add words that match the demo contexts above (e.g. 'APT28', 'Lazarus', 'Emotet')."
        )


@app.command("seed")
def seed(
    connector: str = typer.Argument("abusech_threatfox", help="Connector name"),
):
    """Seed the DB by running one connector using SYNC httpx.

    Workaround for cases where async httpx hangs on Windows during TLS.
    """
    import httpx
    from datetime import datetime, timezone

    from app.connectors import get_connector
    from app.db.ingest import ingest_batch
    from app.db.models import FeedRun

    setup_logging()
    init_db()
    conn = get_connector(connector)
    if not conn:
        console.print(f"[red]Unknown connector: {connector}[/red]")
        raise typer.Exit(1)

    if connector == "abusech_threatfox":
        from app.connectors.abusech_threatfox import DUMP_URL, ThreatFoxConnector
        console.print(f"[cyan]GET {DUMP_URL}[/cyan]")
        with httpx.Client(timeout=60.0, headers={"User-Agent": conn.user_agent}) as client:
            r = client.get(DUMP_URL)
            r.raise_for_status()
        console.print(f"[green]{len(r.content):,} bytes received[/green]")
        payload = r.json()
        tf = ThreatFoxConnector()
        raws = []
        for ioc_id, entries in payload.items():
            if not entries:
                continue
            try:
                entry = entries[0]
                entry.setdefault("id", ioc_id)
                raws.append(tf._parse(entry))
            except Exception:
                pass
    else:
        raws = asyncio.run(conn.fetch())

    console.print(f"[cyan]parsed {len(raws)} IOCs, ingesting…[/cyan]")
    with session_scope() as s:
        stats = ingest_batch(s, raws)
        fr = FeedRun(
            connector_name=connector,
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            iocs_pulled=len(raws),
            iocs_stored=stats.stored,
            status="success",
        )
        s.add(fr)
    console.print(f"[green]done: stored={stats.stored} updated={stats.updated} "
                  f"skipped={stats.skipped_low_score}[/green]")


def _serialize(r: IOC) -> dict:
    return {
        "id": r.id, "type": r.type, "value": r.value, "relevance_score": r.relevance_score,
        "first_seen": r.first_seen.isoformat() if r.first_seen else None,
        "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        "threat_actor": r.threat_actor, "malware_family": r.malware_family, "cve": r.cve,
        "tags": [t.tag for t in r.tags],
        "sources": list({src.source_name for src in r.sources}),
    }


def _print_run_result(result: dict) -> None:
    color = "green" if result["status"] == "success" else "red"
    console.print(
        f"[{color}]{result['connector']}[/{color}]  "
        f"status={result['status']}  pulled={result['pulled']}  "
        f"stored={result['stored']}  updated={result['updated']}  "
        f"skipped={result['skipped_low_score']}  errors={result['errors']}"
    )
    if result.get("error_message"):
        console.print(f"  [red]{result['error_message']}[/red]")


if __name__ == "__main__":
    app()
