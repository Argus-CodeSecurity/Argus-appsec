"""Built-in ``argus`` commands, one module per command family.

The command functions are plain functions; :func:`register_commands` attaches
them to the root app. Registration happens in one place, in a fixed order,
because Typer lists commands in ``argus --help`` in the order they were added.
"""

from __future__ import annotations

import typer

from argus.cli.commands import (
    baseline,
    focused,
    inventory,
    meta,
    monitor,
    policy,
    remediate,
    scan,
    service,
    supply_chain,
)


def register_commands(app: typer.Typer) -> None:
    """Attach every built-in command and command group to ``app``."""
    app.command()(scan.scan)
    app.command()(supply_chain.sbom)
    app.command()(supply_chain.dependencies)
    app.command(name="supply-chain")(supply_chain.supply_chain_cmd)
    app.command()(focused.secrets)
    app.command()(focused.iac)
    app.command(name="api")(focused.api_scan)
    app.command()(focused.cicd)
    app.command()(focused.container)
    app.command()(focused.cloud)
    app.command()(focused.infrastructure)
    app.command()(inventory.inventory)
    app.command()(inventory.drift)
    app.command()(monitor.watch)
    app.command()(monitor.agent)
    app.command()(remediate.fix)
    app.command()(meta.scanners)
    app.command()(meta.reporters)
    app.command()(service.mcp)
    app.command()(service.push)
    app.command()(remediate.review)
    app.command()(remediate.learn)
    app.command()(meta.providers)
    app.command()(service.dashboard)
    app.command()(meta.init)
    app.command()(meta.version)

    app.add_typer(baseline.baseline_app, name="baseline")
    app.add_typer(monitor.server_app, name="server")
    app.add_typer(policy.policy_app, name="policy")
