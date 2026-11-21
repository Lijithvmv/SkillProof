"""The `skillproof` command. Commands live in one module per group (analysis, catalogue, evaluation, operations); each
command's handler returns (result, exit code), and the result is written as JSON to --output. `serve` and
`service-file` return only an exit code. Exit codes: 0 pass, 1 needs attention, 2 blocked, 3 insufficient evidence,
4 invalid input or environment (each command's help says which apply)."""
from __future__ import annotations

import argparse

from skillproof import __version__
from skillproof.config import settings

from skillproof.cli import analysis, catalogue, evaluation, operations
from skillproof.cli.analysis import assurance_gate, scan_archive
from skillproof.cli.common import write_json

__all__ = ["main", "scan_archive", "assurance_gate"]


def build_parser() -> argparse.ArgumentParser:
    conf = settings()
    parser = argparse.ArgumentParser(prog="skillproof", description="Analyze agent skill packages and enforce assurance gates.")
    parser.add_argument("--version", action="version", version=f"SkillProof {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    for group in (analysis, catalogue, evaluation, operations):
        group.add(commands, conf)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    outcome = args.run(args)
    if isinstance(outcome, int):
        return outcome
    result, exit_code = outcome
    write_json(result, args.output)
    return exit_code
