from __future__ import annotations

from llm_security_lab import cli
from llm_security_lab.lab import DEFAULT_EXPERIMENT


def test_legacy_cli_defaults_to_day_4() -> None:
    args = cli.build_parser().parse_args(["--scenario", "clean"])

    assert args.experiment == DEFAULT_EXPERIMENT
    assert args.repeat == 1


def test_repeat_is_bounded() -> None:
    parser = cli.build_parser()

    assert parser.parse_args(["--scenario", "clean", "--repeat", "3"]).repeat == 3


def test_planned_run_selector_is_explicit() -> None:
    args = cli.build_parser().parse_args(
        ["--experiment", "day-08-prompt-injection-mechanism", "--run-plan"]
    )

    assert args.run_plan is True
    assert args.scenario is None
