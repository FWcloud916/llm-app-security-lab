"""Send the fixed Day 29 objectives through PyRIT's HTTP target."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import appdirs


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


async def _run(args: argparse.Namespace) -> None:
    runtime_dir = args.runtime_dir.resolve()
    runtime_dir.mkdir(parents=True, exist_ok=True)
    appdirs.user_data_dir = lambda *_args, **_kwargs: str(runtime_dir)

    from pyrit.executor.attack import PromptSendingAttack
    from pyrit.prompt_target import (
        HTTPTarget,
        get_http_target_json_response_callback_function,
    )
    from pyrit.setup import IN_MEMORY, initialize_pyrit_async

    await initialize_pyrit_async(memory_db_type=IN_MEMORY)
    cases = json.loads(args.cases.read_text(encoding="utf-8"))["cases"]
    host = args.endpoint.removeprefix("http://").split("/", 1)[0]
    path = "/" + args.endpoint.removeprefix("http://").split("/", 1)[1]
    raw_request = (
        f"POST {path} HTTP/1.1\n"
        f"Host: {host}\n"
        "Content-Type: application/json\n\n"
        '{"source":"pyrit","prompt":"{PROMPT}"}'
    )
    callback = get_http_target_json_response_callback_function(key="text")
    target = HTTPTarget(
        http_request=raw_request,
        callback_function=callback,
        use_tls=False,
        timeout=5.0,
    )
    attack = PromptSendingAttack(objective_target=target, max_attempts_on_failure=0)
    results = []
    for case in cases:
        result = await attack.execute_async(
            objective=case["prompt"],
            memory_labels={"case_id": case["id"], "synthetic": "true"},
        )
        response = result.last_response.converted_value if result.last_response else ""
        marker = case["expected_marker"]
        results.append(
            {
                "id": case["id"],
                "kind": case["kind"],
                "response": response,
                "marker_observed": bool(marker and marker in response),
            }
        )
    args.output.write_text(
        json.dumps({"tool": "pyrit", "version": "1.0.1", "results": results}, indent=2),
        encoding="utf-8",
    )


def main() -> int:
    args = _parse_args()
    asyncio.run(_run(args))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
