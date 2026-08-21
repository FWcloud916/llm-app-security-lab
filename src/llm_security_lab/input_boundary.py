"""Validate and serialize one task-specific untrusted-input envelope."""

from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Any

INPUT_BOUNDARY_VERSION = 1
TASK_ID_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
POLICY_KEYS = {
    "version",
    "task_id",
    "max_user_chars",
    "max_reference_notes",
    "max_note_chars",
    "max_target_chars",
    "max_total_text_chars",
    "allowed_image_media_types",
    "max_image_bytes",
    "require_image",
}


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ValueError(f"input boundary {label} must be a positive integer")
    return value


def validate_input_boundary(raw: object) -> dict[str, Any]:
    """Return one strict versioned policy or fail closed."""
    if not isinstance(raw, dict) or set(raw) != POLICY_KEYS:
        raise ValueError("input boundary must contain exactly the version 1 policy fields")
    if raw.get("version") != INPUT_BOUNDARY_VERSION:
        raise ValueError("input boundary version must be 1")
    task_id = raw.get("task_id")
    if not isinstance(task_id, str) or not TASK_ID_PATTERN.fullmatch(task_id):
        raise ValueError("input boundary task_id must use lowercase kebab-case")
    media_types = raw.get("allowed_image_media_types")
    if media_types != ["image/png"]:
        raise ValueError("input boundary allowed_image_media_types must be exactly image/png")
    if not isinstance(raw.get("require_image"), bool):
        raise ValueError("input boundary require_image must be boolean")

    policy = deepcopy(raw)
    for field in (
        "max_user_chars",
        "max_reference_notes",
        "max_note_chars",
        "max_target_chars",
        "max_total_text_chars",
        "max_image_bytes",
    ):
        policy[field] = _positive_int(raw.get(field), field)
    if policy["max_total_text_chars"] < max(
        policy["max_user_chars"], policy["max_note_chars"], policy["max_target_chars"]
    ):
        raise ValueError("input boundary max_total_text_chars is smaller than one field limit")
    return policy


def _validate_text(content: object, limit: int, reason_code: str) -> str:
    if not isinstance(content, str) or not content.strip():
        raise ValueError(f"input boundary rejected: {reason_code}:empty")
    if len(content) > limit:
        raise ValueError(f"input boundary rejected: {reason_code}:too_long")
    return content


def build_input_boundary_message(
    *,
    raw_policy: object,
    user_request: str,
    notes: list[dict[str, Any]],
    target: dict[str, Any] | None,
    image: dict[str, Any] | None,
    turn: int,
) -> tuple[str, dict[str, Any]]:
    """Validate application-owned sources and serialize canonical untrusted JSON."""
    policy = validate_input_boundary(raw_policy)
    if not isinstance(turn, int) or isinstance(turn, bool) or turn < 1:
        raise ValueError("input boundary turn must be a positive integer")

    user_content = _validate_text(user_request, policy["max_user_chars"], "user_request")
    inputs: list[dict[str, Any]] = [
        {
            "content": user_content,
            "kind": "user_request",
            "provenance": "caller",
            "trust": "untrusted",
        }
    ]
    text_chars = len(user_content)

    if turn == 1:
        if len(notes) > policy["max_reference_notes"]:
            raise ValueError("input boundary rejected: too_many_reference_notes")
        for note in notes:
            content = _validate_text(
                note.get("content"), policy["max_note_chars"], "reference_note"
            )
            inputs.append(
                {
                    "content": content,
                    "kind": "reference_note",
                    "provenance": note.get("path"),
                    "sha256": note.get("sha256"),
                    "trust": "untrusted",
                }
            )
            text_chars += len(content)
        if not isinstance(target, dict):
            raise ValueError("input boundary rejected: target_document:missing")
        target_content = _validate_text(
            target.get("content"), policy["max_target_chars"], "target_document"
        )
        inputs.append(
            {
                "content": target_content,
                "kind": "target_document",
                "provenance": target.get("path"),
                "sha256": target.get("sha256"),
                "trust": "untrusted",
            }
        )
        text_chars += len(target_content)

        if image is None and policy["require_image"]:
            raise ValueError("input boundary rejected: image:missing")
        if image is not None:
            media_type = image.get("media_type")
            size_bytes = image.get("size_bytes")
            if media_type not in policy["allowed_image_media_types"]:
                raise ValueError("input boundary rejected: image:unsupported_media_type")
            if not isinstance(size_bytes, int) or size_bytes > policy["max_image_bytes"]:
                raise ValueError("input boundary rejected: image:too_large")
            inputs.append(
                {
                    "kind": "image",
                    "media_type": media_type,
                    "provenance": image.get("path"),
                    "sha256": image.get("sha256"),
                    "size_bytes": size_bytes,
                    "trust": "untrusted",
                }
            )
    elif notes or target is not None or image is not None:
        raise ValueError("input boundary follow-up turns cannot resend first-turn fixtures")

    if text_chars > policy["max_total_text_chars"]:
        raise ValueError("input boundary rejected: total_text:too_long")
    envelope = {
        "inputs": inputs,
        "schema": "input-envelope-v1",
        "task_id": policy["task_id"],
        "turn": turn,
    }
    serialized = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return serialized, {
        "decision": "allow",
        "reason_code": "input_contract_valid",
        "serialized_sha256": hashlib.sha256(serialized.encode()).hexdigest(),
        "source_count": len(inputs),
        "text_chars": text_chars,
        "turn": turn,
    }


def input_boundary_evidence_fingerprint(
    raw_evidence: object, messages: list[dict[str, Any]]
) -> dict[str, Any] | None:
    """Validate recorded admission evidence against the actual user messages."""
    if raw_evidence is None:
        return None
    if not isinstance(raw_evidence, dict) or set(raw_evidence) != {"policy", "decisions"}:
        raise ValueError("input boundary evidence is malformed")
    policy = validate_input_boundary(raw_evidence["policy"])
    decisions = raw_evidence["decisions"]
    user_contents = [
        message.get("content") for message in messages if message.get("role") == "user"
    ]
    if not isinstance(decisions, list) or len(decisions) != len(user_contents):
        raise ValueError("input boundary evidence decision count changed")
    for index, (decision, content) in enumerate(
        zip(decisions, user_contents, strict=True), start=1
    ):
        if not isinstance(decision, dict) or decision.get("turn") != index:
            raise ValueError("input boundary evidence turn order changed")
        if (
            decision.get("decision") != "allow"
            or decision.get("reason_code") != "input_contract_valid"
        ):
            raise ValueError("input boundary evidence decision changed")
        if not isinstance(content, str) or hashlib.sha256(
            content.encode()
        ).hexdigest() != decision.get("serialized_sha256"):
            raise ValueError("input boundary serialized message hash changed")
    return {"policy": policy, "decisions": deepcopy(decisions)}
