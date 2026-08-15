from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from .diagnostics import CtxError


ID_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_ID_LENGTH = 128


def is_valid_id(value: str) -> bool:
    return (
        0 < len(value) <= MAX_ID_LENGTH
        and value not in {".", ".."}
        and ID_PATTERN.fullmatch(value) is not None
    )


def require_id(value: str, label: str = "ID") -> str:
    if not is_valid_id(value):
        raise CtxError(
            "identity.invalid",
            f"{label} must use lowercase letters, digits, and single hyphens only",
            exit_code=1,
        )
    return value


@dataclass(frozen=True, slots=True)
class ContextUri:
    project_id: str
    node_ids: tuple[str, ...] = ()
    item_id: str | None = None

    def __post_init__(self) -> None:
        if not is_valid_id(self.project_id):
            raise CtxError("uri.invalid", f"invalid project ID: {self.project_id}", exit_code=1)
        if any(not is_valid_id(value) for value in self.node_ids):
            raise CtxError("uri.invalid", "invalid node ID in context URI", exit_code=1)
        if self.item_id is not None and not is_valid_id(self.item_id):
            raise CtxError("uri.invalid", f"invalid item ID: {self.item_id}", exit_code=1)

    def __str__(self) -> str:
        path = "" if not self.node_ids else "/" + "/".join(self.node_ids)
        fragment = "" if self.item_id is None else f"#{self.item_id}"
        return f"ctx://{self.project_id}{path}{fragment}"


def parse_ctx_uri(reference: str) -> ContextUri:
    if any(ord(character) < 32 or ord(character) == 127 for character in reference):
        raise CtxError(
            "uri.invalid", "context URI cannot contain control characters", exit_code=1
        )
    candidate = reference.strip()
    if candidate != reference:
        raise CtxError(
            "uri.invalid", "context URI cannot contain surrounding whitespace", exit_code=1
        )
    if candidate.count("#") > 1 or ("#" in candidate and candidate.endswith("#")):
        raise CtxError("uri.invalid", f"invalid context URI: {reference}", exit_code=1)
    try:
        parsed = urlsplit(candidate)
    except ValueError as exc:
        raise CtxError("uri.invalid", f"invalid context URI: {reference}", exit_code=1) from exc
    if parsed.scheme != "ctx" or not parsed.netloc:
        raise CtxError("uri.invalid", f"invalid context URI: {reference}", exit_code=1)
    if parsed.query or parsed.username is not None or parsed.password is not None:
        raise CtxError("uri.invalid", f"invalid context URI: {reference}", exit_code=1)
    try:
        if parsed.port is not None:
            raise CtxError("uri.invalid", f"invalid context URI: {reference}", exit_code=1)
        hostname = parsed.hostname
    except ValueError as exc:
        raise CtxError("uri.invalid", f"invalid context URI: {reference}", exit_code=1) from exc
    if hostname != parsed.netloc or not is_valid_id(parsed.netloc):
        raise CtxError("uri.invalid", f"invalid project ID in context URI: {reference}", exit_code=1)
    if parsed.path.endswith("/") or "//" in parsed.path:
        raise CtxError("uri.invalid", f"invalid node path in context URI: {reference}", exit_code=1)
    node_ids = tuple(segment for segment in parsed.path.split("/") if segment)
    if any(not is_valid_id(segment) for segment in node_ids):
        raise CtxError("uri.invalid", f"invalid node ID in context URI: {reference}", exit_code=1)
    item_id = parsed.fragment or None
    if item_id is not None and not is_valid_id(item_id):
        raise CtxError("uri.invalid", f"invalid item ID in context URI: {reference}", exit_code=1)
    return ContextUri(parsed.netloc, node_ids, item_id)


def node_uri(project_id: str, semantic_ids: tuple[str, ...]) -> str:
    return str(ContextUri(project_id, semantic_ids))


def item_uri(node_reference: str, item_id: str) -> str:
    require_id(item_id, "item ID")
    if "#" in node_reference:
        raise CtxError("uri.invalid", "node URI already has an item fragment", exit_code=1)
    return f"{node_reference}#{item_id}"
