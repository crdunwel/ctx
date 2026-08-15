from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Iterator

import yaml

from .diagnostics import CtxError


MAX_MANIFEST_BYTES = 1_048_576
MAX_YAML_DEPTH = 64
MAX_YAML_NODES = 20_000


class ManifestYamlError(CtxError):
    def __init__(self, message: str) -> None:
        super().__init__("manifest.yaml-invalid", message, exit_code=1)


class UniqueKeySafeLoader(yaml.SafeLoader):
    pass


def _construct_mapping(
    loader: UniqueKeySafeLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        if isinstance(key_node, yaml.nodes.ScalarNode) and key_node.value == "<<":
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "YAML merge keys are not allowed in context manifests",
                key_node.start_mark,
            )
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "mapping keys must be scalar values",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def _reject_aliases(raw_text: str) -> None:
    depth = 0
    try:
        for event in yaml.parse(raw_text, Loader=UniqueKeySafeLoader):
            if isinstance(event, yaml.events.AliasEvent):
                raise ManifestYamlError("YAML aliases are not allowed in context manifests")
            if isinstance(
                event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)
            ):
                depth += 1
                if depth > MAX_YAML_DEPTH:
                    raise ManifestYamlError("manifest YAML nesting is too deep")
            elif isinstance(
                event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)
            ):
                depth -= 1
    except ManifestYamlError:
        raise
    except (yaml.YAMLError, RecursionError) as exc:
        raise ManifestYamlError(str(exc)) from exc


def _check_shape_limits(value: Any) -> None:
    count = 0
    active: set[int] = set()

    def visit(current: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > MAX_YAML_NODES:
            raise ManifestYamlError("manifest contains too many YAML values")
        if depth > MAX_YAML_DEPTH:
            raise ManifestYamlError("manifest YAML nesting is too deep")
        if isinstance(current, (dict, list)):
            identity = id(current)
            if identity in active:
                raise ManifestYamlError("recursive YAML values are not allowed")
            active.add(identity)
            values: Iterator[Any]
            if isinstance(current, dict):
                values = iter((*current.keys(), *current.values()))
            else:
                values = iter(current)
            for child in values:
                visit(child, depth + 1)
            active.remove(identity)

    visit(value, 0)


def load_yaml(path: Path) -> tuple[str, Any]:
    try:
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise CtxError(
            "manifest.read-failed", f"cannot read manifest {path}: {exc}", exit_code=4
        ) from exc
    if len(raw_bytes) > MAX_MANIFEST_BYTES:
        raise ManifestYamlError(
            f"manifest exceeds the {MAX_MANIFEST_BYTES}-byte safety limit"
        )
    try:
        raw_text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ManifestYamlError("manifest must be valid UTF-8") from exc
    if "\x00" in raw_text:
        raise ManifestYamlError("manifest contains a NUL byte")
    _reject_aliases(raw_text)
    try:
        value = yaml.load(raw_text, Loader=UniqueKeySafeLoader)
    except (yaml.YAMLError, RecursionError) as exc:
        raise ManifestYamlError(str(exc)) from exc
    _check_shape_limits(value)
    return raw_text, value


def dump_yaml(value: dict[str, Any]) -> str:
    return yaml.safe_dump(
        value,
        allow_unicode=True,
        default_flow_style=False,
        sort_keys=False,
        width=88,
    )


def create_text_atomic(path: Path, text: str) -> None:
    """Publish a new file without ever replacing an existing one."""
    created_parent = False
    if not path.parent.exists():
        try:
            path.parent.mkdir(mode=0o755)
            created_parent = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise CtxError(
                "manifest.create-failed",
                f"cannot create manifest directory {path.parent}: {exc}",
                exit_code=4,
            ) from exc
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent, prefix=".context.yaml.", suffix=".tmp"
        )
        temporary = Path(temporary_name)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise CtxError(
                "manifest.exists",
                f"manifest already exists and was not replaced: {path}",
                exit_code=1,
            )
        except OSError as exc:
            raise CtxError(
                "manifest.create-failed", f"cannot create manifest {path}: {exc}", exit_code=4
            ) from exc
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        if created_parent:
            try:
                path.parent.rmdir()
            except OSError:
                pass
