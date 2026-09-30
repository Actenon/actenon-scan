"""Strict value checking shared by every AREF-002 M0 type.

Nothing here coerces loosely. A value is accepted only when it already has the
exact expected type, or, for closed vocabularies, when it is the exact wire
string of a member. There are no defaults for missing required data: a missing
proof state is an error, never ``UNKNOWN`` and never ``REFUTED``.
"""

from __future__ import annotations

import re
from enum import Enum
from types import MappingProxyType
from typing import Any, Iterable, Mapping, TypeVar

E = TypeVar("E", bound=Enum)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#-]*$")
_IDENTIFIER_MAX = 200


class EffectModelError(ValueError):
    """An AREF-002 object violates the frozen data model."""


def fail(where: str, message: str) -> EffectModelError:
    return EffectModelError(f"{where}: {message}")


def enum_value(cls: type[E], value: Any, where: str) -> E:
    if isinstance(value, cls):
        return value
    if type(value) is str:
        try:
            return cls(value)
        except ValueError:
            pass
        raise fail(where, f"{value!r} is not a member of {cls.__name__}")
    raise fail(where, f"expected {cls.__name__}, got {type(value).__name__}")


def optional_enum(cls: type[E], value: Any, where: str) -> E | None:
    return None if value is None else enum_value(cls, value, where)


def integer(value: Any, where: str, minimum: int = 0) -> int:
    if type(value) is not int:
        raise fail(where, f"expected an integer, got {type(value).__name__}")
    if value < minimum:
        raise fail(where, f"must be >= {minimum}, got {value}")
    return value


def optional_integer(value: Any, where: str, minimum: int = 0) -> int | None:
    return None if value is None else integer(value, where, minimum)


def number(value: Any, where: str, minimum: float, maximum: float) -> float | int:
    if type(value) not in (int, float):
        raise fail(where, f"expected a number, got {type(value).__name__}")
    if not minimum <= value <= maximum:
        raise fail(where, f"must be within [{minimum}, {maximum}], got {value}")
    return value


def boolean(value: Any, where: str) -> bool:
    if type(value) is not bool:
        raise fail(where, f"expected a boolean, got {type(value).__name__}")
    return value


def optional_boolean(value: Any, where: str) -> bool | None:
    return None if value is None else boolean(value, where)


def text(value: Any, where: str, *, min_length: int = 1) -> str:
    if type(value) is not str:
        raise fail(where, f"expected a string, got {type(value).__name__}")
    if len(value) < min_length:
        raise fail(where, "must not be empty")
    return value


def optional_text(value: Any, where: str, *, min_length: int = 0) -> str | None:
    return None if value is None else text(value, where, min_length=min_length)


def identifier(value: Any, where: str) -> str:
    value = text(value, where)
    if len(value) > _IDENTIFIER_MAX or not _IDENTIFIER.match(value):
        raise fail(where, f"{value!r} is not a legal identifier")
    return value


def optional_identifier(value: Any, where: str) -> str | None:
    return None if value is None else identifier(value, where)


def sequence(value: Any, where: str) -> tuple:
    if isinstance(value, (str, bytes, Mapping)) or not isinstance(value, Iterable):
        raise fail(where, f"expected a sequence, got {type(value).__name__}")
    return tuple(value)


def unique(items: tuple, where: str, key=lambda item: item) -> tuple:
    seen = set()
    for item in items:
        k = key(item)
        if k in seen:
            raise fail(where, f"duplicate entry {k!r}")
        seen.add(k)
    return items


def enum_tuple(cls: type[E], value: Any, where: str) -> tuple[E, ...]:
    items = tuple(
        enum_value(cls, item, f"{where}[{i}]")
        for i, item in enumerate(sequence(value, where))
    )
    return unique(items, where)


def typed_tuple(cls: type, value: Any, where: str) -> tuple:
    items = sequence(value, where)
    for i, item in enumerate(items):
        if not isinstance(item, cls):
            raise fail(f"{where}[{i}]", f"expected {cls.__name__}, got {type(item).__name__}")
    return items


def instance(cls: type, value: Any, where: str):
    if not isinstance(value, cls):
        raise fail(where, f"expected {cls.__name__}, got {type(value).__name__}")
    return value


def optional_instance(cls: type, value: Any, where: str):
    return None if value is None else instance(cls, value, where)


def frozen_counts(value: Any, where: str, key_check) -> Mapping:
    """An immutable ``key -> non-negative int`` map with checked keys."""
    if not isinstance(value, Mapping):
        raise fail(where, f"expected a mapping, got {type(value).__name__}")
    out = {}
    for raw_key, count in value.items():
        k = key_check(raw_key, f"{where} key")
        if k in out:
            raise fail(where, f"duplicate key {k!r}")
        out[k] = integer(count, f"{where}[{raw_key!r}]")
    return MappingProxyType(out)


def counts_to_dict(counts: Mapping, order: Iterable | None = None) -> dict:
    if order is None:
        return {_wire(k): v for k, v in sorted(counts.items(), key=lambda kv: _wire(kv[0]))}
    return {_wire(k): counts[k] for k in order if k in counts}


def _wire(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


class Reader:
    """Reads one JSON object, rejecting unknown and missing keys."""

    def __init__(self, data: Any, where: str, required: Iterable[str], optional: Iterable[str] = ()):
        if not isinstance(data, Mapping):
            raise fail(where, f"expected an object, got {type(data).__name__}")
        required = tuple(required)
        allowed = set(required) | set(optional)
        unknown = sorted(k for k in data if k not in allowed)
        if unknown:
            raise fail(where, f"unknown key(s) {unknown}")
        missing = [k for k in required if k not in data]
        if missing:
            raise fail(where, f"missing required key(s) {missing}")
        self._data = data
        self.where = where

    def __contains__(self, key: str) -> bool:
        return key in self._data

    def at(self, key: str) -> str:
        return f"{self.where}.{key}"

    def get(self, key: str, default: Any = None) -> Any:
        if key in self._data and self._data[key] is None:
            raise fail(self.at(key), "null is not a legal value")
        return self._data.get(key, default)

    def raw(self, key: str, default: Any = None) -> Any:
        """Like :meth:`get` but allows an explicit JSON null."""
        return self._data.get(key, default)


def put(out: dict, key: str, value: Any) -> None:
    """Emit an optional field only when it carries a value."""
    if value is not None:
        out[key] = value
