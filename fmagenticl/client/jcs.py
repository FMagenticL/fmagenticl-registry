"""Deterministic RFC 8785 (JCS-subset) UTF-8 canonical JSON serializer."""

import json
import math
from typing import Any


def jcs_dumps(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Non-finite float not permitted in canonical JSON")
        if value == 0.0:
            return "0"
        if value.is_integer() and abs(value) < (1 << 53):
            return str(int(value))
        return json.dumps(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(jcs_dumps(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: kv[0])
        return "{" + ",".join(f"{json.dumps(str(k), ensure_ascii=False)}:{jcs_dumps(v)}" for k, v in items) + "}"
    raise TypeError(f"Unsupported type for JCS serialization: {type(value).__name__}")


def jcs_bytes(value: Any) -> bytes:
    return jcs_dumps(value).encode("utf-8")
