from __future__ import annotations
import re
from typing import Any

PRIMITIVE_MAP: dict[str, str] = {
    # Python/Pydantic
    "str": "string",
    "constr": "string",
    "emailstr": "string",
    "uuid": "string",
    "uuid1": "string",
    "uuid4": "string",
    "secretstr": "string",
    "date": "string",
    "datetime": "string",
    "time": "string",
    "pathlib.path": "string",
    "path": "string",
    "int": "number",
    "float": "number",
    "decimal": "number",
    "positiveint": "number",
    "nonnegativeint": "number",
    "negativeint": "number",
    "nonpositiveint": "number",
    "conint": "number",
    "confloat": "number",
    "bool": "boolean",
    "none": "null",
    "nonetype": "null",
    "any": "any",
    # TypeScript
    "string": "string",
    "number": "number",
    "boolean": "boolean",
    "null": "null",
    "undefined": "null",
    "unknown": "any",
    "void": "null",
}


def map_py_to_ts(py_type: str) -> str:
    """Provide a friendly TypeScript type suggestion for a Python/Pydantic type."""
    cleaned = py_type.strip()
    if cleaned in ("str", "EmailStr", "UUID", "date", "datetime"):
        return "string"
    if cleaned in ("int", "float", "Decimal", "PositiveInt"):
        return "number"
    if cleaned == "bool":
        return "boolean"
    if cleaned.startswith(("list[", "List[", "Sequence[", "set[")):
        inner = re.sub(r"^(?:list|List|Sequence|set)\[(.*)\]$", r"\1", cleaned)
        return f"{map_py_to_ts(inner)}[]"
    if cleaned.startswith("Optional["):
        inner = re.sub(r"^Optional\[(.*)\]$", r"\1", cleaned)
        return f"{map_py_to_ts(inner)} | undefined"
    if " | None" in cleaned:
        inner = cleaned.replace(" | None", "").strip()
        return f"{map_py_to_ts(inner)} | undefined"
    return cleaned


def parse_type_info(raw: str) -> dict[str, Any]:
    """Parse a type string into structured kind, nullability, and inner components."""
    t = raw.strip()
    # Normalize union syntax
    if " | " in t:
        parts = [p.strip() for p in t.split("|")]
        has_null = any(p.lower() in ("none", "nonetype", "null", "undefined") for p in parts)
        real_parts = [p for p in parts if p.lower() not in ("none", "nonetype", "null", "undefined")]
        if len(real_parts) == 1:
            info = parse_type_info(real_parts[0])
            info["nullable"] = True
            return info
        return {
            "kind": "union",
            "parts": [parse_type_info(p) for p in real_parts],
            "nullable": has_null,
            "raw": t,
        }

    # Python Optional[...]
    if t.startswith("Optional[") and t.endswith("]"):
        inner = t[9:-1].strip()
        info = parse_type_info(inner)
        info["nullable"] = True
        return info

    # Python Union[...]
    if t.startswith("Union[") and t.endswith("]"):
        inner = t[6:-1].strip()
        parts = [p.strip() for p in inner.split(",")]
        has_null = any(p.lower() in ("none", "nonetype", "null", "undefined") for p in parts)
        real_parts = [p for p in parts if p.lower() not in ("none", "nonetype", "null", "undefined")]
        if len(real_parts) == 1:
            info = parse_type_info(real_parts[0])
            info["nullable"] = True
            return info
        return {
            "kind": "union",
            "parts": [parse_type_info(p) for p in real_parts],
            "nullable": has_null,
            "raw": t,
        }

    # Array types: TS T[] or Array<T>, Python list[T], List[T]
    if t.endswith("[]"):
        inner = t[:-2].strip()
        return {"kind": "array", "inner": parse_type_info(inner), "nullable": False, "raw": t}
    if (t.startswith("Array<") and t.endswith(">")) or (t.startswith("ReadonlyArray<") and t.endswith(">")):
        idx = t.index("<")
        inner = t[idx + 1:-1].strip()
        return {"kind": "array", "inner": parse_type_info(inner), "nullable": False, "raw": t}
    if re.match(r"^(?:list|List|Sequence|set|Set|tuple)\[", t) and t.endswith("]"):
        idx = t.index("[")
        inner = t[idx + 1:-1].split(",")[0].strip()
        return {"kind": "array", "inner": parse_type_info(inner), "nullable": False, "raw": t}

    # Dict / Record types
    if (t.startswith("Record<") and t.endswith(">")) or (re.match(r"^(?:dict|Dict)\[", t) and t.endswith("]")):
        return {"kind": "dict", "nullable": False, "raw": t}

    # Python Literal[...]
    if (t.startswith("Literal[") or t.startswith("typing.Literal[")) and t.endswith("]"):
        idx = t.index("[")
        inner = t[idx + 1:-1].strip()
        parts = [p.strip() for p in inner.split(",")]
        parsed_parts = [parse_type_info(p) for p in parts]
        if len(parsed_parts) == 1:
            return parsed_parts[0]
        return {
            "kind": "union",
            "parts": parsed_parts,
            "nullable": any(p.get("nullable") for p in parsed_parts),
            "raw": t,
        }

    # String literal (e.g. 'scheduled', "completed")
    if (t.startswith("'") and t.endswith("'") and len(t) >= 2) or (t.startswith('"') and t.endswith('"') and len(t) >= 2):
        return {
            "kind": "literal",
            "literal_type": "string",
            "value": t[1:-1],
            "canonical": "string",
            "nullable": False,
            "raw": t,
        }

    # Number literal (e.g. 1, 42, 3.14)
    if re.match(r"^-?\d+(?:\.\d+)?$", t):
        return {
            "kind": "literal",
            "literal_type": "number",
            "value": float(t) if "." in t else int(t),
            "canonical": "number",
            "nullable": False,
            "raw": t,
        }

    # Primitives
    lower = t.lower()
    if lower in PRIMITIVE_MAP:
        canonical = PRIMITIVE_MAP[lower]
        return {
            "kind": "any" if canonical == "any" else "primitive",
            "canonical": canonical,
            "nullable": canonical == "null",
            "raw": t,
        }

    # Model / Complex type reference
    return {
        "kind": "model",
        "name": t,
        "nullable": False,
        "raw": t,
    }


def are_types_compatible(fe_type: str, be_type: str) -> tuple[bool, str | None]:
    """Check if a TypeScript frontend type is compatible with a Python/Pydantic backend type."""
    fe = parse_type_info(fe_type)
    be = parse_type_info(be_type)

    # Any / Unknown is compatible with anything
    if fe.get("kind") == "any" or be.get("kind") == "any":
        return True, None

    # Union types
    if fe.get("kind") == "union":
        # Every part of frontend union must be compatible with backend
        for part in fe.get("parts", []):
            compat, err = are_types_compatible(part["raw"], be_type)
            if not compat:
                return False, f"Part '{part['raw']}' of frontend union '{fe_type}' is not compatible with backend '{be_type}': {err}"
        return True, None

    if be.get("kind") == "union":
        # Frontend type must be compatible with at least one variant of backend union
        for part in be.get("parts", []):
            compat, _ = are_types_compatible(fe_type, part["raw"])
            if compat:
                return True, None
        return False, f"Frontend type '{fe_type}' is not compatible with any variant of backend union '{be_type}'"

    # Array check
    if fe.get("kind") == "array" or be.get("kind") == "array":
        if fe.get("kind") != be.get("kind"):
            return False, f"Frontend type '{fe_type}' is not an array like backend '{be_type}'"
        return are_types_compatible(fe["inner"]["raw"], be["inner"]["raw"])

    # Dict check
    if fe.get("kind") == "dict" or be.get("kind") == "dict":
        if fe.get("kind") != be.get("kind"):
            return False, f"Frontend type '{fe_type}' is not a dict/object like backend '{be_type}'"
        return True, None

    # Literal checks
    if fe.get("kind") == "literal" and be.get("kind") == "literal":
        if fe.get("value") == be.get("value"):
            return True, None
        return False, f"Literal value mismatch: frontend '{fe['raw']}' vs backend '{be['raw']}'"

    if fe.get("kind") == "literal" and be.get("kind") == "primitive":
        if fe.get("canonical") == be.get("canonical"):
            return True, None
        return False, f"Frontend literal '{fe['raw']}' ({fe['canonical']}) is not compatible with backend primitive '{be_type}' ({be['canonical']})"

    if fe.get("kind") == "primitive" and be.get("kind") == "literal":
        if fe.get("canonical") == be.get("canonical"):
            return True, None
        return False, f"Frontend primitive '{fe_type}' ({fe['canonical']}) is not compatible with backend literal '{be['raw']}' ({be['canonical']})"

    # Primitive check
    if fe.get("kind") == "primitive" and be.get("kind") == "primitive":
        if fe.get("canonical") == be.get("canonical"):
            return True, None
        return False, f"Incompatible primitive types: frontend '{fe_type}' ({fe['canonical']}) vs backend '{be_type}' ({be['canonical']})"

    if fe.get("kind") == "primitive" and be.get("kind") == "model":
        return False, f"Frontend expects primitive '{fe_type}' but backend specifies model '{be_type}'"

    if fe.get("kind") == "model" and be.get("kind") == "primitive":
        return False, f"Frontend expects model '{fe_type}' but backend specifies primitive '{be_type}'"

    # Both are models (schema field matching will verify detailed shape)
    return True, None
