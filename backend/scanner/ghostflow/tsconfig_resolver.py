"""GhostFlow TypeScript & JavaScript Path Alias Resolver.

Parses tsconfig.json / jsconfig.json configurations to resolve path aliases (e.g. @/*)
to physical files on disk before reporting missing import diagnostics.

Supports:
- compilerOptions.baseUrl
- compilerOptions.paths with wildcard (*) and exact matches
- extends inheritance across multiple configuration files
- Extensions: .ts, .tsx, .d.ts, .js, .jsx, .mjs, .cjs, .json
- Directory index files: /index.ts, /index.tsx, /index.js, etc.
- Safe comment-tolerant JSON parsing (JSONC)
- Safe fallback when tsconfig is absent or malformed
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_SUPPORTED_EXTENSIONS: tuple[str, ...] = (
    ".ts",
    ".tsx",
    ".d.ts",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".json",
)


@dataclass
class ResolvedPath:
    status: str  # "resolved", "unresolved_alias", "not_an_alias"
    target_path: Path | None = None
    alias_matched: str | None = None
    attempted_candidates: list[str] = field(default_factory=list)


def _strip_json_comments(text: str) -> str:
    """Strip JavaScript single-line and multi-line comments and trailing commas for JSON parsing."""
    # 1. Remove multi-line comments /* ... */
    no_multi = re.sub(r"/\*[\s\S]*?\*/", "", text)
    # 2. Remove single-line comments // ...
    no_comments = re.sub(r"(?<!:)//.*$", "", no_multi, flags=re.MULTILINE)
    # 3. Remove trailing commas before } or ]
    clean = re.sub(r",\s*([\}\]])", r"\1", no_comments)
    return clean


def _load_tsconfig_json(file_path: Path) -> dict[str, Any]:
    """Safely read and parse a tsconfig/jsconfig JSON file."""
    if not file_path.is_file():
        return {}
    try:
        raw = file_path.read_text(encoding="utf-8", errors="replace")
        clean = _strip_json_comments(raw)
        data = json.loads(clean)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


class TsConfigResolver:
    """Resolves TypeScript path aliases for a project root or specific tsconfig."""

    def __init__(self, root: Path, config_file: Path | None = None):
        self.root = root.resolve()
        self.config_file = config_file.resolve() if config_file else self._find_primary_config()
        self.base_url: Path = self.root
        self.paths: dict[str, list[str]] = {}
        self._loaded_files: set[Path] = set()

        if self.config_file and self.config_file.is_file():
            self._load_and_merge_config(self.config_file)

    def _find_primary_config(self) -> Path | None:
        """Locate primary tsconfig.json or jsconfig.json in project or frontend directories."""
        cands = [
            self.root / "tsconfig.json",
            self.root / "tsconfig.app.json",
            self.root / "frontend" / "tsconfig.json",
            self.root / "client" / "tsconfig.json",
            self.root / "web" / "tsconfig.json",
            self.root / "apps" / "web" / "tsconfig.json",
            self.root / "jsconfig.json",
            self.root / "frontend" / "jsconfig.json",
        ]
        for c in cands:
            if c.is_file():
                return c
        return None

    def _load_and_merge_config(self, cfg_path: Path) -> None:
        """Recursively load config and any extended configurations."""
        if cfg_path in self._loaded_files:
            return
        self._loaded_files.add(cfg_path)

        data = _load_tsconfig_json(cfg_path)
        if not data:
            return

        cfg_dir = cfg_path.parent

        # 1. Handle "extends"
        extends_val = data.get("extends")
        if isinstance(extends_val, str):
            parent_cand = (cfg_dir / extends_val).resolve()
            if not parent_cand.is_file() and not extends_val.endswith(".json"):
                parent_cand = (cfg_dir / f"{extends_val}.json").resolve()
            try:
                parent_cand.relative_to(self.root)
                if parent_cand.is_file():
                    self._load_and_merge_config(parent_cand)
            except (ValueError, RuntimeError):
                pass

        # 2. Extract compilerOptions
        opts = data.get("compilerOptions")
        if isinstance(opts, dict):
            # baseUrl
            raw_base = opts.get("baseUrl")
            if isinstance(raw_base, str):
                self.base_url = (cfg_dir / raw_base).resolve()
            elif not hasattr(self, "base_url") or self.base_url == self.root:
                self.base_url = cfg_dir

            # paths
            raw_paths = opts.get("paths")
            if isinstance(raw_paths, dict):
                for alias_pat, target_list in raw_paths.items():
                    if isinstance(target_list, list):
                        self.paths[alias_pat] = [
                            str(t) for t in target_list if isinstance(t, str)
                        ]
                    elif isinstance(target_list, str):
                        self.paths[alias_pat] = [target_list]

    @property
    def has_aliases(self) -> bool:
        return bool(self.paths)

    def resolve_specifier(self, specifier: str, importing_file: Path | None = None) -> ResolvedPath:
        """Resolve an import specifier against configured tsconfig paths.

        Returns:
            ResolvedPath with status "resolved", "unresolved_alias", or "not_an_alias".
        """
        if not self.paths or specifier.startswith("."):
            return ResolvedPath(status="not_an_alias")

        # Normalize specifier
        clean_spec = specifier.strip()

        # Try matching each alias pattern
        for pattern, targets in self.paths.items():
            matched_wildcard: str | None = None
            is_match = False

            if pattern.endswith("/*"):
                prefix = pattern[:-2]  # e.g., "@" from "@/*"
                if clean_spec == prefix or clean_spec.startswith(prefix + "/"):
                    is_match = True
                    matched_wildcard = clean_spec[len(prefix) + 1:] if clean_spec != prefix else ""
            elif pattern == clean_spec:
                is_match = True
                matched_wildcard = None
            elif "*" in pattern:
                # Arbitrary wildcard
                pat_regex = "^" + re.escape(pattern).replace(r"\*", r"(.*)") + "$"
                m = re.match(pat_regex, clean_spec)
                if m:
                    is_match = True
                    matched_wildcard = m.group(1)

            if not is_match:
                continue

            # This specifier is an alias declared in tsconfig.json
            attempted: list[str] = []

            for target_pat in targets:
                if matched_wildcard is not None and "*" in target_pat:
                    expanded_target = target_pat.replace("*", matched_wildcard)
                elif matched_wildcard is not None and not target_pat.endswith("/"):
                    expanded_target = f"{target_pat}/{matched_wildcard}" if matched_wildcard else target_pat
                else:
                    expanded_target = target_pat

                # Candidate path relative to baseUrl
                cand_base = self.base_url / expanded_target
                cand_resolved = self._resolve_file_or_index(cand_base, attempted)
                if cand_resolved and cand_resolved.is_file():
                    try:
                        cand_resolved.relative_to(self.root)
                    except (ValueError, RuntimeError):
                        # Path alias attempts to traverse outside project root
                        continue
                    return ResolvedPath(
                        status="resolved",
                        target_path=cand_resolved,
                        alias_matched=pattern,
                        attempted_candidates=attempted,
                    )

            # Matched a known alias pattern, but target file does not exist
            return ResolvedPath(
                status="unresolved_alias",
                target_path=None,
                alias_matched=pattern,
                attempted_candidates=attempted,
            )

        return ResolvedPath(status="not_an_alias")

    def _resolve_file_or_index(self, target: Path, attempted: list[str]) -> Path | None:
        """Check direct file, extensions, and directory index files."""
        # 1. Exact match
        attempted.append(str(target))
        if target.is_file():
            return target.resolve()

        # 2. Append extensions
        for ext in _SUPPORTED_EXTENSIONS:
            cand = target.with_suffix(ext) if not target.name.endswith(ext) else target
            cand_str = str(target) + ext
            attempted.append(cand_str)
            p_cand = Path(cand_str)
            if p_cand.is_file():
                return p_cand.resolve()

        # 3. Directory index
        if target.is_dir() or (not target.suffix and not target.name.startswith(".")):
            for ext in _SUPPORTED_EXTENSIONS:
                cand_idx = target / f"index{ext}"
                attempted.append(str(cand_idx))
                if cand_idx.is_file():
                    return cand_idx.resolve()

        return None


_RESOLVER_CACHE: dict[Path, TsConfigResolver] = {}


def get_resolver(file_path: Path, root: Path) -> TsConfigResolver:
    """Find and return the most specific TsConfigResolver for a file within root."""
    resolved_file = file_path.resolve()
    resolved_root = root.resolve()

    # Search upwards from file's directory up to root
    cur: Path = resolved_file.parent if resolved_file.is_file() else resolved_file
    while True:
        for cfg_name in ("tsconfig.json", "tsconfig.app.json", "jsconfig.json"):
            cand = cur / cfg_name
            if cand.is_file():
                if cand not in _RESOLVER_CACHE:
                    _RESOLVER_CACHE[cand] = TsConfigResolver(root=cur, config_file=cand)
                return _RESOLVER_CACHE[cand]

        if cur == resolved_root or resolved_root not in cur.parents:
            break
        cur = cur.parent

    # Fallback to root resolver
    if resolved_root not in _RESOLVER_CACHE:
        _RESOLVER_CACHE[resolved_root] = TsConfigResolver(root=resolved_root)
    return _RESOLVER_CACHE[resolved_root]


def clear_resolver_cache() -> None:
    """Clear resolver cache (useful in tests)."""
    _RESOLVER_CACHE.clear()
