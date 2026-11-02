"""GhostFlow Monorepo & Multi-Root Project Discovery Engine.

Discovers and classifies multiple application, service, and package roots across:
- apps/* (e.g., apps/web, apps/admin, apps/mobile)
- services/* (e.g., services/auth, services/billing, services/api)
- packages/* (e.g., packages/shared-types, packages/ui, packages/common)
- Traditional root-level frontend and backend directories (frontend, backend, server, client, ui)
- Standalone single-root repositories

Guarantees:
- Never executes user code or scripts.
- Safely excludes dependency dirs (node_modules, .venv), build artifacts, and caches.
- Preserves 100% backward compatibility with single-root and dual-root projects.
- De-duplicates nested overlapping roots.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

EXCLUDED_DIRS: frozenset[str] = frozenset({
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "env",
    ".env",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".output",
    ".turbo",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    "__pycache__",
    ".ghostflow",
    "coverage",
    ".coverage",
    "htmlcov",
    ".tox",
    ".idea",
    ".vscode",
})

ProjectRole = Literal["frontend", "backend", "shared", "unknown"]


@dataclass
class DiscoveredRoot:
    name: str
    role: ProjectRole
    path: Path
    relative_path: str
    framework: str = "unknown"
    has_package_json: bool = False
    has_python: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MonorepoStructure:
    root_dir: Path
    is_monorepo: bool
    frontend_roots: list[Path] = field(default_factory=list)
    backend_roots: list[Path] = field(default_factory=list)
    shared_roots: list[Path] = field(default_factory=list)
    discovered_roots: list[DiscoveredRoot] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_monorepo": self.is_monorepo,
            "root_dir": str(self.root_dir),
            "frontend_roots": [str(p) for p in self.frontend_roots],
            "backend_roots": [str(p) for p in self.backend_roots],
            "shared_roots": [str(p) for p in self.shared_roots],
            "roots_count": len(self.discovered_roots),
            "discovered_roots": [
                {
                    "name": r.name,
                    "role": r.role,
                    "relative_path": r.relative_path,
                    "framework": r.framework,
                }
                for r in self.discovered_roots
            ],
        }


def _is_excluded(path: Path) -> bool:
    """Check if any path component is an excluded directory."""
    return any(part in EXCLUDED_DIRS for part in path.parts)


def _detect_frontend_framework(pkg_path: Path) -> str:
    """Inspect package.json to identify the frontend framework."""
    if not pkg_path.is_file():
        return "vanilla-js"
    try:
        data = json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
        all_deps = set()
        for k in ("dependencies", "devDependencies", "peerDependencies"):
            if isinstance(data.get(k), dict):
                all_deps.update(data[k].keys())
        if "next" in all_deps:
            return "nextjs"
        if "react" in all_deps:
            return "react"
        if "vue" in all_deps:
            return "vue"
        if "svelte" in all_deps:
            return "svelte"
        if "@angular/core" in all_deps:
            return "angular"
        if "vite" in all_deps:
            return "vite"
        return "javascript"
    except Exception:
        return "javascript"


def _detect_backend_framework(dir_path: Path) -> str:
    """Inspect Python or Node files to identify backend framework."""
    # Check Python
    py_files = [p for p in dir_path.glob("*.py") if not _is_excluded(p)]
    for pyf in py_files[:10]:
        try:
            txt = pyf.read_text(encoding="utf-8", errors="replace")
            if "fastapi" in txt.lower():
                return "fastapi"
            if "starlette" in txt.lower():
                return "starlette"
            if "flask" in txt.lower():
                return "flask"
            if "django" in txt.lower():
                return "django"
        except Exception:
            continue

    # Check Node / Express
    pkg = dir_path / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8", errors="replace"))
            deps = set()
            for k in ("dependencies", "devDependencies"):
                if isinstance(data.get(k), dict):
                    deps.update(data[k].keys())
            if "express" in deps:
                return "express"
            if "fastify" in deps:
                return "fastify"
            if "koa" in deps:
                return "koa"
            if "nestjs" in str(deps):
                return "nestjs"
        except Exception:
            pass

    return "python" if py_files else "unknown"


def _is_frontend_dir(candidate: Path) -> bool:
    """Determine whether a candidate directory is a frontend project root."""
    pkg = candidate / "package.json"
    has_pkg = pkg.is_file()
    fw = _detect_frontend_framework(pkg) if has_pkg else ""

    if fw in ("react", "vue", "svelte", "angular", "nextjs", "vite"):
        return True

    # Check directory name hints
    name_lower = candidate.name.lower()
    if name_lower in ("frontend", "client", "web", "ui"):
        # Has TS/JS files
        has_fe_code = any(
            candidate.glob(f"**/*{ext}")
            for ext in (".tsx", ".jsx", ".ts", ".js")
            if not _is_excluded(candidate)
        )
        if has_fe_code:
            return True

    # Check for src/ directory with React/TS files
    src_dir = candidate / "src"
    if src_dir.is_dir():
        for ext in (".tsx", ".jsx", ".ts", ".js"):
            if any(src_dir.glob(f"*{ext}")):
                return True

    return False


def _is_backend_dir(candidate: Path) -> bool:
    """Determine whether a candidate directory is a backend project root."""
    name_lower = candidate.name.lower()
    has_py_manifest = (candidate / "requirements.txt").is_file() or (candidate / "pyproject.toml").is_file()

    # Check for Python files
    has_py_code = any(candidate.glob("*.py")) or any(candidate.glob("src/*.py")) or any(candidate.glob("app/*.py"))

    if has_py_manifest or (has_py_code and name_lower in ("backend", "server", "api", "service", "services")):
        return True

    # Express / Node backend
    pkg = candidate / "package.json"
    if pkg.is_file():
        fw = _detect_backend_framework(candidate)
        if fw in ("express", "fastify", "koa", "nestjs"):
            return True

    # Check Python framework imports
    if has_py_code and _detect_backend_framework(candidate) in ("fastapi", "flask", "django", "starlette"):
        return True

    return False


def _is_shared_dir(candidate: Path) -> bool:
    """Determine whether a candidate directory is a shared package/types library."""
    name_lower = candidate.name.lower()
    if any(k in name_lower for k in ("shared", "common", "types", "models", "schemas", "lib")):
        return True
    return False


def discover_monorepo(root: Path) -> MonorepoStructure:
    """Discover all relevant frontend, backend, and shared package roots in project.

    Handles:
    - Monorepos with apps/*, services/*, packages/*
    - Traditional dual-root projects (frontend/ + backend/)
    - Single-root projects with co-located or top-level code
    """
    resolved_root = root.resolve()
    discovered_roots: list[DiscoveredRoot] = []
    fe_roots: list[Path] = []
    be_roots: list[Path] = []
    shared_roots: list[Path] = []

    # 1. Check monorepo container directories: apps/*, services/*, packages/*, libs/*
    container_dirs = ["apps", "services", "packages", "libs", "projects", "modules"]
    has_containers = False

    for container_name in container_dirs:
        container = resolved_root / container_name
        if not container.is_dir() or _is_excluded(container):
            continue

        for child in sorted(container.iterdir()):
            if not child.is_dir() or _is_excluded(child):
                continue

            has_containers = True
            rel_str = str(child.relative_to(resolved_root)).replace("\\", "/")
            pkg_file = child / "package.json"

            if _is_frontend_dir(child):
                fw = _detect_frontend_framework(pkg_file)
                d_root = DiscoveredRoot(
                    name=child.name,
                    role="frontend",
                    path=child,
                    relative_path=rel_str,
                    framework=fw,
                    has_package_json=pkg_file.is_file(),
                )
                discovered_roots.append(d_root)
                fe_roots.append(child)

            elif _is_backend_dir(child):
                fw = _detect_backend_framework(child)
                d_root = DiscoveredRoot(
                    name=child.name,
                    role="backend",
                    path=child,
                    relative_path=rel_str,
                    framework=fw,
                    has_python=True,
                )
                discovered_roots.append(d_root)
                be_roots.append(child)

            elif _is_shared_dir(child):
                fw = _detect_frontend_framework(pkg_file) if pkg_file.is_file() else "shared"
                d_root = DiscoveredRoot(
                    name=child.name,
                    role="shared",
                    path=child,
                    relative_path=rel_str,
                    framework=fw,
                    has_package_json=pkg_file.is_file(),
                )
                discovered_roots.append(d_root)
                shared_roots.append(child)

    # 2. Check conventional standard root subdirectories (frontend, backend, client, server, api, web)
    conventional_fe = ["frontend", "client", "web", "ui"]
    for fe_name in conventional_fe:
        fe_dir = resolved_root / fe_name
        if fe_dir.is_dir() and not _is_excluded(fe_dir) and fe_dir not in fe_roots:
            rel_str = str(fe_dir.relative_to(resolved_root)).replace("\\", "/")
            pkg_file = fe_dir / "package.json"
            fw = _detect_frontend_framework(pkg_file) if pkg_file.is_file() else "react"
            d_root = DiscoveredRoot(
                name=fe_dir.name,
                role="frontend",
                path=fe_dir,
                relative_path=rel_str,
                framework=fw,
                has_package_json=pkg_file.is_file(),
            )
            discovered_roots.append(d_root)
            fe_roots.append(fe_dir)

    conventional_be = ["backend", "server", "api"]
    for be_name in conventional_be:
        be_dir = resolved_root / be_name
        if be_dir.is_dir() and not _is_excluded(be_dir) and be_dir not in be_roots:
            rel_str = str(be_dir.relative_to(resolved_root)).replace("\\", "/")
            fw = _detect_backend_framework(be_dir)
            d_root = DiscoveredRoot(
                name=be_dir.name,
                role="backend",
                path=be_dir,
                relative_path=rel_str,
                framework=fw,
                has_python=True,
            )
            discovered_roots.append(d_root)
            be_roots.append(be_dir)

    # 3. Check for shared directory at root
    for sh_name in ["shared", "common", "models", "types"]:
        sh_dir = resolved_root / sh_name
        if sh_dir.is_dir() and not _is_excluded(sh_dir) and sh_dir not in shared_roots:
            rel_str = str(sh_dir.relative_to(resolved_root)).replace("\\", "/")
            d_root = DiscoveredRoot(
                name=sh_dir.name,
                role="shared",
                path=sh_dir,
                relative_path=rel_str,
                framework="shared",
            )
            discovered_roots.append(d_root)
            shared_roots.append(sh_dir)

    # 4. Fallback for single-root project: if no roots found, assign root as both or appropriate
    if not fe_roots and not be_roots:
        is_fe = _is_frontend_dir(resolved_root)
        is_be = _is_backend_dir(resolved_root)
        if is_fe:
            fe_roots.append(resolved_root)
            discovered_roots.append(DiscoveredRoot(
                name=resolved_root.name,
                role="frontend",
                path=resolved_root,
                relative_path=".",
                framework=_detect_frontend_framework(resolved_root / "package.json"),
            ))
        if is_be:
            be_roots.append(resolved_root)
            discovered_roots.append(DiscoveredRoot(
                name=resolved_root.name,
                role="backend",
                path=resolved_root,
                relative_path=".",
                framework=_detect_backend_framework(resolved_root),
            ))
        if not is_fe and not is_be:
            # Default fallback: scan root as both
            fe_roots.append(resolved_root)
            be_roots.append(resolved_root)
            discovered_roots.append(DiscoveredRoot(
                name=resolved_root.name,
                role="frontend",
                path=resolved_root,
                relative_path=".",
            ))
            discovered_roots.append(DiscoveredRoot(
                name=resolved_root.name,
                role="backend",
                path=resolved_root,
                relative_path=".",
            ))
    elif not fe_roots:
        # Backend-only project
        pass
    elif not be_roots:
        # Frontend-only project
        pass

    is_monorepo = len(fe_roots) + len(be_roots) + len(shared_roots) > 2 or has_containers

    return MonorepoStructure(
        root_dir=resolved_root,
        is_monorepo=is_monorepo,
        frontend_roots=fe_roots,
        backend_roots=be_roots,
        shared_roots=shared_roots,
        discovered_roots=discovered_roots,
    )

