"""GhostFlow Database Schema Intelligence & Static Diagnostics.

Detects discrepancies between SQLAlchemy ORM models and Alembic migration files
using pure static Python AST analysis.

Rules:
- DB001: Model / Migration Table Mismatch
- DB002: Missing Column in Model or Migration
- DB003: Column Type Mismatch
- DB004: Nullable / Default Inconsistency
- DB005: Foreign-Key Target Inconsistency
- DB006: Unindexed Foreign Key Column
- DB007: Broken Migration Revision Chain

Guarantees:
- Pure static analysis using Python AST and filesystem traversal.
- Never executes project migration scripts or arbitrary code.
- Never connects to or modifies the scanned project's database.
- Distinguishes confirmed findings from uncertain/heuristic ones.
- Provides precise source-file and line-number evidence.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Evidence, Finding

_EXCLUDED_DIRS: frozenset[str] = frozenset({
    ".venv",
    "venv",
    "node_modules",
    ".git",
    "dist",
    "build",
    ".ghostflow",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "coverage",
    ".coverage",
    "htmlcov",
})

# Type normalization mapping
_TYPE_NORM_MAP: dict[str, str] = {
    "integer": "integer",
    "int": "integer",
    "smallint": "integer",
    "bigint": "integer",
    "biginteger": "integer",
    "string": "string",
    "str": "string",
    "varchar": "string",
    "char": "string",
    "text": "text",
    "boolean": "boolean",
    "bool": "boolean",
    "datetime": "datetime",
    "date": "date",
    "time": "time",
    "timestamp": "datetime",
    "uuid": "uuid",
    "float": "float",
    "real": "float",
    "numeric": "numeric",
    "decimal": "numeric",
    "json": "json",
    "jsonb": "json",
    "bytes": "binary",
    "largebinary": "binary",
    "binary": "binary",
}


def _normalize_sql_type(raw_type: str) -> str:
    """Normalize SQLAlchemy / Alembic column types into canonical categories."""
    clean = raw_type.lower().split("(")[0].strip()
    if clean.startswith("sa."):
        clean = clean[3:]
    return _TYPE_NORM_MAP.get(clean, clean)


@dataclass
class ColumnDef:
    name: str
    type_name: str
    nullable: bool = True
    has_default: bool = False
    is_primary_key: bool = False
    is_unique: bool = False
    is_indexed: bool = False
    foreign_key_target: str | None = None  # e.g. "users.id"
    file_path: str = ""
    line: int = 1
    source_snippet: str = ""


@dataclass
class TableModelDef:
    table_name: str
    model_name: str
    columns: dict[str, ColumnDef] = field(default_factory=dict)
    foreign_keys: list[dict[str, Any]] = field(default_factory=list)
    indexes: list[dict[str, Any]] = field(default_factory=list)
    file_path: str = ""
    line: int = 1
    source_snippet: str = ""


@dataclass
class MigrationRevision:
    revision_id: str
    down_revision: str | list[str] | None
    file_path: Path
    line: int
    created_tables: dict[str, dict[str, ColumnDef]] = field(default_factory=dict)
    dropped_tables: set[str] = field(default_factory=set)
    added_columns: list[tuple[str, ColumnDef]] = field(default_factory=list)
    dropped_columns: list[tuple[str, str]] = field(default_factory=list)
    altered_columns: list[dict[str, Any]] = field(default_factory=list)
    created_indexes: list[dict[str, Any]] = field(default_factory=list)
    created_foreign_keys: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# AST Extraction for SQLAlchemy Models
# ---------------------------------------------------------------------------


def _extract_ast_val(node: ast.AST | None) -> Any:
    """Safely extract literal value from AST node."""
    if node is None:
        return None
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


class _SqlAlchemyModelVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, source_lines: list[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.tables: dict[str, TableModelDef] = {}

    def _get_snippet(self, lineno: int) -> str:
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        table_name: str | None = None
        table_args: list[ast.AST] = []
        columns: dict[str, ColumnDef] = {}
        foreign_keys: list[dict[str, Any]] = []
        indexes: list[dict[str, Any]] = []

        # Check class body assignments
        for stmt in node.body:
            # 1. __tablename__ = "name"
            if isinstance(stmt, ast.Assign):
                for target in stmt.targets:
                    if isinstance(target, ast.Name) and target.id == "__tablename__":
                        val = _extract_ast_val(stmt.value)
                        if isinstance(val, str):
                            table_name = val

                    # 2. __table_args__
                    elif isinstance(target, ast.Name) and target.id == "__table_args__":
                        if isinstance(stmt.value, (ast.Tuple, ast.List)):
                            table_args.extend(stmt.value.elts)

            # 3. Column declarations: col = Column(...) or col: Mapped[...] = mapped_column(...)
            col_target_name: str | None = None
            call_node: ast.Call | None = None

            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                col_target_name = stmt.targets[0].id
                if isinstance(stmt.value, ast.Call):
                    call_node = stmt.value
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                col_target_name = stmt.target.id
                if isinstance(stmt.value, ast.Call):
                    call_node = stmt.value

            if col_target_name and call_node and not col_target_name.startswith("_"):
                func_name = ""
                if isinstance(call_node.func, ast.Name):
                    func_name = call_node.func.id
                elif isinstance(call_node.func, ast.Attribute):
                    func_name = call_node.func.attr

                if func_name in ("Column", "mapped_column"):
                    col_def = self._parse_column_call(call_node, col_target_name, stmt.lineno)
                    if col_def:
                        columns[col_def.name] = col_def
                        if col_def.foreign_key_target:
                            foreign_keys.append({
                                "column": col_def.name,
                                "target": col_def.foreign_key_target,
                                "line": col_def.line,
                            })
                        if col_def.is_indexed:
                            indexes.append({
                                "columns": [col_def.name],
                                "unique": col_def.is_unique,
                                "line": col_def.line,
                            })

        # Parse table_args for additional indexes or composite foreign keys
        for arg in table_args:
            if isinstance(arg, ast.Call):
                f_name = ""
                if isinstance(arg.func, ast.Name):
                    f_name = arg.func.id
                elif isinstance(arg.func, ast.Attribute):
                    f_name = arg.func.attr
                if f_name == "Index":
                    idx_cols = []
                    for idx_arg in arg.args[1:]:
                        col_str = _extract_ast_val(idx_arg)
                        if isinstance(col_str, str):
                            idx_cols.append(col_str)
                    if idx_cols:
                        indexes.append({"columns": idx_cols, "unique": False, "line": arg.lineno})
                elif f_name == "ForeignKeyConstraint":
                    pass

        if table_name:
            self.tables[table_name] = TableModelDef(
                table_name=table_name,
                model_name=node.name,
                columns=columns,
                foreign_keys=foreign_keys,
                indexes=indexes,
                file_path=str(self.file_path),
                line=node.lineno,
                source_snippet=self._get_snippet(node.lineno),
            )

        self.generic_visit(node)

    def _parse_column_call(self, call: ast.Call, attr_name: str, lineno: int) -> ColumnDef | None:
        explicit_name: str | None = None
        type_name: str = "unknown"
        nullable: bool = True
        has_default: bool = False
        is_pk: bool = False
        is_unique: bool = False
        is_indexed: bool = False
        fk_target: str | None = None

        args = call.args

        # Case 1: First arg is string literal column name: Column('name', Type, ...)
        if args and isinstance(args[0], ast.Constant) and isinstance(args[0].value, str):
            explicit_name = args[0].value
            type_nodes = args[1:]
        else:
            type_nodes = args

        # Extract Type
        if type_nodes:
            t_node = type_nodes[0]
            if isinstance(t_node, ast.Call):
                type_name = _extract_ast_val(t_node.func) or "unknown"
            else:
                type_name = _extract_ast_val(t_node) or "unknown"

        # Check for ForeignKey in positional args
        for arg in args:
            if isinstance(arg, ast.Call):
                f_name = _extract_ast_val(arg.func)
                if f_name == "ForeignKey" and arg.args:
                    fk_target_val = _extract_ast_val(arg.args[0])
                    if isinstance(fk_target_val, str):
                        fk_target = fk_target_val

        # Check keyword args
        for kw in call.keywords:
            if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                explicit_name = str(kw.value.value)
            elif kw.arg == "nullable":
                val = _extract_ast_val(kw.value)
                if isinstance(val, bool):
                    nullable = val
            elif kw.arg in ("default", "server_default"):
                has_default = True
            elif kw.arg == "primary_key":
                is_pk = bool(_extract_ast_val(kw.value))
                if is_pk:
                    nullable = False
            elif kw.arg == "unique":
                is_unique = bool(_extract_ast_val(kw.value))
            elif kw.arg == "index":
                is_indexed = bool(_extract_ast_val(kw.value))
            elif kw.arg == "type_":
                if isinstance(kw.value, ast.Call):
                    type_name = _extract_ast_val(kw.value.func) or "unknown"
                else:
                    type_name = _extract_ast_val(kw.value) or "unknown"

        col_name = explicit_name or attr_name
        return ColumnDef(
            name=col_name,
            type_name=type_name,
            nullable=nullable,
            has_default=has_default,
            is_primary_key=is_pk,
            is_unique=is_unique,
            is_indexed=is_indexed,
            foreign_key_target=fk_target,
            file_path=str(self.file_path),
            line=lineno,
            source_snippet=self._get_snippet(lineno),
        )


def _inspect_sqlalchemy_models(root: Path) -> dict[str, TableModelDef]:
    """Scan Python files and extract all SQLAlchemy declarative models."""
    models: dict[str, TableModelDef] = {}

    for py_file in root.rglob("*.py"):
        if any(part in _EXCLUDED_DIRS for part in py_file.parts):
            continue
        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            if "__tablename__" not in content and "Column(" not in content and "mapped_column(" not in content:
                continue
            tree = ast.parse(content, filename=str(py_file))
            visitor = _SqlAlchemyModelVisitor(py_file, content.splitlines())
            visitor.visit(tree)
            models.update(visitor.tables)
        except Exception:
            continue

    return models


# ---------------------------------------------------------------------------
# AST Extraction for Alembic Migrations
# ---------------------------------------------------------------------------


class _AlembicMigrationVisitor(ast.NodeVisitor):
    def __init__(self, file_path: Path, source_lines: list[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.revision_id: str | None = None
        self.down_revision: str | list[str] | None = None
        self.created_tables: dict[str, dict[str, ColumnDef]] = {}
        self.dropped_tables: set[str] = set()
        self.added_columns: list[tuple[str, ColumnDef]] = []
        self.dropped_columns: list[tuple[str, str]] = []
        self.altered_columns: list[dict[str, Any]] = []
        self.created_indexes: list[dict[str, Any]] = []
        self.created_foreign_keys: list[dict[str, Any]] = []

    def _get_snippet(self, lineno: int) -> str:
        if 0 < lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                if target.id == "revision":
                    val = _extract_ast_val(node.value)
                    if isinstance(val, str):
                        self.revision_id = val
                elif target.id == "down_revision":
                    val = _extract_ast_val(node.value)
                    if isinstance(val, str) or val is None:
                        self.down_revision = val
                    elif isinstance(node.value, (ast.Tuple, ast.List)):
                        items = [_extract_ast_val(e) for e in node.value.elts]
                        self.down_revision = [str(x) for x in items if isinstance(x, str)]
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node.name == "upgrade":
            for stmt in ast.walk(node):
                if isinstance(stmt, ast.Call) and isinstance(stmt.func, ast.Attribute):
                    method_name = stmt.func.attr

                    # 1. op.create_table('table_name', sa.Column(...), ...)
                    if method_name == "create_table" and stmt.args:
                        table_name = _extract_ast_val(stmt.args[0])
                        if isinstance(table_name, str):
                            cols: dict[str, ColumnDef] = {}
                            for arg in stmt.args[1:]:
                                col_def = self._parse_sa_column(arg)
                                if col_def:
                                    cols[col_def.name] = col_def
                                    if col_def.foreign_key_target:
                                        self.created_foreign_keys.append({
                                            "table": table_name,
                                            "column": col_def.name,
                                            "target": col_def.foreign_key_target,
                                            "line": stmt.lineno,
                                        })
                            self.created_tables[table_name] = cols

                    # 2. op.add_column('table_name', sa.Column(...))
                    elif method_name == "add_column" and len(stmt.args) >= 2:
                        table_name = _extract_ast_val(stmt.args[0])
                        col_def = self._parse_sa_column(stmt.args[1])
                        if isinstance(table_name, str) and col_def:
                            self.added_columns.append((table_name, col_def))

                    # 3. op.drop_column('table_name', 'col_name')
                    elif method_name == "drop_column" and len(stmt.args) >= 2:
                        t_name = _extract_ast_val(stmt.args[0])
                        c_name = _extract_ast_val(stmt.args[1])
                        if isinstance(t_name, str) and isinstance(c_name, str):
                            self.dropped_columns.append((t_name, c_name))

                    # 4. op.drop_table('table_name')
                    elif method_name == "drop_table" and stmt.args:
                        t_name = _extract_ast_val(stmt.args[0])
                        if isinstance(t_name, str):
                            self.dropped_tables.add(t_name)

                    # 5. op.create_index('ix_name', 'table_name', ['col1', ...])
                    elif method_name == "create_index" and len(stmt.args) >= 3:
                        t_name = _extract_ast_val(stmt.args[1])
                        cols_ast = stmt.args[2]
                        cols = []
                        if isinstance(cols_ast, (ast.List, ast.Tuple)):
                            for c in cols_ast.elts:
                                val = _extract_ast_val(c)
                                if isinstance(val, str):
                                    cols.append(val)
                        if isinstance(t_name, str) and cols:
                            self.created_indexes.append({"table": t_name, "columns": cols, "line": stmt.lineno})

                    # 6. op.create_foreign_key('fk_name', 'source_table', 'referent_table', ['s_col'], ['r_col'])
                    elif method_name == "create_foreign_key" and len(stmt.args) >= 5:
                        s_table = _extract_ast_val(stmt.args[1])
                        r_table = _extract_ast_val(stmt.args[2])
                        s_cols = []
                        if isinstance(stmt.args[3], (ast.List, ast.Tuple)):
                            s_cols = [_extract_ast_val(e) for e in stmt.args[3].elts if isinstance(_extract_ast_val(e), str)]
                        r_cols = []
                        if isinstance(stmt.args[4], (ast.List, ast.Tuple)):
                            r_cols = [_extract_ast_val(e) for e in stmt.args[4].elts if isinstance(_extract_ast_val(e), str)]
                        if isinstance(s_table, str) and isinstance(r_table, str) and s_cols and r_cols:
                            self.created_foreign_keys.append({
                                "table": s_table,
                                "column": s_cols[0],
                                "target": f"{r_table}.{r_cols[0]}",
                                "line": stmt.lineno,
                            })

                    # 7. op.alter_column('table_name', 'col_name', nullable=..., type_=...)
                    elif method_name == "alter_column" and len(stmt.args) >= 2:
                        t_name = _extract_ast_val(stmt.args[0])
                        c_name = _extract_ast_val(stmt.args[1])
                        nullable = None
                        t_type = None
                        for kw in stmt.keywords:
                            if kw.arg == "nullable":
                                val = _extract_ast_val(kw.value)
                                if isinstance(val, bool):
                                    nullable = val
                            elif kw.arg == "type_":
                                t_type = _extract_ast_val(kw.value)
                        if isinstance(t_name, str) and isinstance(c_name, str):
                            self.altered_columns.append({
                                "table": t_name,
                                "column": c_name,
                                "nullable": nullable,
                                "type": t_type,
                                "line": stmt.lineno,
                            })

        self.generic_visit(node)

    def _parse_sa_column(self, node: ast.AST) -> ColumnDef | None:
        if not isinstance(node, ast.Call):
            return None
        f_name = _extract_ast_val(node.func)
        if f_name not in ("Column", "sa.Column"):
            return None

        col_name: str | None = None
        type_name: str = "unknown"
        nullable: bool = True
        has_default: bool = False
        is_pk: bool = False
        fk_target: str | None = None

        if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            col_name = node.args[0].value
            type_nodes = node.args[1:]
        else:
            type_nodes = node.args

        if type_nodes:
            t_node = type_nodes[0]
            if isinstance(t_node, ast.Call):
                type_name = _extract_ast_val(t_node.func) or "unknown"
            else:
                type_name = _extract_ast_val(t_node) or "unknown"

        for arg in node.args:
            if isinstance(arg, ast.Call):
                call_fn = _extract_ast_val(arg.func)
                if call_fn in ("ForeignKey", "sa.ForeignKey") and arg.args:
                    val = _extract_ast_val(arg.args[0])
                    if isinstance(val, str):
                        fk_target = val

        for kw in node.keywords:
            if kw.arg == "nullable":
                val = _extract_ast_val(kw.value)
                if isinstance(val, bool):
                    nullable = val
            elif kw.arg in ("server_default", "default"):
                has_default = True
            elif kw.arg == "primary_key":
                is_pk = bool(_extract_ast_val(kw.value))
                if is_pk:
                    nullable = False

        if not col_name:
            return None

        return ColumnDef(
            name=col_name,
            type_name=type_name,
            nullable=nullable,
            has_default=has_default,
            is_primary_key=is_pk,
            foreign_key_target=fk_target,
            file_path=str(self.file_path),
            line=node.lineno,
            source_snippet=self._get_snippet(node.lineno),
        )


def _inspect_alembic_migrations(root: Path) -> list[MigrationRevision]:
    """Scan and parse all Alembic migration revision files."""
    revisions: list[MigrationRevision] = []

    # Look for migration files under **/versions/*.py or **/migrations/*.py
    for py_file in root.rglob("*.py"):
        if any(part in _EXCLUDED_DIRS for part in py_file.parts):
            continue
        # Fast filter
        if "alembic" not in str(py_file).lower() and "migration" not in str(py_file).lower() and "version" not in str(py_file).lower():
            continue

        try:
            content = py_file.read_text(encoding="utf-8", errors="replace")
            if "revision" not in content or "def upgrade" not in content:
                continue
            tree = ast.parse(content, filename=str(py_file))
            visitor = _AlembicMigrationVisitor(py_file, content.splitlines())
            visitor.visit(tree)
            if visitor.revision_id:
                revisions.append(MigrationRevision(
                    revision_id=visitor.revision_id,
                    down_revision=visitor.down_revision,
                    file_path=py_file,
                    line=1,
                    created_tables=visitor.created_tables,
                    dropped_tables=visitor.dropped_tables,
                    added_columns=visitor.added_columns,
                    dropped_columns=visitor.dropped_columns,
                    altered_columns=visitor.altered_columns,
                    created_indexes=visitor.created_indexes,
                    created_foreign_keys=visitor.created_foreign_keys,
                ))
        except Exception:
            continue

    return revisions


# ---------------------------------------------------------------------------
# Migration Chain Replay & Effective Schema Computation
# ---------------------------------------------------------------------------


@dataclass
class EffectiveMigrationSchema:
    tables: dict[str, dict[str, ColumnDef]] = field(default_factory=dict)
    indexes: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    foreign_keys: list[dict[str, Any]] = field(default_factory=list)
    revision_count: int = 0
    chain_findings: list[Finding] = field(default_factory=list)


def _compute_effective_migration_schema(revisions: list[MigrationRevision]) -> EffectiveMigrationSchema:
    schema = EffectiveMigrationSchema(revision_count=len(revisions))
    if not revisions:
        return schema

    rev_by_id: dict[str, MigrationRevision] = {r.revision_id: r for r in revisions}

    # 1. Check DB007: Broken down_revision references and multiple unmerged heads
    children: dict[str, list[str]] = {}
    roots: list[MigrationRevision] = []

    for r in revisions:
        down = r.down_revision
        if down is None:
            roots.append(r)
        elif isinstance(down, str):
            if down not in rev_by_id:
                # Broken migration chain!
                fid = hashlib.sha1(f"DB007:{r.file_path.name}:{down}".encode()).hexdigest()[:12]
                schema.chain_findings.append(Finding(
                    id=fid,
                    rule_id="DB007",
                    title=f"Broken migration revision chain in '{r.file_path.name}'",
                    severity="high",
                    confidence=0.95,
                    category="Database Schema",
                    message=(
                        f"Migration revision '{r.revision_id}' specifies down_revision='{down}', "
                        f"but no migration file with revision ID '{down}' exists in the project."
                    ),
                    recommendation="Ensure all migration revisions form a contiguous lineage or run 'alembic history' to identify missing versions.",
                    evidence=[Evidence(role="backend", file=str(r.file_path), line=1, source=f"down_revision = '{down}'")],
                    details={"revision": r.revision_id, "missing_down_revision": down},
                ))
            else:
                children.setdefault(down, []).append(r.revision_id)
        elif isinstance(down, (list, tuple)):
            for d in down:
                if d not in rev_by_id:
                    fid = hashlib.sha1(f"DB007:{r.file_path.name}:{d}".encode()).hexdigest()[:12]
                    schema.chain_findings.append(Finding(
                        id=fid,
                        rule_id="DB007",
                        title=f"Broken merge down_revision '{d}' in '{r.file_path.name}'",
                        severity="high",
                        confidence=0.95,
                        category="Database Schema",
                        message=f"Merge revision '{r.revision_id}' references missing parent revision '{d}'.",
                        recommendation="Realign the migration merge revision parents.",
                        evidence=[Evidence(role="backend", file=str(r.file_path), line=1, source=str(down))],
                        details={"revision": r.revision_id, "missing_down_revision": d},
                    ))
                else:
                    children.setdefault(d, []).append(r.revision_id)

    # Detect multiple heads without merge
    heads = [r for r in revisions if r.revision_id not in children]
    if len(heads) > 1:
        head_ids = [h.revision_id for h in heads]
        fid = hashlib.sha1(f"DB007:multiple_heads:{'_'.join(sorted(head_ids))}".encode()).hexdigest()[:12]
        ev_list = [Evidence(role="backend", file=str(h.file_path), line=1, source=f"revision = '{h.revision_id}'") for h in heads[:4]]
        schema.chain_findings.append(Finding(
            id=fid,
            rule_id="DB007",
            title=f"Multiple Alembic migration heads ({len(heads)}) detected without merge",
            severity="medium",
            confidence=0.90,
            category="Database Schema",
            message=(
                f"Project contains {len(heads)} divergent migration branches (heads: {', '.join(head_ids)}). "
                f"Running migrations in CI/production will fail with multiple heads error."
            ),
            recommendation="Run 'alembic merge heads -m \"merge divergent branches\"' to reconcile divergent revision chains.",
            evidence=ev_list,
            details={"heads": head_ids},
        ))

    # Replay migrations in chronological / revision order
    # Simple order: root to leaves
    visited: set[str] = set()
    ordered_revs: list[MigrationRevision] = []

    def _visit(r: MigrationRevision) -> None:
        if r.revision_id in visited:
            return
        visited.add(r.revision_id)
        ordered_revs.append(r)
        for child_id in children.get(r.revision_id, []):
            if child_id in rev_by_id:
                _visit(rev_by_id[child_id])

    for root_r in roots:
        _visit(root_r)

    # Add any disconnected / unvisited revisions
    for r in revisions:
        if r.revision_id not in visited:
            ordered_revs.append(r)

    for rev in ordered_revs:
        # 1. create_table
        for t_name, cols in rev.created_tables.items():
            schema.tables[t_name] = dict(cols)

        # 2. add_column
        for t_name, c_def in rev.added_columns:
            if t_name in schema.tables:
                schema.tables[t_name][c_def.name] = c_def
            else:
                schema.tables.setdefault(t_name, {})[c_def.name] = c_def

        # 3. drop_column
        for t_name, c_name in rev.dropped_columns:
            if t_name in schema.tables and c_name in schema.tables[t_name]:
                del schema.tables[t_name][c_name]

        # 4. drop_table
        for t_name in rev.dropped_tables:
            if t_name in schema.tables:
                del schema.tables[t_name]

        # 5. alter_column
        for alt in rev.altered_columns:
            t_name = alt["table"]
            c_name = alt["column"]
            if t_name in schema.tables and c_name in schema.tables[t_name]:
                col = schema.tables[t_name][c_name]
                if alt.get("nullable") is not None:
                    col.nullable = alt["nullable"]
                if alt.get("type"):
                    col.type_name = str(alt["type"])

        # 6. indexes
        for idx in rev.created_indexes:
            t_name = idx["table"]
            schema.indexes.setdefault(t_name, []).append(idx)

        # 7. foreign keys
        schema.foreign_keys.extend(rev.created_foreign_keys)

    return schema


# ---------------------------------------------------------------------------
# Cross-Validation Rules Execution
# ---------------------------------------------------------------------------


def analyze_database_diagnostics(root: Path) -> list[Finding]:
    """Inspect project SQLAlchemy models and Alembic migrations.

    Returns:
        List of Finding instances for schema mismatches, missing columns,
        type discrepancies, unindexed foreign keys, and broken revision chains.
    """
    findings: list[Finding] = []
    seen_ids: set[str] = set()

    models = _inspect_sqlalchemy_models(root)
    revisions = _inspect_alembic_migrations(root)

    # 1. If no migrations and no models exist, nothing to diagnose
    if not models and not revisions:
        return []

    effective_schema = _compute_effective_migration_schema(revisions)
    findings.extend(effective_schema.chain_findings)
    mig_tables = effective_schema.tables

    has_migrations = effective_schema.revision_count > 0

    # -----------------------------------------------------------------------
    # DB001: Model / Migration Table Mismatch
    # -----------------------------------------------------------------------
    if has_migrations:
        for table_name, model_def in models.items():
            if table_name not in mig_tables:
                fid = hashlib.sha1(f"DB001:missing_table:{table_name}:{model_def.model_name}".encode()).hexdigest()[:12]
                if fid not in seen_ids:
                    seen_ids.add(fid)
                    findings.append(Finding(
                        id=fid,
                        rule_id="DB001",
                        title=f"SQLAlchemy model '{model_def.model_name}' table '{table_name}' missing from migrations",
                        severity="high",
                        confidence=0.92,
                        category="Database Schema",
                        message=(
                            f"Model '{model_def.model_name}' defines '__tablename__ = \"{table_name}\"', "
                            f"but no Alembic migration creates this table. Running queries against this model "
                            f"will fail with UndefinedTableError in PostgreSQL."
                        ),
                        recommendation=f"Generate an Alembic migration (e.g. 'alembic revision --autogenerate -m \"create {table_name} table\"') to create '{table_name}'.",
                        evidence=[Evidence(role="backend", file=model_def.file_path, line=model_def.line, source=model_def.source_snippet)],
                        details={"table": table_name, "model": model_def.model_name, "issue": "table_not_in_migrations"},
                    ))

    # -----------------------------------------------------------------------
    # DB002: Missing Column in Migration or Model
    # DB003: Column Type Mismatch
    # DB004: Nullable / Default Inconsistency
    # -----------------------------------------------------------------------
    if has_migrations:
        for table_name, model_def in models.items():
            if table_name not in mig_tables:
                continue

            mig_cols = mig_tables[table_name]

            # Columns in Model vs Migration
            for col_name, m_col in model_def.columns.items():
                if col_name not in mig_cols:
                    fid = hashlib.sha1(f"DB002:missing_column:{table_name}:{col_name}".encode()).hexdigest()[:12]
                    if fid not in seen_ids:
                        seen_ids.add(fid)
                        findings.append(Finding(
                            id=fid,
                            rule_id="DB002",
                            title=f"Column '{col_name}' in model '{model_def.model_name}' missing from table '{table_name}'",
                            severity="high",
                            confidence=0.90,
                            category="Database Schema",
                            message=(
                                f"Model '{model_def.model_name}' declares column '{col_name}', but column '{col_name}' "
                                f"was not created in Alembic migrations for table '{table_name}'."
                            ),
                            recommendation=f"Add an Alembic migration with 'op.add_column(\"{table_name}\", sa.Column(\"{col_name}\", ...))'.",
                            evidence=[Evidence(role="backend", file=m_col.file_path, line=m_col.line, source=m_col.source_snippet)],
                            details={"table": table_name, "column": col_name, "model": model_def.model_name},
                        ))
                else:
                    mig_col = mig_cols[col_name]

                    # DB003: Type Mismatch
                    m_norm = _normalize_sql_type(m_col.type_name)
                    mig_norm = _normalize_sql_type(mig_col.type_name)
                    if m_norm != "unknown" and mig_norm != "unknown" and m_norm != mig_norm:
                        # Allow string and text interoperability
                        if not ({m_norm, mig_norm} == {"string", "text"}):
                            fid = hashlib.sha1(f"DB003:type_mismatch:{table_name}:{col_name}:{m_norm}:{mig_norm}".encode()).hexdigest()[:12]
                            if fid not in seen_ids:
                                seen_ids.add(fid)
                                findings.append(Finding(
                                    id=fid,
                                    rule_id="DB003",
                                    title=f"Column type mismatch on '{table_name}.{col_name}' ({m_col.type_name} vs {mig_col.type_name})",
                                    severity="high",
                                    confidence=0.88,
                                    category="Database Schema",
                                    message=(
                                        f"Model '{model_def.model_name}' defines column '{col_name}' as '{m_col.type_name}', "
                                        f"but Alembic migrations specify '{mig_col.type_name}'."
                                    ),
                                    recommendation=f"Align column type in model '{model_def.model_name}' or add an alter_column migration.",
                                    evidence=[
                                        Evidence(role="backend", file=m_col.file_path, line=m_col.line, source=m_col.source_snippet),
                                        Evidence(role="backend", file=mig_col.file_path, line=mig_col.line, source=mig_col.source_snippet),
                                    ],
                                    details={"table": table_name, "column": col_name, "model_type": m_col.type_name, "migration_type": mig_col.type_name},
                                ))

                    # DB004: Nullable Inconsistency
                    # Flag when Model requires NOT NULL (without default), but migration allowed NULL
                    if not m_col.nullable and not m_col.has_default and mig_col.nullable and not mig_col.has_default:
                        fid = hashlib.sha1(f"DB004:nullable_mismatch:{table_name}:{col_name}".encode()).hexdigest()[:12]
                        if fid not in seen_ids:
                            seen_ids.add(fid)
                            findings.append(Finding(
                                id=fid,
                                rule_id="DB004",
                                title=f"Nullable inconsistency on '{table_name}.{col_name}'",
                                severity="medium",
                                confidence=0.85,
                                category="Database Schema",
                                message=(
                                    f"Model '{model_def.model_name}' defines column '{col_name}' as NOT NULL (nullable=False), "
                                    f"but the migration schema defines it as nullable without a default value."
                                ),
                                recommendation="Align nullability constraints between model and Alembic migration.",
                                evidence=[
                                    Evidence(role="backend", file=m_col.file_path, line=m_col.line, source=m_col.source_snippet),
                                    Evidence(role="backend", file=mig_col.file_path, line=mig_col.line, source=mig_col.source_snippet),
                                ],
                                details={"table": table_name, "column": col_name, "model_nullable": False, "migration_nullable": True},
                            ))

    # -----------------------------------------------------------------------
    # DB005: Foreign-Key Target Inconsistency
    # -----------------------------------------------------------------------
    all_known_tables: dict[str, set[str]] = {}
    if has_migrations:
        for t, cols in mig_tables.items():
            all_known_tables[t] = set(cols.keys())
    for t, m_def in models.items():
        all_known_tables.setdefault(t, set()).update(m_def.columns.keys())

    for table_name, model_def in models.items():
        for fk in model_def.foreign_keys:
            target = fk.get("target")  # e.g. "users.id" or "auth.users.id"
            col = fk.get("column")
            if target and "." in target:
                parts = target.split(".")
                r_col = parts[-1]
                r_table = parts[-2]
                # Skip external schemas like auth.users
                if len(parts) >= 3 and parts[0] in ("auth", "storage", "public"):
                    continue
                if r_table in all_known_tables and r_col not in all_known_tables[r_table]:
                    fid = hashlib.sha1(f"DB005:fk_target_missing:{table_name}:{col}:{target}".encode()).hexdigest()[:12]
                    if fid not in seen_ids:
                        seen_ids.add(fid)
                        findings.append(Finding(
                            id=fid,
                            rule_id="DB005",
                            title=f"Foreign key '{table_name}.{col}' targets nonexistent column '{target}'",
                            severity="high",
                            confidence=0.94,
                            category="Database Schema",
                            message=(
                                f"Model '{model_def.model_name}' references '{target}' via foreign key, "
                                f"but table '{r_table}' does not declare column '{r_col}'."
                            ),
                            recommendation=f"Update foreign key reference on '{table_name}.{col}' to point to an existing column in '{r_table}'.",
                            evidence=[Evidence(role="backend", file=model_def.file_path, line=fk.get("line", 1), source=f"ForeignKey('{target}')")],
                            details={"source_table": table_name, "source_column": col, "target": target},
                        ))

    # -----------------------------------------------------------------------
    # DB006: Unindexed Foreign Key Column
    # -----------------------------------------------------------------------
    for table_name, model_def in models.items():
        # Collect all indexed columns on this table
        indexed_cols: set[str] = set()
        for c in model_def.columns.values():
            if c.is_indexed or c.is_primary_key or c.is_unique:
                indexed_cols.add(c.name)
        for idx in model_def.indexes:
            for c_name in idx.get("columns", []):
                indexed_cols.add(c_name)
        if table_name in effective_schema.indexes:
            for idx in effective_schema.indexes[table_name]:
                for c_name in idx.get("columns", []):
                    indexed_cols.add(c_name)

        for fk in model_def.foreign_keys:
            col_name = fk.get("column")
            if col_name and col_name not in indexed_cols:
                fid = hashlib.sha1(f"DB006:unindexed_fk:{table_name}:{col_name}".encode()).hexdigest()[:12]
                if fid not in seen_ids:
                    seen_ids.add(fid)
                    findings.append(Finding(
                        id=fid,
                        rule_id="DB006",
                        title=f"Unindexed foreign key column '{table_name}.{col_name}'",
                        severity="medium",
                        confidence=0.82,
                        category="Database Schema",
                        message=(
                            f"Column '{col_name}' on table '{table_name}' defines a foreign key constraint "
                            f"targeting '{fk.get('target')}', but has no index. In PostgreSQL, unindexed foreign keys "
                            f"cause table locks during parent record deletions and lead to full table scans on joins."
                        ),
                        recommendation=f"Add index=True to '{table_name}.{col_name}' or declare an explicit Index in __table_args__.",
                        evidence=[Evidence(role="backend", file=model_def.file_path, line=fk.get("line", 1), source=f"ForeignKey('{fk.get('target')}')")],
                        details={"table": table_name, "column": col_name, "target": fk.get("target")},
                    ))

    return findings

