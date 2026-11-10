"""
Static analysis for deprecated PQC API usage (S8).

This module provides harden_check_unsafe_api() which scans Python code
for deprecated, non-PQC cryptography calls (legacy RSA/ECC imports, etc.).
"""
import ast
import os
import sys
import importlib.util
from typing import Dict, Any, List, Union

# Legacy algorithm tokens: an import is deprecated only when its
# module-path segment or imported name is EXACTLY one of these tokens.
# Substring matching is forbidden here: "dsa" ⊂ "mldsa" and "ec" ⊂
# "ed448"/"mldsa" are PQC-adjacent false positives.
DEPRECATED_TOKENS = frozenset({
    "rsa",
    "dsa",
    "ec",
    "ecdsa",
    "ed25519",
    "ed448",
    "x25519",
    "x448",
    "ed448_scc",
    "padding",
    "seed",
})

# PQC-safe tokens: never flagged even when they share a substring with a
# legacy token (mlkem, mldsa, slhdsa ...).
PQC_SAFE_TOKENS = frozenset({
    "mlkem",
    "mldsa",
    "slhdsa",
    "ml_dsa",
    "ml_kem",
    "pqcrypto",
    "mlkemparam",
    "dilithium",
    "falcon",
    "sphincs",
})

# Module path segments that make an import deprecated only when the
# *imported name* (or its module segment) is a legacy token.
_ASYMMETRIC_SEGMENT = "asymmetric"


def _token_is_deprecated(token: str) -> bool:
    """True only when `token` is exactly a legacy token, not a PQC-safe one."""
    token_l = token.lower()
    if token_l in PQC_SAFE_TOKENS:
        return False
    return token_l in DEPRECATED_TOKENS


class UnsafeAPIDetector(ast.NodeVisitor):
    """AST visitor that detects deprecated PQC API usage."""

    def __init__(self, source_file: str):
        self.source_file = source_file
        self.findings: List[Dict[str, Any]] = []
        self.source_lines: List[str] = []

    def visit_Import(self, node: ast.Import):
        """Detect 'import rsa' or 'import ec' style imports."""
        self._check_imports(node.names, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Detect 'from cryptography.hazmat.primitives.asymmetric import rsa' style imports."""
        if node.module:
            self._check_from_import(node.module, node.names, node.lineno)
        self.generic_visit(node)

    def _check_imports(self, names: List[ast.alias], lineno: int):
        """Check simple import statements."""
        for alias in names:
            name = alias.name
            if _token_is_deprecated(name):
                self.findings.append({
                    "file": self.source_file,
                    "line": lineno,
                    "pattern": name,
                    "severity": "high"
                })

    def _check_from_import(self, module: str, names: List[ast.alias], lineno: int):
        """Check 'from X import Y' style imports."""
        module_lower = module.lower()
        
        # Is this an 'asymmetric' module import?
        from_asymmetric = _ASYMMETRIC_SEGMENT in module_lower.split(".")
        
        for alias in names:
            name = alias.name
            if from_asymmetric and _token_is_deprecated(name):
                # Import from asymmetric module of a legacy token
                self.findings.append({
                    "file": self.source_file,
                    "line": lineno,
                    "pattern": f"from {module} import {name}",
                    "severity": "high"
                })
            elif not from_asymmetric and _token_is_deprecated(name):
                # Direct import of a legacy token (e.g., 'import rsa' handled above,
                # but could also be 'from some_lib import rsa')
                self.findings.append({
                    "file": self.source_file,
                    "line": lineno,
                    "pattern": f"from {module} import {name}",
                    "severity": "high"
                })


def harden_check_unsafe_api(module: Union[object, str]) -> Dict[str, Any]:
    """Scan a Python module for deprecated PQC API usage.

    Returns {
        "findings": [{ "file": str, "line": int, "pattern": str, "severity": str }],
        "count": int
    }

    Intake is either an already-imported module object (behaviour unchanged)
    or a string target:
    - a path ending in `.py` → AST-walk that file;
    - any other existing path → recursive walk of `*.py` beneath it;
    - otherwise → treated as an importable module name and resolved with
      `importlib` (this is how submodule-only packages such as
      `cryptography.hazmat.primitives.asymmetric.mlkem` are reachable).

    A non-existent path or unresolvable module name raises `ValueError` with
    the target string. The returned shape is unchanged:
    {
        "findings": [{ "file", "line", "pattern", "severity" }],
        "count": int
    }

    `findings` entries gained a `file` field when target intake was added;
    module-object callers get `file` = the module `__file__` (or `"<memory>"`
    for a module with no source file).

    Example patterns flagged:
    - usage of `cryptography.hazmat.primitives.asymmetric` paths that are not
      PQC-ready
    - import of legacy RSA/ECC where ML-KEM/ML-DSA is required per CNSA 2.0.
    """
    target = module
    findings: List[Dict[str, Any]] = []
    source_file = "<memory>"

    # Handle string targets
    if isinstance(module, str):
        target = module
        
        # Check if it's a .py file
        if target.endswith(".py") or (os.path.isfile(target) and target.endswith(".py")):
            if not os.path.exists(target):
                raise ValueError(f"Target not found: {target}")
            source_file = target
            results = _scan_file(target)
            return {"findings": results, "count": len(results)}
        
        # Check if it's a directory
        if os.path.isdir(target):
            results = _scan_directory(target)
            return {"findings": results, "count": len(results)}
        
        # Otherwise treat as module name
        if not os.path.exists(target):
            raise ValueError(f"Target not found: {target}")
        
        # Try to import the module
        try:
            spec = importlib.util.find_spec(target)
            if spec is None or spec.origin is None:
                raise ValueError(f"Cannot resolve module: {target}")
            
            # Import the module
            if target in sys.modules:
                mod_obj = sys.modules[target]
            else:
                mod_obj = importlib.import_module(target)
            
            # Get the source file
            source_file = getattr(mod_obj, "__file__", "<memory>")
            if source_file is None:
                source_file = "<memory>"
            
            # Scan the module object
            if source_file != "<memory>" and source_file.endswith(".py"):
                results = _scan_file(source_file)
            else:
                results = _scan_module_ast(mod_obj)
            
            return {"findings": results, "count": len(results)}
        except (ImportError, ModuleNotFoundError, ValueError):
            raise ValueError(f"Cannot resolve module: {target}")

    # Handle module object input
    if not hasattr(module, '__file__') and not isinstance(module, type(sys)):
        # Non-module object - return empty findings (graceful) or could raise TypeError
        # Per spec: "TypeError or graceful empty findings"
        return {"findings": [], "count": 0}

    # Module object case
    source_file = getattr(module, "__file__", None)
    if source_file is None:
        source_file = "<memory>"
    
    if source_file != "<memory>" and source_file.endswith(".py"):
        results = _scan_file(source_file)
        # Update file field to module's file
        for f in results:
            f["file"] = source_file
        return {"findings": results, "count": len(results)}
    else:
        results = _scan_module_ast(module)
        for f in results:
            f["file"] = source_file
        return {"findings": results, "count": len(results)}


def _scan_file(filepath: str) -> List[Dict[str, Any]]:
    """Scan a single Python file for deprecated patterns."""
    findings = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            source = f.read()
    except (IOError, OSError):
        return findings
    
    try:
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return findings
    
    detector = UnsafeAPIDetector(filepath)
    detector.visit(tree)
    return detector.findings


def _scan_directory(dirpath: str) -> List[Dict[str, Any]]:
    """Recursively scan all .py files in a directory."""
    findings = []
    
    for root, dirs, files in os.walk(dirpath):
        for filename in files:
            if filename.endswith(".py"):
                filepath = os.path.join(root, filename)
                file_findings = _scan_file(filepath)
                findings.extend(file_findings)
    
    return findings


def _scan_module_ast(module) -> List[Dict[str, Any]]:
    """Scan a module object by parsing its AST from source."""
    findings = []
    
    source_file = getattr(module, "__file__", "<memory>")
    if source_file == "<memory>":
        # Try to get source from the module
        try:
            import inspect
            source = inspect.getsource(module)
            tree = ast.parse(source)
            detector = UnsafeAPIDetector("<memory>")
            detector.visit(tree)
            return detector.findings
        except (OSError, TypeError):
            return findings
    
    return findings