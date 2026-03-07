"""
Safe expression evaluator for length / count / offset expressions.

Protocol definitions use `{expr}` strings to express values that depend on
previously-parsed fields.  For example:

    length: "{username_len}"
    length: "{total_length - 5}"
    count:  "{item_count * 2}"

The parser calls `evaluate(expr_str, context)` where `context` is a dict of
field_name → int value built up as fields are parsed left to right.

Security:
    We evaluate using Python's `eval()` on the extracted expression, but with
    a heavily restricted namespace: only the context variables, basic arithmetic
    operators, and a handful of safe builtins (min, max, abs).  No attribute
    access, no imports, no calls to arbitrary callables — these are all blocked
    by AST inspection before eval() is called.

    This is intentional: protocol definitions are authored by the pentester
    themselves and loaded from local files they control.  The restriction is
    a defence-in-depth measure to catch accidental complexity, not to sandbox
    untrusted input.
"""

from __future__ import annotations

import ast
import re


# Allowed AST node types — strictly arithmetic + names
_ALLOWED_NODES = {
    ast.Expression,
    ast.BinOp,
    ast.UnaryOp,
    ast.Constant,
    ast.Name,
    ast.Load,    # required by ast.Name for variable reads
    ast.Call,    # allowed only for the safe builtins: min, max, abs, int
    ast.Add,
    ast.Sub,
    ast.Mult,
    ast.FloorDiv,
    ast.Mod,
    ast.UAdd,
    ast.USub,
    ast.IfExp,   # ternary: a if cond else b
    ast.Compare,
    ast.BoolOp,
    ast.And,
    ast.Or,
    ast.Not,
    ast.Eq,
    ast.NotEq,
    ast.Lt,
    ast.LtE,
    ast.Gt,
    ast.GtE,
}

_SAFE_BUILTINS = {"min": min, "max": max, "abs": abs, "int": int}

_EXPR_RE = re.compile(r"^\{(.+)\}$")


def evaluate(expr_str: str, context: dict[str, int]) -> int:
    """
    Evaluate an expression string with the given variable context.

    If `expr_str` is a plain integer literal (no braces), return it directly.
    If it's wrapped in `{...}`, extract and evaluate the inner expression.

    Args:
        expr_str: A string like "4", "{username_len}", or "{total - 5}".
        context:  Dict of field_name → int for all previously parsed fields.

    Returns:
        Integer result.

    Raises:
        ValueError:   Expression is malformed, unsafe, or uses an undefined name.
        ZeroDivisionError: Expression involves division by zero.
    """
    if expr_str is None:
        raise ValueError("Expression string is None")

    expr_str = str(expr_str).strip()

    # Plain integer literal
    if expr_str.lstrip("-").isdigit():
        return int(expr_str)

    # Must be {expr}
    m = _EXPR_RE.match(expr_str)
    if not m:
        raise ValueError(
            f"Expression {expr_str!r} must be either a plain integer "
            f"or a {{expression}} string like '{{username_len - 4}}'"
        )

    inner = m.group(1).strip()
    return _safe_eval(inner, context)


def _safe_eval(expr: str, context: dict[str, int]) -> int:
    try:
        tree = ast.parse(expr, mode="eval")
    except SyntaxError as exc:
        raise ValueError(f"Syntax error in expression {expr!r}: {exc}") from exc

    _check_ast(tree, expr)

    ns = {**context, **_SAFE_BUILTINS}
    try:
        result = eval(compile(tree, "<expr>", "eval"), {"__builtins__": {}}, ns)  # noqa: S307
    except NameError as exc:
        raise ValueError(
            f"Undefined name in expression {expr!r}: {exc}. "
            f"Available fields: {sorted(context.keys())}"
        ) from exc

    if not isinstance(result, (int, float, bool)):
        raise ValueError(
            f"Expression {expr!r} evaluated to {type(result).__name__}; expected a number"
        )
    return int(result)


def _check_ast(tree: ast.AST, expr: str) -> None:
    for node in ast.walk(tree):
        if type(node) is ast.Call:
            # Only calls to explicitly whitelisted names are permitted
            if not (isinstance(node.func, ast.Name) and node.func.id in _SAFE_BUILTINS):
                raise ValueError(
                    f"Unsafe function call in expression {expr!r}. "
                    f"Allowed functions: {sorted(_SAFE_BUILTINS.keys())}"
                )
            continue
        if type(node) not in _ALLOWED_NODES:
            raise ValueError(
                f"Unsafe construct {type(node).__name__!r} in expression {expr!r}. "
                f"Only arithmetic operations and field name references are allowed."
            )
