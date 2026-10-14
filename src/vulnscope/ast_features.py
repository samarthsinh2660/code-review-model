"""Count selected Clang AST nodes inside a source-local function body."""

from __future__ import annotations

import bisect


AST_KINDS = (
    "IfStmt", "ForStmt", "WhileStmt", "DoStmt", "SwitchStmt",
    "CallExpr", "CXXMemberCallExpr", "BinaryOperator", "CompoundAssignOperator",
    "UnaryOperator", "ArraySubscriptExpr", "CStyleCastExpr", "CXXStaticCastExpr",
    "CXXNewExpr", "CXXDeleteExpr", "DeclStmt", "ReturnStmt", "ConditionalOperator",
    "MemberExpr",
)
FEATURE_NAMES = tuple(f"ast_{kind}" for kind in AST_KINDS)
FUNCTION_KINDS = {"FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl"}
BODY_KINDS = {"CompoundStmt", "CXXTryStmt"}


def _line(offset: int, newline_offsets: list[int]) -> int:
    return bisect.bisect_left(newline_offsets, offset) + 1


def ast_body_counts(
    ast: dict, source: bytes, function_name: str, declaration_start_line: int
) -> tuple[int, ...]:
    """Find exactly one audited definition and count node kinds under its body."""

    newlines = [index for index, byte in enumerate(source) if byte == 10]
    candidates = []
    stack = [ast]
    while stack:
        node = stack.pop()
        stack.extend(node.get("inner", []))
        if node.get("kind") not in FUNCTION_KINDS or node.get("name") != function_name:
            continue
        offset = node.get("loc", {}).get("offset")
        begin = node.get("range", {}).get("begin", {}).get("offset")
        encoded = function_name.encode()
        if (
            not isinstance(offset, int) or not isinstance(begin, int)
            or source[offset : offset + len(encoded)] != encoded
            or _line(begin, newlines) != declaration_start_line
        ):
            continue
        bodies = [child for child in node.get("inner", []) if child.get("kind") in BODY_KINDS]
        if len(bodies) == 1:
            candidates.append(bodies[0])
    if len(candidates) != 1:
        raise ValueError(f"expected one AST body for {function_name}@{declaration_start_line}, found {len(candidates)}")
    counts = {kind: 0 for kind in AST_KINDS}
    stack = [candidates[0]]
    while stack:
        node = stack.pop()
        kind = node.get("kind")
        if kind in counts:
            counts[kind] += 1
        stack.extend(node.get("inner", []))
    return tuple(counts[kind] for kind in AST_KINDS)
