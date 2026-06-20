"""
AST-based scanner. Uses tree-sitter to confirm regex findings.
Strategy: regex pre-filter -> AST confirmation.

Covers:
  - eval / exec
  - child_process.exec (Node)
  - subprocess with shell=True (Python)
  - SQL string concatenation
  - path.join with user input (basic traversal signal)
"""

import ast as _pyast
import re as _re
from pathlib import Path
from typing import List

_SQL_VERB = _re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b")
_SQL_CLAUSE = _re.compile(r"\b(FROM|INTO|WHERE|VALUES|SET|JOIN)\b")


def _looks_like_sql(text_upper: str) -> bool:
    if not (_SQL_VERB.search(text_upper) and _SQL_CLAUSE.search(text_upper)):
        return False
    return any(tok in text_upper for tok in ("EXECUTE", "QUERY", "CURSOR", "._Q(", "SQL", "TABLE", "RETURNING"))


def analyze_python_ast(content: str) -> List[dict]:
    """
    Native-AST Python analyzer. Flags ONLY real call expressions to dangerous
    sinks - never strings, comments, or identifiers that merely mention them.
    Works without tree-sitter (uses the standard-library `ast`).
    Returns finding dicts: {line, type, name, severity, snippet, fix}.
    """
    try:
        tree = _pyast.parse(content)
    except (SyntaxError, ValueError):
        return []

    findings: List[dict] = []

    def _full_name(node) -> str:
        parts = []
        while isinstance(node, _pyast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, _pyast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def _kw(call, name):
        for k in call.keywords:
            if k.arg == name:
                return k
        return None

    SECURITY_CTX = ("token", "password", "secret", "nonce", "salt", "key",
                    "otp", "session", "csrf", "auth", "passwd", "pin")

    for node in _pyast.walk(tree):
        if not isinstance(node, _pyast.Call):
            continue
        name = _full_name(node.func)
        line = getattr(node, "lineno", 1)

        if name in ("pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads"):
            findings.append({"line": line, "type": "unsafe_pickle",
                "name": "Unsafe pickle deserialization", "severity": "high",
                "snippet": name + "(...)",
                "fix": "Avoid pickle on untrusted data. Use json, or verify the source is trusted."})

        elif name == "yaml.load":
            loader = _kw(node, "Loader")
            loader_txt = _full_name(loader.value) if (loader and isinstance(loader.value, (_pyast.Attribute, _pyast.Name))) else ""
            if "safe" not in loader_txt.lower():
                findings.append({"line": line, "type": "unsafe_yaml",
                    "name": "Unsafe yaml.load() - missing SafeLoader", "severity": "high",
                    "snippet": "yaml.load(...)",
                    "fix": "Use yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader)."})

        elif name in ("eval", "exec"):
            only_const = len(node.args) == 1 and isinstance(node.args[0], _pyast.Constant)
            if not only_const:
                findings.append({"line": line, "type": "code_execution",
                    "name": "Dynamic code execution (eval/exec)", "severity": "high",
                    "snippet": name + "(...)",
                    "fix": "Avoid eval/exec. Use ast.literal_eval for data, or an explicit dispatch table."})

        elif name in ("subprocess.run", "subprocess.call", "subprocess.Popen",
                      "subprocess.check_output", "subprocess.check_call"):
            shell = _kw(node, "shell")
            if shell is not None and isinstance(shell.value, _pyast.Constant) and shell.value.value is True:
                findings.append({"line": line, "type": "command_injection",
                    "name": "subprocess with shell=True", "severity": "high",
                    "snippet": name + "(..., shell=True)",
                    "fix": "Use a list of args with shell=False (the default), never a shell string."})
        elif name in ("os.system", "os.popen"):
            findings.append({"line": line, "type": "command_injection",
                "name": "Command execution via " + name, "severity": "high",
                "snippet": name + "(...)",
                "fix": "Replace with subprocess.run([...], shell=False) and validate inputs."})

    # Second pass: weak randomness in security context — assignment targets
    _weak_random_lines: set[int] = set()
    for node in _pyast.walk(tree):
        target_names = []
        if isinstance(node, _pyast.Assign):
            for t in node.targets:
                if isinstance(t, _pyast.Name):
                    target_names.append(t.id.lower())
                elif isinstance(t, _pyast.Attribute):
                    target_names.append(t.attr.lower())
        elif isinstance(node, _pyast.AnnAssign) and isinstance(node.target, _pyast.Name):
            target_names.append(node.target.id.lower())
        else:
            continue
        if not any(any(ctx in tn for ctx in SECURITY_CTX) for tn in target_names):
            continue
        value = getattr(node, "value", None)
        for sub in (_pyast.walk(value) if value is not None else []):
            if isinstance(sub, _pyast.Call):
                nm = _full_name(sub.func)
                if nm.startswith("random."):
                    ln = getattr(sub, "lineno", 1)
                    _weak_random_lines.add(ln)
                    findings.append({"line": ln, "type": "weak_random",
                        "name": "Weak RNG for a security value", "severity": "medium",
                        "snippet": nm + "(...)",
                        "fix": "Use the secrets module (secrets.token_hex / secrets.randbelow) for security values."})

    # Third pass: random.* calls inside security-named functions (catches return/direct calls)
    for node in _pyast.walk(tree):
        if not isinstance(node, (_pyast.FunctionDef, _pyast.AsyncFunctionDef)):
            continue
        if not any(ctx in node.name.lower() for ctx in SECURITY_CTX):
            continue
        for sub in _pyast.walk(node):
            if isinstance(sub, _pyast.Call):
                nm = _full_name(sub.func)
                if nm.startswith("random."):
                    ln = getattr(sub, "lineno", 1)
                    if ln not in _weak_random_lines:
                        _weak_random_lines.add(ln)
                        findings.append({"line": ln, "type": "weak_random",
                            "name": "Weak RNG in security function", "severity": "medium",
                            "snippet": nm + "(...)",
                            "fix": "Use the secrets module (secrets.token_hex / secrets.randbelow) for security values."})
    return findings


try:
    from tree_sitter import Language, Parser
    import tree_sitter_javascript as tsjs
    import tree_sitter_python as tspy
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False


# ---------------------------------------------------------------------------
# Regex pre-filters - cheap, run first
# ---------------------------------------------------------------------------

_NODE_TRIGGERS = [
    "eval(",
    "exec(",
    "child_process",
    ".exec(",
    "execSync(",
    "readFile(",
    "readFileSync(",
    "path.join(",
    "SELECT ",
    "INSERT ",
    "UPDATE ",
    "DELETE ",
]

_PYTHON_TRIGGERS = [
    "eval(",
    "exec(",
    "subprocess",
    "os.system(",
    "pickle.load",
    "yaml.load(",
    "open(",
    "SELECT ",
    "INSERT ",
    "UPDATE ",
    "DELETE ",
]


def _has_trigger(content: str, triggers: list) -> bool:
    content_lower = content.lower()
    return any(t.lower() in content_lower for t in triggers)


# ---------------------------------------------------------------------------
# AST visitors
# ---------------------------------------------------------------------------

def _get_node_text(node) -> str:
    try:
        return node.text.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _visit_js(root_node) -> List[dict]:
    findings = []

    def visit(node):
        if node.type == "call_expression":
            func = node.child_by_field_name("function")
            func_text = _get_node_text(func) if func else ""

            # eval / exec
            if func_text in ("eval", "exec"):
                findings.append({
                    "line": node.start_point[0] + 1,
                    "type": "dangerous_eval",
                    "name": "Dangerous eval() usage",
                    "severity": "high",
                    "snippet": _get_node_text(node)[:200],
                    "fix": "JSON.parse(userInput)",
                })

            # child_process.exec / execSync
            if func_text in ("exec", "execSync") or func_text.endswith(".exec"):
                findings.append({
                    "line": node.start_point[0] + 1,
                    "type": "command_injection",
                    "name": "Command injection via exec()",
                    "severity": "high",
                    "snippet": _get_node_text(node)[:200],
                    "fix": "execFile(command, args, callback)",
                })

            # fs.readFile / readFileSync with user input (basic signal)
            if func_text in ("readFile", "readFileSync"):
                args = node.child_by_field_name("arguments")
                if args and _get_node_text(args):
                    findings.append({
                        "line": node.start_point[0] + 1,
                        "type": "path_traversal",
                        "name": "Potential path traversal in file read",
                        "severity": "medium",
                        "snippet": _get_node_text(node)[:200],
                        "fix": "path.join(__dirname, 'base', path.basename(userInput))",
                    })

        # Binary expression: SQL string + variable  (e.g. "SELECT * FROM " + userId)
        if node.type == "binary_expression":
            node_text = _get_node_text(node).upper()
            if _looks_like_sql(node_text):
                findings.append({
                    "line": node.start_point[0] + 1,
                    "type": "sql_injection",
                    "name": "SQL injection via string concatenation",
                    "severity": "high",
                    "snippet": _get_node_text(node)[:200],
                    "fix": "db.query('SELECT * FROM table WHERE id = ?', [userInput])",
                })

        for child in node.children:
            visit(child)

    visit(root_node)
    return findings


def _visit_python(root_node) -> List[dict]:
    findings = []

    def visit(node):
        if node.type == "call":
            func = node.child_by_field_name("function")
            func_text = _get_node_text(func) if func else ""

            # eval / exec
            if func_text in ("eval", "exec"):
                findings.append({
                    "line": node.start_point[0] + 1,
                    "type": "dangerous_eval",
                    "name": "Dangerous eval/exec usage",
                    "severity": "high",
                    "snippet": _get_node_text(node)[:200],
                    "fix": "ast.literal_eval(user_input)",
                })

            # os.system
            if func_text == "os.system":
                findings.append({
                    "line": node.start_point[0] + 1,
                    "type": "command_injection",
                    "name": "Command injection via os.system()",
                    "severity": "high",
                    "snippet": _get_node_text(node)[:200],
                    "fix": "subprocess.run([command, arg], shell=False)",
                })

            # subprocess with shell=True
            if "subprocess" in func_text or func_text in ("Popen", "run", "call", "check_output"):
                args_node = node.child_by_field_name("arguments")
                if args_node and "shell=True" in _get_node_text(args_node):
                    findings.append({
                        "line": node.start_point[0] + 1,
                        "type": "command_injection",
                        "name": "Command injection via subprocess shell=True",
                        "severity": "high",
                        "snippet": _get_node_text(node)[:200],
                        "fix": "subprocess.run([command, arg], shell=False)",
                    })

            # pickle.load / pickle.loads
            if func_text in ("pickle.load", "pickle.loads", "loads") and "pickle" in _get_node_text(node):
                findings.append({
                    "line": node.start_point[0] + 1,
                    "type": "unsafe_deserialization",
                    "name": "Unsafe pickle deserialization",
                    "severity": "high",
                    "snippet": _get_node_text(node)[:200],
                    "fix": "Use json.loads() instead of pickle for untrusted data.",
                })

            # yaml.load without Loader
            if func_text in ("yaml.load", "load") and "yaml" in _get_node_text(node):
                args_node = node.child_by_field_name("arguments")
                args_text = _get_node_text(args_node) if args_node else ""
                if "Loader" not in args_text:
                    findings.append({
                        "line": node.start_point[0] + 1,
                        "type": "unsafe_deserialization",
                        "name": "Unsafe yaml.load() - missing Loader",
                        "severity": "high",
                        "snippet": _get_node_text(node)[:200],
                        "fix": "yaml.safe_load(data)",
                    })

        # String concatenation with SQL keywords
        if node.type in ("concatenated_string", "binary_operator"):
            node_text = _get_node_text(node).upper()
            if _looks_like_sql(node_text):
                findings.append({
                    "line": node.start_point[0] + 1,
                    "type": "sql_injection",
                    "name": "SQL injection via string formatting",
                    "severity": "high",
                    "snippet": _get_node_text(node)[:200],
                    "fix": "cursor.execute('SELECT * FROM table WHERE id = %s', (user_input,))",
                })

        for child in node.children:
            visit(child)

    visit(root_node)
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def hybrid_analyze_file(file_path: Path, content: str) -> List[dict]:
    """
    Hybrid analysis: regex pre-filter, then AST confirmation.
    Returns a list of finding dicts, each with type/name/severity/line/snippet/fix.
    """
    suffix = file_path.suffix.lower()

    if suffix == ".py":
        # stdlib AST: no tree-sitter dependency, never fires on string literals/comments.
        findings = analyze_python_ast(content)
        # Replace synthetic "name(...)" snippets with the actual source line so that
        # downstream data-source inference ("request.", "input(", etc.) works correctly.
        source_lines = content.splitlines()
        for f in findings:
            line_no = f.get("line", 1) - 1
            if 0 <= line_no < len(source_lines):
                f["snippet"] = source_lines[line_no].strip()[:200]
        # Tree-sitter: add SQL-concatenation findings only (not covered by stdlib AST).
        if TREE_SITTER_AVAILABLE and _has_trigger(content, _PYTHON_TRIGGERS):
            try:
                parser = Parser(Language(tspy.language()))
                tree = parser.parse(bytes(content, "utf8"))
                sql_findings = [f for f in _visit_python(tree.root_node) if f.get("type") == "sql_injection"]
                findings.extend(sql_findings)
            except Exception:
                pass
        for f in findings:
            f["file"] = str(file_path)
            f["language"] = "python"
        return findings

    if not TREE_SITTER_AVAILABLE:
        return []

    if suffix in (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"):
        if not _has_trigger(content, _NODE_TRIGGERS):
            return []
        try:
            parser = Parser(Language(tsjs.language()))
            tree = parser.parse(bytes(content, "utf8"))
            findings = _visit_js(tree.root_node)
        except Exception:
            return []
        language = "node"

    else:
        return []

    # Attach file path and language to every finding
    for f in findings:
        f["file"] = str(file_path)
        f["language"] = language

    return findings
