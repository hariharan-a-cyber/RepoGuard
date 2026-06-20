import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Literal

from backend.utils.security import is_excluded_path


@dataclass(frozen=True)
class TaintState:
    source_symbol: str
    depth: int
    chain: tuple[str, ...]
    sanitized: bool
    uncertain: bool


@dataclass(frozen=True)
class TaintFlow:
    kind: str
    file_path: str
    line: int
    source_symbol: str
    sink_symbol: str
    sanitized: bool
    framework: str
    route_hint: str | None = None
    propagation_depth: int = 0
    propagation_chain: List[str] | None = None
    uncertain: bool = False
    exploitability_level: Literal["HIGH", "MEDIUM", "LOW"] = "LOW"


class TaintService:
    JS_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx"}
    GO_EXTENSIONS = {".go"}
    CSHARP_EXTENSIONS = {".cs"}
    MAX_PROPAGATION_DEPTH = 2

    SOURCE_RE = re.compile(
        r"req\.(query|body|params|headers|cookies)\.(\w+)"
        r"|req\.(query|body|params|headers|cookies)\[['\"]([^'\"]+)['\"]\]",
        re.IGNORECASE,
    )
    DECL_ASSIGN_RE = re.compile(r"\b(const|let|var)\s+(\w+)\s*=\s*(.+)")
    GO_DECL_ASSIGN_RE = re.compile(r"\b(\w+)\s*:=\s*(.+)")
    CSHARP_DECL_ASSIGN_RE = re.compile(
        r"\b(?:var|string|int|long|bool|double|float|decimal|object|Guid|DateTime|I[A-Za-z0-9_]+|[A-Z][A-Za-z0-9_]*)\s+(\w+)\s*=\s*(.+)"
    )
    REASSIGN_RE = re.compile(r"^\s*(\w+)\s*=\s*(.+)")
    ROUTE_RE = re.compile(r"\b(app|router)\.(get|post|put|delete|patch)\s*\(\s*['\"]([^'\"]+)['\"]", re.IGNORECASE)
    FUNC_DEF_RE = re.compile(r"\bfunction\s+(\w+)\s*\(\s*(\w+)\s*\)")
    ARROW_FUNC_RE = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=\s*\(\s*(\w+)\s*\)\s*=>")
    CALL_RE = re.compile(r"\b(\w+)\s*\(([^)]*)\)")

    SQL_SINK_RE = re.compile(r"\b(db|pool|connection|sequelize)\.query\s*\((.+)\)", re.IGNORECASE)
    CMD_SINK_RE = re.compile(r"\b(exec|execSync|spawn|spawnSync)\s*\((.+)\)", re.IGNORECASE)
    REDIRECT_SINK_RE = re.compile(r"\b(res\.redirect|redirect)\s*\((.+)\)", re.IGNORECASE)
    GO_SQL_SINK_RE = re.compile(r"\b(db|tx|conn)\.(Query|QueryRow|Exec)\s*\((.+)\)", re.IGNORECASE)
    GO_CMD_SINK_RE = re.compile(r"\bexec\.Command\s*\((.+)\)", re.IGNORECASE)
    CSHARP_SQL_SINK_RE = re.compile(r"\b(FromSqlRaw|ExecuteSqlRaw|SqlCommand)\s*\((.+)\)", re.IGNORECASE)
    CSHARP_CMD_SINK_RE = re.compile(r"\bProcess\.Start\s*\((.+)\)", re.IGNORECASE)

    GO_SOURCE_RE = re.compile(
        r"\br\.(?:URL\.Query\(\)\.Get|FormValue)\(\s*['\"]([^'\"]+)['\"]\s*\)"
        r"|\bc\.(?:Query|Param|FormValue)\(\s*['\"]([^'\"]+)['\"]\s*\)",
        re.IGNORECASE,
    )
    CSHARP_SOURCE_RE = re.compile(
        r"\b(?:HttpContext\.)?Request\.(?:Query|Form)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]"
        r"|\bConsole\.ReadLine\s*\(\s*\)",
        re.IGNORECASE,
    )

    SANITIZER_HINTS = (
        "sanitize(",
        "escape(",
        "validator.",
        "xss(",
        "queryescape(",
        "url.queryescape(",
        "webutility.urlencode(",
        "httputility.urlencode(",
    )
    SANITIZER_CALL_RE = re.compile(r"(?:sanitize|escape|xss)\s*\(")

    @staticmethod
    def _detect_framework(text: str) -> str:
        blob = str(text or "").lower()
        if "@nestjs/" in blob or "nestjs" in blob:
            return "nestjs"
        if "fastify" in blob:
            return "fastify"
        if "koa" in blob:
            return "koa"
        if "hapi" in blob or "@hapi/" in blob:
            return "hapi"
        if "express" in blob or "router." in blob or "app.get(" in blob:
            return "express"
        return "javascript"

    @staticmethod
    def _detect_framework_for_file(path: Path, text: str) -> str:
        suffix = path.suffix.lower()
        blob = str(text or "").lower()
        if suffix in TaintService.JS_EXTENSIONS:
            return TaintService._detect_framework(text)
        if suffix in TaintService.GO_EXTENSIONS:
            if "gin-gonic/gin" in blob or "gin." in blob:
                return "gin"
            if "labstack/echo" in blob or "echo." in blob:
                return "echo"
            if "net/http" in blob:
                return "net-http"
            return "go"
        if suffix in TaintService.CSHARP_EXTENSIONS:
            if "microsoft.aspnetcore" in blob or "controllerbase" in blob or "[httpget" in blob:
                return "aspnet"
            return "csharp"
        return "unknown"

    def scan_repository(self, repo_dir: Path) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        for path in sorted(repo_dir.rglob("*")):
            suffix = path.suffix.lower()
            if not path.is_file() or suffix not in (self.JS_EXTENSIONS | self.GO_EXTENSIONS | self.CSHARP_EXTENSIONS):
                continue
            if is_excluded_path(path, repo_dir):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue
            if suffix in self.JS_EXTENSIONS:
                flows.extend(self._scan_js_file(repo_dir, path, text))
            else:
                flows.extend(self._scan_non_js_file(repo_dir, path, text))
        return flows

    def _scan_js_file(self, repo_dir: Path, path: Path, text: str) -> List[TaintFlow]:
        lines = text.splitlines()
        tainted_vars: dict[str, TaintState] = {}
        route_hint: str | None = None
        flows: List[TaintFlow] = []
        function_sinks = self._extract_function_sinks(lines)
        framework = self._detect_framework(text)

        rel = str(path.relative_to(repo_dir)).replace("\\", "/")

        for idx, line in enumerate(lines, start=1):
            route_match = self.ROUTE_RE.search(line)
            if route_match:
                route_hint = f"{route_match.group(2).upper()} {route_match.group(3)}"

            self._apply_assignment_taint(line, tainted_vars)

            flows.extend(
                self._sink_flows_for_line(
                    rel,
                    idx,
                    line,
                    tainted_vars,
                    route_hint,
                    framework,
                )
            )
            flows.extend(
                self._function_call_flows_for_line(
                    rel,
                    idx,
                    line,
                    tainted_vars,
                    route_hint,
                    function_sinks,
                    framework,
                )
            )

        return flows

    def _scan_non_js_file(self, repo_dir: Path, path: Path, text: str) -> List[TaintFlow]:
        lines = text.splitlines()
        tainted_vars: dict[str, TaintState] = {}
        flows: List[TaintFlow] = []
        rel = str(path.relative_to(repo_dir)).replace("\\", "/")
        framework = self._detect_framework_for_file(path, text)
        language = "go" if path.suffix.lower() in self.GO_EXTENSIONS else "csharp"

        for idx, line in enumerate(lines, start=1):
            self._apply_assignment_taint_non_js(line, tainted_vars, language)
            flows.extend(self._sink_flows_for_line_non_js(rel, idx, line, tainted_vars, framework, language))

        return flows

    def _apply_assignment_taint_non_js(
        self,
        line: str,
        tainted_vars: dict[str, TaintState],
        language: str,
    ) -> None:
        if language == "go":
            assign = self.GO_DECL_ASSIGN_RE.search(line)
            if assign:
                var_name = assign.group(1)
                rhs = assign.group(2)
            else:
                reassignment = self.REASSIGN_RE.search(line)
                if not reassignment:
                    return
                var_name = reassignment.group(1)
                rhs = reassignment.group(2)
        else:
            assign = self.CSHARP_DECL_ASSIGN_RE.search(line)
            if assign:
                var_name = assign.group(1)
                rhs = assign.group(2)
            else:
                reassignment = self.REASSIGN_RE.search(line)
                if not reassignment:
                    return
                var_name = reassignment.group(1)
                rhs = reassignment.group(2)

        src = self._extract_source_by_language(rhs, language)
        if src:
            tainted_vars[var_name] = TaintState(source_symbol=src, depth=0, chain=(src, var_name), sanitized=False, uncertain=False)
            return

        propagated = self._propagate_from_rhs(rhs, tainted_vars)
        if propagated:
            tainted_vars[var_name] = propagated
        else:
            tainted_vars.pop(var_name, None)

    def _sink_flows_for_line_non_js(
        self,
        rel: str,
        idx: int,
        line: str,
        tainted_vars: dict[str, TaintState],
        framework: str,
        language: str,
    ) -> List[TaintFlow]:
        flows: List[TaintFlow] = []

        if language == "go":
            sink_specs: list[tuple[str, re.Pattern[str], Callable[[re.Match[str]], tuple[str, str]]]] = [
                ("sql_injection", self.GO_SQL_SINK_RE, lambda m: (f"{m.group(1)}.{m.group(2)}", m.group(3))),
                ("command_injection", self.GO_CMD_SINK_RE, lambda m: ("exec.Command", m.group(1))),
            ]
        else:
            sink_specs = [
                ("sql_injection", self.CSHARP_SQL_SINK_RE, lambda m: (m.group(1), m.group(2))),
                ("command_injection", self.CSHARP_CMD_SINK_RE, lambda m: ("Process.Start", m.group(1))),
            ]

        for kind, sink_re, extractor in sink_specs:
            match = sink_re.search(line)
            if not match:
                continue

            sink_symbol, sink_args = extractor(match)
            src = self._extract_source_by_language(sink_args, language)
            state: TaintState | None = None

            if src:
                state = TaintState(source_symbol=src, depth=0, chain=(src,), sanitized=False, uncertain=False)
            else:
                state = self._find_tainted_state(sink_args, tainted_vars)

            if not state:
                continue

            sanitized = state.sanitized or self._is_sanitized(sink_args)
            tier = self._assess_exploitability_tier(kind=kind, sanitized=sanitized, depth=state.depth, uncertain=state.uncertain)
            flows.append(
                TaintFlow(
                    kind=kind,
                    file_path=rel,
                    line=idx,
                    source_symbol=state.source_symbol,
                    sink_symbol=sink_symbol,
                    sanitized=sanitized,
                    framework=framework,
                    route_hint=None,
                    propagation_depth=state.depth,
                    propagation_chain=list(state.chain),
                    uncertain=state.uncertain,
                    exploitability_level=tier,
                )
            )

        return flows

    def _apply_assignment_taint(self, line: str, tainted_vars: dict[str, TaintState]) -> None:
        assign = self.DECL_ASSIGN_RE.search(line)
        if assign:
            var_name = assign.group(2)
            rhs = assign.group(3)
        else:
            reassignment = self.REASSIGN_RE.search(line)
            if not reassignment:
                return
            var_name = reassignment.group(1)
            rhs = reassignment.group(2)

        src = self._extract_source(rhs)
        if src:
            tainted_vars[var_name] = TaintState(source_symbol=src, depth=0, chain=(src, var_name), sanitized=False, uncertain=False)
            return

        propagated = self._propagate_from_rhs(rhs, tainted_vars)
        if propagated:
            tainted_vars[var_name] = propagated
        else:
            # Overwriting with non-tainted value should break previous taint chain.
            tainted_vars.pop(var_name, None)

    def _propagate_from_rhs(self, rhs: str, tainted_vars: dict[str, TaintState]) -> TaintState | None:
        for existing_var in sorted(tainted_vars.keys(), key=lambda name: (-len(name), name)):
            existing_state = tainted_vars[existing_var]
            if not re.search(rf"\b{re.escape(existing_var)}\b", rhs):
                continue

            transformed = self._is_transformed(rhs, existing_var)
            saturated = existing_state.depth >= self.MAX_PROPAGATION_DEPTH
            next_depth = min(self.MAX_PROPAGATION_DEPTH, existing_state.depth + 1)
            sanitized = existing_state.sanitized or self._is_sanitized(rhs)
            uncertain = existing_state.uncertain or transformed or saturated
            next_chain = existing_state.chain + (existing_var,)
            if len(next_chain) > 5:
                next_chain = next_chain[-5:]

            return TaintState(
                source_symbol=existing_state.source_symbol,
                depth=next_depth,
                chain=next_chain,
                sanitized=sanitized,
                uncertain=uncertain,
            )
        return None

    @staticmethod
    def _is_transformed(rhs: str, variable: str) -> bool:
        compact = re.sub(r"\s+", "", (rhs or "").strip().rstrip(";"))
        compact = compact.strip("()")
        simple_refs = {
            variable,
            f"+{variable}",
            f"-{variable}",
            f"String({variable})",
            f"Number({variable})",
            f"Boolean({variable})",
            f"{variable}.trim()",
        }
        if compact in simple_refs:
            return False
        return True

    def _sink_flows_for_line(
        self,
        rel: str,
        idx: int,
        line: str,
        tainted_vars: dict[str, TaintState],
        route_hint: str | None,
        framework: str,
    ) -> List[TaintFlow]:
        flows: List[TaintFlow] = []

        for kind, sink_re in (
            ("sql_injection", self.SQL_SINK_RE),
            ("command_injection", self.CMD_SINK_RE),
            ("open_redirect", self.REDIRECT_SINK_RE),
        ):
            match = sink_re.search(line)
            if not match:
                continue

            sink_symbol = match.group(1)
            sink_args = match.group(2)
            src = self._extract_source(sink_args)
            state: TaintState | None = None

            if src:
                state = TaintState(source_symbol=src, depth=0, chain=(src,), sanitized=False, uncertain=False)
            else:
                state = self._find_tainted_state(sink_args, tainted_vars)

            if not state:
                continue

            sanitized = state.sanitized or self._is_sanitized(sink_args)
            tier = self._assess_exploitability_tier(kind=kind, sanitized=sanitized, depth=state.depth, uncertain=state.uncertain)
            flows.append(
                TaintFlow(
                    kind=kind,
                    file_path=rel,
                    line=idx,
                    source_symbol=state.source_symbol,
                    sink_symbol=sink_symbol,
                    sanitized=sanitized,
                    framework=framework,
                    route_hint=route_hint,
                    propagation_depth=state.depth,
                    propagation_chain=list(state.chain),
                    uncertain=state.uncertain,
                    exploitability_level=tier,
                )
            )

        return flows

    def _function_call_flows_for_line(
        self,
        rel: str,
        idx: int,
        line: str,
        tainted_vars: dict[str, TaintState],
        route_hint: str | None,
        function_sinks: dict[str, list[dict[str, str | int | bool]]],
        framework: str,
    ) -> List[TaintFlow]:
        flows: List[TaintFlow] = []
        for call in self.CALL_RE.finditer(line):
            fn_name = call.group(1)
            if fn_name in {"if", "for", "while", "switch", "catch"}:
                continue
            if fn_name not in function_sinks:
                continue

            arg_blob = call.group(2)
            state = self._find_tainted_state(arg_blob, tainted_vars)
            if not state:
                src = self._extract_source(arg_blob)
                if not src:
                    continue
                state = TaintState(source_symbol=src, depth=0, chain=(src,), sanitized=False, uncertain=False)

            for fn_sink in function_sinks[fn_name]:
                kind = str(fn_sink["kind"])
                sanitized = bool(fn_sink["sanitized"]) or state.sanitized or self._is_sanitized(arg_blob)
                depth = min(self.MAX_PROPAGATION_DEPTH, state.depth + 1)
                uncertain = True
                chain = state.chain + (f"{fn_name}()",)
                if len(chain) > 5:
                    chain = chain[-5:]
                tier = self._assess_exploitability_tier(kind=kind, sanitized=sanitized, depth=depth, uncertain=uncertain)

                flows.append(
                    TaintFlow(
                        kind=kind,
                        file_path=rel,
                        line=idx,
                        source_symbol=state.source_symbol,
                        sink_symbol=str(fn_sink["sink_symbol"]),
                        sanitized=sanitized,
                        framework=framework,
                        route_hint=route_hint,
                        propagation_depth=depth,
                        propagation_chain=list(chain),
                        uncertain=uncertain,
                        exploitability_level=tier,
                    )
                )
        return flows

    def _find_tainted_state(self, text: str, tainted_vars: dict[str, TaintState]) -> TaintState | None:
        search_space = self._strip_string_literals(text)
        candidates: list[tuple[int, int, int, str, TaintState]] = []
        for var_name, state in tainted_vars.items():
            if re.search(rf"\b{re.escape(var_name)}\b", search_space):
                candidates.append((state.depth, 1 if state.uncertain else 0, len(var_name), var_name, state))

        if not candidates:
            return None

        candidates.sort(key=lambda item: (item[0], item[1], item[2], item[3]), reverse=True)
        return candidates[0][4]

    @staticmethod
    def _strip_string_literals(text: str) -> str:
        if not text:
            return ""

        out: list[str] = []
        quote: str | None = None
        escape = False
        for ch in text:
            if quote is None:
                if ch in {"'", '"', "`"}:
                    quote = ch
                    continue
                out.append(ch)
                continue

            if escape:
                escape = False
                continue

            if ch == "\\":
                escape = True
                continue

            if ch == quote:
                quote = None
                continue

        return "".join(out)

    def _extract_function_sinks(self, lines: List[str]) -> dict[str, list[dict[str, str | int | bool]]]:
        sinks: dict[str, list[dict[str, str | int | bool]]] = {}

        for idx, line in enumerate(lines):
            fn_match = self.FUNC_DEF_RE.search(line) or self.ARROW_FUNC_RE.search(line)
            if not fn_match:
                continue

            fn_name = fn_match.group(1)
            param = fn_match.group(2)
            body_text = self._extract_block_text(lines, idx)
            if not body_text:
                continue

            for kind, sink_re in (
                ("sql_injection", self.SQL_SINK_RE),
                ("command_injection", self.CMD_SINK_RE),
                ("open_redirect", self.REDIRECT_SINK_RE),
            ):
                match = sink_re.search(body_text)
                if not match:
                    continue
                sink_args = match.group(2)
                if not re.search(rf"\b{re.escape(param)}\b", sink_args):
                    continue

                sinks.setdefault(fn_name, []).append(
                    {
                        "kind": kind,
                        "sink_symbol": match.group(1),
                        "sanitized": self._is_sanitized(sink_args),
                    }
                )

        return sinks

    @staticmethod
    def _extract_block_text(lines: List[str], start_idx: int) -> str:
        collected: List[str] = []
        brace_depth = 0
        started = False

        for line in lines[start_idx:]:
            collected.append(line)
            opens = line.count("{")
            closes = line.count("}")
            if opens > 0:
                started = True
            brace_depth += opens
            brace_depth -= closes
            if started and brace_depth <= 0:
                break

        return "\n".join(collected)

    @staticmethod
    def _assess_exploitability_tier(
        *,
        kind: str,
        sanitized: bool,
        depth: int,
        uncertain: bool,
    ) -> Literal["HIGH", "MEDIUM", "LOW"]:
        if sanitized:
            return "LOW"
        if uncertain or depth > 0:
            return "MEDIUM"
        if kind in {"sql_injection", "command_injection"}:
            return "HIGH"
        return "MEDIUM"

    def _extract_source(self, text: str) -> str | None:
        match = self.SOURCE_RE.search(text)
        if not match:
            return None
        if match.group(1) and match.group(2):
            return f"req.{match.group(1)}.{match.group(2)}"
        if match.group(3) and match.group(4):
            return f"req.{match.group(3)}[{match.group(4)}]"
        return "req.input"

    def _extract_source_by_language(self, text: str, language: str) -> str | None:
        if language == "go":
            match = self.GO_SOURCE_RE.search(text)
            if not match:
                return None
            if match.group(1):
                return f"r.query[{match.group(1)}]"
            if match.group(2):
                return f"c.query[{match.group(2)}]"
            return "go.request"

        if language == "csharp":
            match = self.CSHARP_SOURCE_RE.search(text)
            if not match:
                return None
            if match.group(1):
                return f"Request.Query[{match.group(1)}]"
            return "Console.ReadLine()"

        return self._extract_source(text)

    def _is_sanitized(self, text: str) -> bool:
        lowered = text.lower()

        # Allowlist lookup: when the tainted value is used as an index/key into
        # a map or array (e.g. ALLOWED[req.query.dest] or routes[req.params.id]),
        # or as a key to a lookup method (.get / .includes / .has / .find),
        # the value reaching the sink is the looked-up entry, not the raw input.
        if re.search(r"[A-Za-z_$][\w$]*\s*\[\s*(?:req|request|ctx|context)\b[^\]]*\]", text, re.IGNORECASE):
            return True
        if re.search(r"\.(?:get|has|includes|find|indexof)\s*\(\s*(?:req|request|ctx|context)\b", text, re.IGNORECASE):
            return True

        has_sanitizer = any(hint.lower() in lowered for hint in self.SANITIZER_HINTS)
        if not has_sanitizer:
            return False

        # Treat mixed expressions with concatenation and fresh request sources as partially sanitized.
        if "+" in text and self._extract_source(text):
            return False

        return True
