import time
from pathlib import Path

from backend.services.taint_service import TaintService


def test_express_sql_taint_flow_detected(tmp_path: Path) -> None:
    file_path = tmp_path / "api.js"
    file_path.write_text(
        """
        app.get('/users', (req, res) => {
          const id = req.query.id;
          db.query("SELECT * FROM users WHERE id=" + id);
        });
        """,
        encoding="utf-8",
    )

    service = TaintService()
    flows = service.scan_repository(tmp_path)

    assert any(flow.kind == "sql_injection" for flow in flows)
    sql_flow = [flow for flow in flows if flow.kind == "sql_injection"][0]
    assert sql_flow.framework == "express"
    assert sql_flow.sanitized is False
    assert "req.query.id" in sql_flow.source_symbol


def test_encoded_redirect_flow_not_treated_as_sanitized(tmp_path: Path) -> None:
    file_path = tmp_path / "auth.js"
    file_path.write_text(
        """
        router.get('/login', (req, res) => {
          const next = req.query.next;
          res.redirect(encodeURIComponent(next));
        });
        """,
        encoding="utf-8",
    )

    service = TaintService()
    flows = service.scan_repository(tmp_path)

    redirects = [flow for flow in flows if flow.kind == "open_redirect"]
    assert len(redirects) == 1
    assert redirects[0].sanitized is False


def test_fastify_framework_taint_flow_detected(tmp_path: Path) -> None:
        file_path = tmp_path / "api.js"
        file_path.write_text(
                """
                const fastify = require('fastify')();
                fastify.get('/users', async (req, reply) => {
                    const id = req.query.id;
                    db.query("SELECT * FROM users WHERE id=" + id);
                    return { ok: true };
                });
                """,
                encoding="utf-8",
        )

        service = TaintService()
        flows = service.scan_repository(tmp_path)

        assert any(flow.kind == "sql_injection" for flow in flows)
        sql_flow = [flow for flow in flows if flow.kind == "sql_injection"][0]
        assert sql_flow.framework == "fastify"


def test_taint_selection_is_deterministic_across_runs(tmp_path: Path) -> None:
    file_path = tmp_path / "stable.js"
    file_path.write_text(
        """
        app.post('/users', (req, res) => {
          const id = req.body.id;
          const user = req.body.user;
          const q = id + user;
          db.query("SELECT * FROM users WHERE id=" + q);
        });
        """,
        encoding="utf-8",
    )

    service = TaintService()
    signatures = []
    for _ in range(5):
        flows = service.scan_repository(tmp_path)
        sql = [flow for flow in flows if flow.kind == "sql_injection"]
        assert len(sql) == 1
        signatures.append((sql[0].source_symbol, tuple(sql[0].propagation_chain or []), sql[0].propagation_depth))

    assert len(set(signatures)) == 1


def test_strip_string_literals_handles_large_quoted_input() -> None:
    service = TaintService()
    long_literal = '"' + ("a" * 50000) + '" + req.body.id'

    stripped = service._strip_string_literals(long_literal)

    assert "a" * 100 not in stripped
    assert "req.body.id" in stripped


def test_partial_sanitization_is_not_marked_safe(tmp_path: Path) -> None:
    file_path = tmp_path / "partial.js"
    file_path.write_text(
        """
        app.post('/users', (req, res) => {
          const id = req.body.id;
          const mixed = encodeURIComponent(id) + req.body.extra;
          db.query("SELECT * FROM users WHERE id=" + mixed);
        });
        """,
        encoding="utf-8",
    )

    service = TaintService()
    flows = service.scan_repository(tmp_path)
    sql = [flow for flow in flows if flow.kind == "sql_injection"]

    assert len(sql) == 1
    assert sql[0].sanitized is False


def test_taint_scan_repeated_output_stable_with_runtime_budget(tmp_path: Path) -> None:
    file_path = tmp_path / "benchmark.js"
    literal_blob = "A" * 30000
    file_path.write_text(
        f"""
        app.post('/users', (req, res) => {{
          const id = req.body.id;
          const extra = req.body.extra;
          const merged = String(id) + extra;
          const filler = \"{literal_blob}\";
          db.query(\"SELECT * FROM users WHERE id=\" + merged);
          res.send(filler.length);
        }});
        """,
        encoding="utf-8",
    )

    service = TaintService()
    signatures = []
    started = time.perf_counter()
    for _ in range(12):
        flows = service.scan_repository(tmp_path)
        signature = tuple(
            sorted(
                (
                    flow.kind,
                    flow.file_path,
                    flow.line,
                    flow.source_symbol,
                    flow.sink_symbol,
                    flow.sanitized,
                    flow.exploitability_level,
                    flow.propagation_depth,
                    tuple(flow.propagation_chain or []),
                )
                for flow in flows
            )
        )
        signatures.append(signature)
    elapsed = time.perf_counter() - started

    assert len(set(signatures)) == 1
    assert elapsed < 5.0


def test_go_sql_taint_flow_detected(tmp_path: Path) -> None:
    file_path = tmp_path / "handler.go"
    file_path.write_text(
        """
        package main

        import "net/http"

        func handler(w http.ResponseWriter, r *http.Request) {
            id := r.URL.Query().Get("id")
            query := "SELECT * FROM users WHERE id=" + id
            db.Query(query)
        }
        """,
        encoding="utf-8",
    )

    service = TaintService()
    flows = service.scan_repository(tmp_path)

    sql = [flow for flow in flows if flow.kind == "sql_injection"]
    assert len(sql) == 1
    assert sql[0].framework == "net-http"
    assert "r.query[id]" in sql[0].source_symbol
    assert sql[0].sanitized is False


def test_csharp_command_taint_flow_detected(tmp_path: Path) -> None:
    file_path = tmp_path / "Runner.cs"
    file_path.write_text(
        """
        using System.Diagnostics;
        using Microsoft.AspNetCore.Mvc;

        public class RunnerController : ControllerBase
        {
            public void Run()
            {
                var cmd = Request.Query["cmd"];
                Process.Start(cmd);
            }
        }
        """,
        encoding="utf-8",
    )

    service = TaintService()
    flows = service.scan_repository(tmp_path)

    cmd = [flow for flow in flows if flow.kind == "command_injection"]
    assert len(cmd) == 1
    assert cmd[0].framework == "aspnet"
    assert "Request.Query[cmd]" in cmd[0].source_symbol
    assert cmd[0].sink_symbol == "Process.Start"
