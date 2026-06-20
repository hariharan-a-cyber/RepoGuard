def report(conn, dept):
    # VULN: concatenation split across a variable (harder to pattern-match)
    base = "SELECT name FROM employees WHERE dept = "
    full = base + dept
    return conn.execute(full).fetchall()
