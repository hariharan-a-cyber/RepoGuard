def lookup(conn, name):
    # VULN: inline concatenation SQLi
    return conn.execute("SELECT * FROM users WHERE name = '" + name + "'")
